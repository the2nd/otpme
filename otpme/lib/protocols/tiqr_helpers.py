# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
Pure tiqr protocol helpers, used by the authd/ssod command handlers and
by the web endpoints the phone talks to. Same idea as oidc_helpers.py:
no backend, no logger, no object lookups, so they can be unit tested on
their own.

The three values a login turns on, and why they are derived rather than
stored:

    session_key  4 byte timestamp + 16 byte random, hex   PUBLIC
    challenge    HMAC(site secret, session_key, user)     PUBLIC
    poll_id      HMAC(site secret, session_key)           PRIVATE

tiqr's own reference keeps a server side record per login attempt, keyed
by the session key, holding the challenge and the browser's session id.
We cannot: the phone posts to one fixed URL and lands on whichever node
the load balancer picks, while a shared dict is local to one host. A
cluster replicated record would work, but the record is created before
anybody has proven anything -- an unauthenticated caller could make us
write one per request, on every node, with no reaper to clean up after
them (OTPme has none; used_otp is cleaned lazily, failed_pass is capped
per user).

So nothing is written until the phone answers correctly. That is only
possible because the phone posts the session key back (sessionKey,
userId, response -- there is no challenge field in the protocol), which
lets any node re-derive the challenge from it. The timestamp inside the
session key carries the expiry that the reference gets from its store's
TTL.

poll_id exists because the session key is printed as a QR code and is
therefore public. The reference files the result under the browser's own
session id, which never appears in the QR; deriving poll_id keeps that
separation without a stored mapping.

None of this changes what the phone sees: it treats the session key as
opaque hex.
"""
import hmac
import struct
import hashlib
from urllib.parse import quote

from otpme.lib import jwt
from otpme.lib import stuff

# 4 byte timestamp + 16 byte random. The reference uses 16 random bytes
# (128 bits) and calls that sufficient; keeping 16 after making room for
# the timestamp means we do not fall below it. The apps pad the session
# field to 128 hex digits, so anything up to 64 bytes is accepted.
SESSION_KEY_TIME_BYTES = 4
SESSION_KEY_RANDOM_BYTES = 16
SESSION_KEY_HEX_LEN = (SESSION_KEY_TIME_BYTES + SESSION_KEY_RANDOM_BYTES) * 2

# How far a session key may be ahead of us before we call it bogus. Two
# nodes never agree on the time to the second, and a key minted on a
# slightly fast node must not be dead on arrival elsewhere.
DEFAULT_CLOCK_SKEW = 60

# Labels keep the derivations apart. Without them a session key could in
# principle produce a challenge that equals somebody's poll id.
CHALLENGE_LABEL = "tiqr-challenge"
POLL_LABEL = "tiqr-poll"

# The two one-shot keys of an enrollment. The first sits in the QR code
# and buys nothing but the metadata; the second travels inside that
# metadata and is the only one that may deliver a secret. Whoever
# photographs the QR therefore cannot post a secret without fetching the
# metadata first. Carried as the "scope" claim, so one key can never be
# presented where the other is expected.
ENROLL_SCOPE_METADATA = "tiqr-enroll-metadata"
ENROLL_SCOPE_SECRET = "tiqr-enroll-secret"
ENROLL_ALGORITHM = "HS256"

# Protocol version we speak in the URLs we hand out.
DEFAULT_PROTOCOL_VERSION = 2


def _get_key(site_secret):
    """ Site secret (hex) as raw key bytes. """
    try:
        return bytes.fromhex(site_secret)
    except (ValueError, TypeError, AttributeError) as e:
        raise ValueError("tiqr site secret is not hex encoded") from e


def gen_session_key(timestamp):
    """ Build a session key: timestamp, then randomness, hex encoded.

    The timestamp is a big endian unsigned 32 bit unix time, which is
    good until 2106 and plenty for a three minute window. """
    stamp = struct.pack(">I", int(timestamp))
    random_part = stuff.gen_secret(len=SESSION_KEY_RANDOM_BYTES,
                                encoding="hex")
    return stamp.hex() + random_part


def get_session_key_time(session_key):
    """ Read the timestamp back out of a session key. """
    try:
        stamp = bytes.fromhex(session_key)[:SESSION_KEY_TIME_BYTES]
    except (ValueError, TypeError, AttributeError) as e:
        raise ValueError("session key is not hex encoded") from e
    if len(stamp) != SESSION_KEY_TIME_BYTES:
        raise ValueError("session key too short")
    # float, not the int unpack hands back: callers add the challenge
    # expiry to this and store the sum as TiqrAuthResult's expiry, which
    # UsedHash types as float. Two ints make an int and the type check
    # refuses the object.
    return float(struct.unpack(">I", stamp)[0])


def session_key_expired(session_key, max_age, now,
    clock_skew=DEFAULT_CLOCK_SKEW):
    """ Is this session key outside its window?

    Too old is expired. Too far in the future is expired as well -- that
    is either a broken clock or somebody making keys up. """
    age = now - get_session_key_time(session_key)
    if age > max_age:
        return True
    if age < -clock_skew:
        return True
    return False


def derive_challenge(site_secret, session_key, user_uuid, challenge_len):
    """ The OCRA challenge for this login attempt.

    Deterministic, so any node can recover it from the session key the
    phone posts back. Unpredictable to anybody who does not hold the
    site secret, which is what the challenge has to be. Bound to the
    user so a session key cannot be answered on behalf of someone
    else. """
    message = f"{CHALLENGE_LABEL}:{session_key}:{user_uuid}"
    mac = hmac.new(_get_key(site_secret), message.encode(), hashlib.sha256)
    digest = mac.hexdigest()
    if challenge_len > len(digest):
        raise ValueError("challenge longer than the digest")
    return digest[:challenge_len]


def derive_poll_id(site_secret, session_key):
    """ The handle the browser collects the result under.

    Never leaves the server except into the browser's own session, and
    in particular never goes into the QR code. Someone who photographs
    the QR knows the session key but cannot get from there to here. """
    message = f"{POLL_LABEL}:{session_key}"
    mac = hmac.new(_get_key(site_secret), message.encode(), hashlib.sha256)
    return mac.hexdigest()


def hash_poll_id(poll_id):
    """ What an answered login is filed under, instead of the poll id.

    The browser holds the poll id in its session and hands it back to
    collect the result, so it is a bearer value. The key it is stored
    under travels through the cluster journal and the logs, so the hash
    goes there instead -- the same way OIDC stores authcode_hash rather
    than the code.

    Plain SHA-256 hex, identical to oidc_helpers.hash_token(). Written
    out here rather than imported from there because this module pulls
    in nothing but jwt and stuff, which is what keeps it testable on
    its own. """
    if isinstance(poll_id, str):
        poll_id = poll_id.encode("utf-8")
    return hashlib.sha256(poll_id).hexdigest()


def build_enroll_key(site_secret, scope, expiry, user_uuid, token_name,
    device_name, login_token_uuid):
    """ A signed grant to finish one enrollment.

    No token object exists while a phone enrolls -- the passkey flow
    creates its slot only on success so a cancelled attempt leaves no
    debris, and this follows it. Everything needed to create the token
    therefore travels in the key, signed, so the unauthenticated request
    that finishes the enrollment can only create exactly what an
    authenticated request granted.

    <login_token_uuid> is the token the user presented in the session
    that started this enrollment. The new token has to inherit its
    roles, access groups and groups or it cannot be used to log in at
    all -- passkey_register_complete() mirrors the same three, and says
    what happens otherwise: "token is not valid for accessgroup 'SSO'".
    Only the uuid travels; the memberships are read when the enrollment
    finishes, which keeps the key short and the list current.

    It is a bearer value for its lifetime: whoever holds it can enroll
    their own phone. That is true of the reference implementation too --
    its enrollmentKey buys the same thing -- and is why the key only
    ever appears in the user's own browser and dies after a few
    minutes. """
    payload = {
                'scope'             : scope,
                'user_uuid'         : user_uuid,
                'token_name'        : token_name,
                'device_name'       : device_name,
                'login_token_uuid'  : login_token_uuid,
                'exp'               : int(expiry),
            }
    return jwt.encode(payload=payload,
                    secret=site_secret,
                    algorithm=ENROLL_ALGORITHM)


def parse_enroll_key(site_secret, enroll_key, scope):
    """ Check a grant and return its claims.

    Signature and expiry are checked by the JWT layer. The scope is
    checked here: the key from the QR code must not be accepted where
    the one from the metadata is expected. Raises ValueError. """
    try:
        claims = jwt.decode(jwt=enroll_key,
                            secret=site_secret,
                            algorithm=ENROLL_ALGORITHM)
    except Exception as e:
        raise ValueError(f"invalid enrollment key: {e}") from e
    if claims.get('scope') != scope:
        raise ValueError("enrollment key has the wrong scope")
    for claim in ('user_uuid', 'token_name', 'login_token_uuid'):
        if not claims.get(claim):
            raise ValueError(f"enrollment key misses {claim}")
    return claims


# What may appear in a service display name. Not a style rule: the
# identifier below is derived from it and ends up as the host of the
# tiqrauth:// URL, so this is the reg-name character set of RFC 3986 --
# unreserved plus sub-delims, without the percent that would start an
# escape sequence. A space is the one people reach for first, and the
# one that breaks it.
#
# Non-ASCII is out for a second reason: the app parses the URL by
# swapping in "http://" and letting OkHttp canonicalise the authority,
# which IDN-encodes it to punycode. The enrollment metadata is JSON and
# keeps what it was given, so the two would no longer name the same
# service, and every login would ask the user to enroll first.
VALID_SERVICE_NAME_CHARS = frozenset(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-._~!$&'()*+,;=")


def validate_service_display_name(display_name):
    """ Can a display name survive being turned into an identifier?

    Raises ValueError naming the offending characters if not. Called
    when tiqr_service_display_name is set, because that is the only
    moment where somebody is there to read the answer: a name that
    fails here enrolls fine -- the metadata is JSON -- and then makes
    every login QR code unparsable for the app. """
    invalid = sorted(set(display_name) - VALID_SERVICE_NAME_CHARS)
    if not invalid:
        return
    msg = _("Invalid characters in tiqr service display name: {chars}")
    msg = msg.format(chars=" ".join(repr(x) for x in invalid))
    raise ValueError(msg)


def canonical_service_identifier(display_name, realm):
    """ The identifier the app files an account under.

    Lower case, and that is the whole point. The app parses the
    authentication URL by replacing the scheme with "http://" and
    handing the result to OkHttp, which canonicalises the authority --
    so the identifier comes back lower case, whatever we sent. The
    enrollment metadata is JSON and passes through no URL parser, so
    what it declares is stored verbatim. Send "HBOSS" in both and the
    app stores "HBOSS", looks up "hboss", finds nothing, and asks the
    user to enroll -- while still displaying "HBOSS", because that is
    the separate displayName field.

    So: the identifier is folded here, once, for both the metadata and
    the URL. The display name keeps whatever case it was given.

    Computed in one place because it was duplicated in sso1 and auth1,
    and a value these two disagree on is exactly the failure above. """
    identifier = display_name or realm
    return identifier.lower()


def build_auth_url(auth_scheme, service_identifier, session_key, challenge,
    identity_id=None, sp_identifier=None,
    version=DEFAULT_PROTOCOL_VERSION, return_url=None):
    """ The tiqrauth:// URL that goes into the QR code and the link.

    Shape taken from Tiqr_Service::_getChallengeUrl(): the service
    identifier is the host and stays unescaped, while the user and the
    SP identifier are escaped. The apps read the path as
    [sessionKey, challenge, spIdentifier, version].

    The custom scheme, not the universal link form: the latter needs the
    app to be associated with our domain, which only works for an app
    published under your own name. """
    if sp_identifier is None:
        sp_identifier = service_identifier
    user_part = ""
    if identity_id:
        user_part = f"{quote(identity_id, safe='')}@"
    url = (f"{auth_scheme}://{user_part}{service_identifier}"
            f"/{session_key}/{challenge}"
            f"/{quote(sp_identifier, safe='')}/{version}")
    if return_url:
        # Appended raw as the query, not as a named parameter: the app
        # parses the whole query string as a URL
        # (AuthenticationUrlParams.parseOldFormatUrl).
        url = f"{url}?{return_url}"
    return url


def build_metadata_url_template(sso_fqdn):
    """ The metadata URL with the enrollment key left open.

    This is what travels to another site when the user enrolling a phone
    is not one of ours: the QR code has to point at the portal the
    browser is talking to, but the grant that goes into it is minted on
    the user's home site. Handing over the finished URL shape instead of
    the bare FQDN keeps the route, the scheme and the parameter name in
    the one place that serves them -- the remote side only fills in the
    key it just built.

    Escaping happens in build_metadata_url(), so the template must not
    be percent encoded by the caller. """
    return f"https://{sso_fqdn}/tiqr/metadata?enrollment_key={{enroll_key}}"


def build_metadata_url(url_template, enroll_key):
    """ Put an enrollment key into such a template.

    The key is a JWT and goes into a query parameter, so it is escaped
    here. Raises ValueError if the template is not one of ours -- it may
    have come in over the wire, and a URL we cannot recognise must not
    end up in a QR code. """
    if not str(url_template).startswith("https://"):
        raise ValueError("metadata URL template is not https")
    if "{enroll_key}" not in url_template:
        raise ValueError("metadata URL template has no enrollment key")
    return url_template.format(enroll_key=quote(enroll_key, safe=''))


def build_enroll_url(enroll_scheme, metadata_url):
    """ The tiqrenroll:// URL that goes into the enrollment QR code.

    The metadata URL is appended whole, unescaped, exactly as
    Tiqr_Service::_getEnrollString() does it.

    Into the QR code and nowhere else -- a browser cannot deliver it to
    the app. Its URL parser reads the "https:" that follows "//" as a
    host with an empty port, drops the empty port on serialising, and
    the app receives tiqrenroll://https//host/... The app checks
    startsWith("tiqrenroll://") and then toHttpUrlOrNull() on the rest
    (EnrollmentRepository.isValidChallenge in tiqr-app-core-android), so
    that fails. Tried against the app in every shape that survives the
    parser -- tiqrenroll:<url>, %3A-encoded, a third slash, Android's
    intent:// form, setAttribute, location.href -- and it rejects all of
    them.

    The protocol does have an answer for this: besides the custom scheme
    it defines a Universal Link, https://<host>/<path>?metadata=<url
    encoded metadata url>, which survives any parser because the payload
    sits in a query parameter (tiqr.org/technical/protocol/). It is not
    open to us: the app registers only the two custom schemes, and their
    names come from build placeholders (tiqr_config_enroll_scheme and
    friends). A Universal Link would have to name our own domain, which
    means the app must be built and published for it -- the same
    condition that already keeps push notifications out of reach.

    privacyIDEA arrives at the same place and shows the QR code only.

    build_auth_url() above has no such problem: its host is the service
    identifier, and no URL is embedded after the authority. """
    return f"{enroll_scheme}://{metadata_url}"
