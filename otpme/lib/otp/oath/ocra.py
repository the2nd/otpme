# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" OCRA (OATH Challenge-Response Algorithm, RFC 6287).

OCRA is the challenge-response sibling of HOTP: same HMAC core, same
dynamic truncation, but instead of a bare counter a set of input fields
goes into the HMAC. Which fields those are is spelled out by the OCRA
suite string, e.g. "OCRA-1:HOTP-SHA1-6:QH10-S" (the tiqr default).

The computation itself comes from the "oath" package, the same way
hotp.py and totp.py delegate to pyotp. It reproduces every tiqr test
vector from Tiqr/tiqr-server-libphp; see tests/unit/test_ocra.py.

What that package does not get right for us, hence this module:

  * It appends the session information verbatim and insists on it being
    exactly as long as the suite says. A tiqr session key is 16 bytes
    while the field is 64, and the reference implementations pad it on
    the LEFT -- that is what _get_session_field() does. Get this wrong
    and every response mismatches, with nothing to indicate why.
  * Its compute_challenge() draws from the "random" module, which is a
    Mersenne Twister and therefore predictable. gen_challenge() below
    uses OTPme's CSPRNG instead.
  * It accepts any hashlib algorithm and truncation lengths the RFC does
    not allow, and for truncation length 0 it returns a decimal value
    where the RFC asks for the raw hash. get_suite() rejects all of that
    rather than let a suite through that no client can answer.
  * Its P_digest branch is broken (str2hashalgo returns the hashlib
    constructor, whose .digest_size does not exist), so suites with a
    PIN field would fail. We reject those suites up front anyway.
"""
import os
import hmac

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

# str2ocrasuite() is the package's public entry point: it heads the
# __all__ of oath._ocra and is re-exported here. The object it hands
# back is another matter -- OcraSuite, DataInput and CryptoFunction are
# deliberately not exported, and get_suite() below reads their
# attributes because the package offers no other way to learn the
# session field size or the challenge type. The version floor in
# pyproject.toml and tests/unit/test_ocra.py are what pin that down.
from oath import str2ocrasuite

from otpme.lib import stuff
from otpme.lib.exceptions import *

# Fields we do not feed. tiqr uses the challenge and the session key and
# nothing else, so a suite asking for a counter, a PIN or a timestamp is
# a misconfiguration. Rejecting it here beats a confusing ValueError
# from deep inside the OCRA computation.
UNSUPPORTED_FIELDS = {
                    'C' : "counter",
                    'P' : "PIN/password",
                    'T' : "timestamp",
                    }

# RFC 6287 allows exactly these three, and so do the tiqr apps. The oath
# package is more permissive and takes any hashlib algorithm, MD5
# included, which would only fail later on the phone.
SUPPORTED_HASHES = ["sha1", "sha256", "sha512"]

# RFC 6287 allows 0 (return the raw hash) and 4 to 10 digits. We refuse
# 0 as well: the oath package returns a decimal value there instead of
# the hash, and no tiqr client asks for it. The package also accepts
# 1 to 3, which the RFC does not.
MIN_DIGITS = 4
MAX_DIGITS = 10

def get_suite(suite):
    """ Parse and check an OCRA suite. """
    try:
        ocrasuite = str2ocrasuite(suite)
    except Exception as e:
        msg = _("Invalid OCRA suite: {suite}")
        msg = msg.format(suite=suite)
        raise OTPmeException(msg) from e

    for field, field_name in UNSUPPORTED_FIELDS.items():
        if getattr(ocrasuite.data_input, field, None):
            msg = _("Unsupported OCRA field in suite: {field_name}")
            msg = msg.format(field_name=field_name)
            raise OTPmeException(msg)

    if not ocrasuite.data_input.Q:
        msg = _("OCRA suite without challenge: {suite}")
        msg = msg.format(suite=suite)
        raise OTPmeException(msg)

    # hash_algo is the hashlib constructor; an instance knows its name.
    hash_name = ocrasuite.crypto_function.hash_algo().name
    if hash_name not in SUPPORTED_HASHES:
        msg = _("Unsupported OCRA hash function: {hash_name}")
        msg = msg.format(hash_name=hash_name)
        raise OTPmeException(msg)

    digits = ocrasuite.crypto_function.truncation_length
    if digits is None or digits < MIN_DIGITS or digits > MAX_DIGITS:
        msg = _("Unsupported OCRA truncation length: {digits}")
        msg = msg.format(digits=digits)
        raise OTPmeException(msg)

    return ocrasuite

def _get_hex(value, field_name):
    """ Decode a hex encoded parameter to bytes. """
    try:
        decoded = bytes.fromhex(value)
    except (ValueError, TypeError) as e:
        msg = _("OCRA parameter is not hex encoded: {field_name}")
        msg = msg.format(field_name=field_name)
        raise OTPmeException(msg) from e
    return decoded

def _get_session_field(ocrasuite, session):
    """ Bring the session information to the size the suite requires.

    Zero padded on the LEFT, which is what the tiqr server library and
    the tiqr apps do. Returns None if the suite has no session field. """
    session_bytes = ocrasuite.data_input.S
    if not session_bytes:
        return None
    if session is None:
        session = ""
    session_field = _get_hex(session, "session")
    if len(session_field) > session_bytes:
        msg = _("OCRA session information too long: {length} bytes")
        msg = msg.format(length=len(session_field))
        raise OTPmeException(msg)
    return session_field.rjust(session_bytes, b"\0")

def generate(suite, secret, challenge, session=None):
    """ Calculate the OCRA response.

    The secret is hex encoded, as stored on the token. The challenge is
    passed as it appears in the authentication URL, which for a QH suite
    is already its hex encoding. """
    ocrasuite = get_suite(suite)
    key = _get_hex(secret, "secret")

    ocra_args = {'Q' : challenge}
    session_field = _get_session_field(ocrasuite, session)
    if session_field is not None:
        ocra_args['S'] = session_field

    try:
        response = ocrasuite(key, **ocra_args)
    except Exception as e:
        msg = _("Error calculating OCRA response: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e

    return response

def verify(suite, secret, challenge, response, session=None):
    """ Verify an OCRA response. """
    if response is None:
        return False
    expected = generate(suite, secret, challenge, session=session)
    # Compared as bytes: compare_digest() refuses str arguments that are
    # not ASCII, and the response comes off a public endpoint where
    # anyone can put anything in it.
    return hmac.compare_digest(expected.encode(), str(response).encode())

def gen_challenge(suite):
    """ Generate a random challenge matching the suite's challenge type.

    Returned in the form that goes into e.g. a tiqr authentication URL.
    For QH that is already the hex encoding generate() expects, for
    QN/QA it is not -- and only QH interoperates with the tiqr apps,
    which hand the challenge straight into the OCRA computation. """
    ocrasuite = get_suite(suite)
    challenge_type, challenge_len = ocrasuite.data_input.Q

    if challenge_type == "H":
        # gen_secret() takes a byte count and returns two chars per byte.
        secret_len = (challenge_len + 1) // 2
        challenge = stuff.gen_secret(len=secret_len, encoding="hex")
    elif challenge_type == "N":
        challenge = stuff.gen_pin(pin_len=challenge_len)
    elif challenge_type == "A":
        # gen_password() guarantees at least one character of each class,
        # so this is not quite uniform over the alphabet. Good enough for
        # a challenge, and QA does not interoperate with tiqr anyway.
        challenge = stuff.gen_password(length=challenge_len,
                                    require_special=False)
    else:
        msg = _("Unsupported OCRA challenge type: {challenge_type}")
        msg = msg.format(challenge_type=challenge_type)
        raise OTPmeException(msg)

    return challenge[:challenge_len]
