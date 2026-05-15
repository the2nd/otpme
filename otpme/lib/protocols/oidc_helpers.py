# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
Pure OIDC helper functions used by both the protocol handler
(sso1.py) and the OIDCSession class.

These deliberately do NOT import any OTPme modules so they can be
unit-tested in isolation. Anything that needs backend / config /
logger lookups stays on the caller side.
"""
import base64
import hashlib


# AMR values that count as "strong" / hardware-backed for the ACR=2
# heuristic. Any of these in the ``amr`` list bumps acr to "2";
# otherwise "1" (single-factor) or "0" (nothing).
#
#   ``hwk`` -- proof-of-possession of a hardware-secured key
#              (FIDO/U2F/FIDO2 tokens emit this)
#   ``sc``  -- smart card (YubiKey-PIV emits this)
#   ``mfa`` -- explicit multiple-factor authentication marker
#
# Spec: RFC 8176 "Authentication Method Reference Values"
#   (defines the ``amr`` claim + creates the IANA registry;
#   all three values above are registered in §2)
#   https://datatracker.ietf.org/doc/html/rfc8176
# IANA "Authentication Method Reference Values" registry
#   (authoritative live list of additions made after RFC 8176)
#   https://www.iana.org/assignments/authentication-method-reference-values/authentication-method-reference-values.xhtml
STRONG_AMR_FACTORS = frozenset({'hwk', 'sc', 'mfa'})


def hash_token(token):
    """ Canonical SHA-256 hex digest used for OIDC token storage and
    indexed lookup. Same hash produced for equivalent str/bytes input.
    """
    if isinstance(token, str):
        token = token.encode("utf-8")
    return hashlib.sha256(token).hexdigest()


def compute_at_hash(access_token, alg):
    """ ``at_hash`` -- hash the access_token with the digest matching
    the JWT signing alg, take the left half, base64url-encode without
    padding.

    Returns ``None`` for unknown algs (caller omits the claim rather
    than emitting a bogus value).

    Spec: OIDC Core 1.0 §3.1.3.6 "ID Token" (at_hash definition)
      https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
    Spec: RFC 7518 §3 "Cryptographic Algorithms for Digital Signatures"
      https://datatracker.ietf.org/doc/html/rfc7518#section-3
    """
    if alg in ("HS256", "RS256", "ES256", "PS256"):
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
    elif alg in ("HS384", "RS384", "ES384", "PS384"):
        digest = hashlib.sha384(access_token.encode("ascii")).digest()
    elif alg in ("HS512", "RS512", "ES512", "PS512"):
        digest = hashlib.sha512(access_token.encode("ascii")).digest()
    elif alg == "EdDSA":
        # FAPI 1.0 §5.2.2.1: Ed25519 -> SHA-512, take left 256 bits.
        #   https://openid.net/specs/openid-financial-api-part-2-1_0.html
        digest = hashlib.sha512(access_token.encode("ascii")).digest()
    else:
        return None
    half = digest[:len(digest) // 2]
    return base64.urlsafe_b64encode(half).rstrip(b"=").decode("ascii")


def verify_pkce(code_verifier, code_challenge, code_challenge_method):
    """ PKCE verification.

    Returns ``True`` when:
      - no challenge was set and no verifier presented (PKCE not in use)
      - method=plain and verifier equals challenge
      - method=S256 and base64url(SHA256(verifier)) equals challenge

    Returns ``False`` otherwise. Note that callers gate ``plain`` via
    a separate per-client opt-in (oidc_allow_plain_pkce); this
    function only validates the math.

    Spec: RFC 7636 "Proof Key for Code Exchange by OAuth Public Clients"
      §4.6 "Server Verifies code_verifier before Returning the Tokens"
      https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
    Spec: OAuth 2.1 §7.5.2 forbids "plain" (S256 is the only
      compliant method going forward)
      https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
    """
    if not code_challenge:
        return code_verifier is None
    if not code_verifier:
        return False
    method = (code_challenge_method or "plain").upper()
    if method == "PLAIN":
        return code_verifier == code_challenge
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        calc = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return calc == code_challenge
    return False


def compute_acr(amr, scheme):
    """ Map an AMR list to an ACR string per ``oidc_acr_scheme``.

    Schemes:
      - ``"numeric"``: ``"0"`` / ``"1"`` / ``"2"`` -- broadest RP support.
      - ``"none"``: don't emit acr (returns ``None``).

    Heuristic: hardware-backed/mfa => "2", any factor => "1",
    nothing => "0".

    Spec: OIDC Core 1.0 §2 "ID Token" (acr claim, registered claims)
      https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Spec: ISO/IEC 29115 (numeric assurance levels referenced by acr)
    """
    if scheme == "none":
        return None
    if not amr:
        return "0"
    if STRONG_AMR_FACTORS.intersection(amr):
        return "2"
    return "1"
