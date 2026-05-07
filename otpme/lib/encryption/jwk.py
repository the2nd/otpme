# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
JWK / JWKS helpers.

Used by the OIDC OP for signing-key generation, JWKS rendering, and
key-rotation bookkeeping. Kept under otpme/lib/encryption/ so
otpme.lib.classes (Site) can use it without importing from the web
layer.
"""
import hashlib
from typing import Any, Dict, List

from joserfc.jwk import ECKey, OKPKey, RSAKey


_DEFAULT_KEY_TYPE = "RSA"
_DEFAULT_KEY_SIZE = 2048
_DEFAULT_ALG = "RS256"


def generate_signing_key(kty: str = _DEFAULT_KEY_TYPE,
                         size=_DEFAULT_KEY_SIZE,
                         alg: str = _DEFAULT_ALG) -> Dict[str, Any]:
    """ Generate a fresh signing keypair as a JWK dict.

    For RSA: ``size`` is the modulus bit length (2048, 3072, 4096).
    For EC:  ``size`` is the curve name (e.g. ``P-256``).
    For OKP: ``size`` is the curve name (e.g. ``Ed25519``).

    Returns the **private** JWK including private parameters (``d``,
    etc.) so the caller can persist it on the Site object. The
    returned dict carries:
        kty, kid, alg, use="sig", and the algorithm-specific params.

    A custom ``otpme_status`` field is set to "active" by default; on
    rotation the caller flips the previous active key to "retired".
    """
    parameters = {"alg": alg, "use": "sig"}
    if kty == "RSA":
        key = RSAKey.generate_key(size, parameters=parameters, private=True)
    elif kty == "EC":
        key = ECKey.generate_key(size, parameters=parameters, private=True)
    elif kty == "OKP":
        key = OKPKey.generate_key(size, parameters=parameters, private=True)
    else:
        raise ValueError(f"Unsupported key type: {kty}")
    jwk = key.as_dict(private=True)
    jwk.setdefault("alg", alg)
    jwk.setdefault("use", "sig")
    jwk["kid"] = derive_kid(jwk)
    jwk["otpme_status"] = "active"
    return jwk


def derive_kid(jwk: Dict[str, Any]) -> str:
    """ Derive a stable, unique kid from the public key material.

    SHA-256 of the canonical public-key fingerprint, hex-truncated to
    16 chars. Stable across serialization, unique per key, doesn't
    leak timing information.
    """
    public_only = {k: v for k, v in jwk.items()
                   if k in ("kty", "n", "e", "crv", "x", "y")}
    items = sorted(public_only.items())
    blob = "&".join(f"{k}={v}" for k, v in items).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def public_jwk(jwk: Dict[str, Any]) -> Dict[str, Any]:
    """ Return a JWK safe to publish (no private parameters).

    Uses joserfc's per-kty Key class as an allowlist source: we
    import the JWK and ask the resulting Key object for its public
    serialisation. That way joserfc decides which fields are private
    (``d``, ``p``, ``q``, ``dp``, ``dq``, ``qi`` for RSA, ``d`` for
    EC/OKP, etc.) -- a denylist we'd otherwise have to maintain by
    hand and that would silently leak when a new kty is added.

    OTPme-internal metadata (``otpme_status``) is stripped on top.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        key = RSAKey.import_key(jwk)
    elif kty == "EC":
        key = ECKey.import_key(jwk)
    elif kty == "OKP":
        key = OKPKey.import_key(jwk)
    else:
        raise ValueError(f"Unsupported key type: {kty}")
    pub = key.as_dict(private=False)
    pub.pop("otpme_status", None)
    return pub


def render_jwks(signing_keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    """ Build a JWKS document from a list of JWKs.

    Includes both active and retired keys (so RPs can verify tokens
    signed before the latest rotation). Strips private fields.
    """
    return {"keys": [public_jwk(k) for k in signing_keys]}


def find_active_key(signing_keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    """ Return the JWK marked active. Raises LookupError if none. """
    for k in signing_keys:
        if k.get("otpme_status") == "active":
            return k
    raise LookupError("No active OIDC signing key on this Site.")
