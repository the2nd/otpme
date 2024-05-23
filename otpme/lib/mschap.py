# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import hashlib
from passlib.utils import des

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def generate_nt_response(authenticator_challenge,
    peer_challenge, username, password):
    """ https://tools.ietf.org/html/rfc2759#section-8.1 """
    challenge = challenge_hash(peer_challenge,
                            authenticator_challenge,
                            username)

    nt_hash = nt_password_hash(password)
    return challenge_response(challenge, nt_hash)

def challenge_hash(peer_challenge, authenticator_challenge, username):
    """ https://tools.ietf.org/html/rfc2759#section-8.2 """
    sha1 = hashlib.sha1()
    sha1.update(peer_challenge)
    sha1.update(authenticator_challenge)
    if isinstance(username, str):
        username = username.encode('utf-8')
    sha1.update(username)
    return sha1.digest()[:8]

def nt_password_hash(password):
    """ https://tools.ietf.org/html/rfc2759#section-8.3 """
    if isinstance(password, str):
        pw_bin = password.encode('utf-16')[2:]
    else:
        pw_bin = password[2:]
    md4 = hashlib.new('md4')
    md4.update(pw_bin)
    password_hash = md4.digest()
    return password_hash

def hash_nt_password_hash(password_hash):
    """ https://tools.ietf.org/html/rfc2759#section-8.4 """
    md4 = hashlib.new('md4')
    md4.update(password_hash)
    password_hash_hash = md4.digest()
    return password_hash_hash

def challenge_response(challenge, password_hash):
    """ https://tools.ietf.org/html/rfc2759#section-8.5 """
    zpwd = b''.join((password_hash, b'\x00'*5))

    response = b''
    key = des.expand_des_key(zpwd[:7])
    response += des.des_encrypt_block(key, challenge)

    key = des.expand_des_key(zpwd[7:14])
    response += des.des_encrypt_block(key, challenge)

    key = des.expand_des_key(zpwd[14:])
    response += des.des_encrypt_block(key, challenge)

    return response

def generate_authenticator_response(nt_response, peer_challenge,
    authenticator_challenge, username, password=None, password_hash=None):
    """ https://tools.ietf.org/html/rfc2759#section-8.7 """
    magic1 = b"\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76" \
            b"\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65" \
            b"\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67" \
            b"\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74"

    magic2 = b"\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B"  \
            b"\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F" \
            b"\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E" \
            b"\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F" \
            b"\x6E"

    if password and not password_hash:
        password_hash = nt_password_hash(password)
    password_hash_hash = hash_nt_password_hash(password_hash)

    m = hashlib.sha1()
    m.update(password_hash_hash[:16])
    m.update(nt_response[:24])
    m.update(magic1[:39])
    digest = m.digest()

    challenge = challenge_hash(peer_challenge,
                            authenticator_challenge,
                            username)
    n = hashlib.sha1()
    n.update(digest[:20])
    n.update(challenge[:8])
    n.update(magic2[:41])
    authenticator_response = n.hexdigest()

    return "S=%s" % authenticator_response

def get_master_key(nt_response, password_hash=None, password_hash_hash=None):
    """ https://tools.ietf.org/html/draft-ietf-pppext-mschapv2-keys-02 """
    magic1 = b"\x54\x68\x69\x73\x20\x69\x73\x20\x74" \
            b"\x68\x65\x20\x4D\x50\x50\x45\x20\x4D" \
            b"\x61\x73\x74\x65\x72\x20\x4B\x65\x79"

    if not password_hash_hash and password_hash:
        password_hash_hash = hash_nt_password_hash(password_hash)

    m = hashlib.sha1()
    m.update(password_hash_hash[:16])
    m.update(nt_response[:24])
    m.update(magic1[:27])
    digest = m.digest()
    master_key = digest[:16]
    return master_key

def get_asymetric_start_key(master_key, session_key_len, is_send, is_server):
    """ https://tools.ietf.org/html/draft-ietf-pppext-mschapv2-keys-02 """
    magic2 = b"\x4F\x6E\x20\x74\x68\x65\x20\x63\x6C\x69" \
            b"\x65\x6E\x74\x20\x73\x69\x64\x65\x2C\x20" \
            b"\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68" \
            b"\x65\x20\x73\x65\x6E\x64\x20\x6B\x65\x79" \
            b"\x3B\x20\x6F\x6E\x20\x74\x68\x65\x20\x73" \
            b"\x65\x72\x76\x65\x72\x20\x73\x69\x64\x65" \
            b"\x2C\x20\x69\x74\x20\x69\x73\x20\x74\x68" \
            b"\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20" \
            b"\x6B\x65\x79\x2E"

    magic3 = b"\x4F\x6E\x20\x74\x68\x65\x20\x63\x6C\x69" \
            b"\x65\x6E\x74\x20\x73\x69\x64\x65\x2C\x20" \
            b"\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68" \
            b"\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20" \
            b"\x6B\x65\x79\x3B\x20\x6F\x6E\x20\x74\x68" \
            b"\x65\x20\x73\x65\x72\x76\x65\x72\x20\x73" \
            b"\x69\x64\x65\x2C\x20\x69\x74\x20\x69\x73" \
            b"\x20\x74\x68\x65\x20\x73\x65\x6E\x64\x20" \
            b"\x6B\x65\x79\x2E"

    shspad1 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


    shspad2 = b"\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2" \
            b"\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2" \
            b"\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2" \
            b"\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2"

    if is_send:
        if is_server:
            s = magic3
        else:
            s = magic2
    else:
        if is_server:
            s = magic2
        else:
            s = magic3

    m = hashlib.sha1()
    m.update(master_key[:16])
    m.update(shspad1[:40])
    m.update(s[:84])
    m.update(shspad2[:40])
    session_key = m.digest()[:session_key_len]
    return session_key
