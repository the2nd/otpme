#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def test():
    from otpme.lib import config
    from otpme.lib import init_otpme
    from otpme.lib import mschap_util
    from otpme.lib import stuff
    from otpme.lib import sotp
    from otpme.lib import srp
    from otpme.lib import slp
    from otpme.lib.encoding.base import encode

    from otpme.lib import backend
    logger = config.logger
    init_otpme()

    # Just for quick testing of stuff.

    # Test MSCHAP module.
    from otpme.lib import mschap
    from otpme.lib import mschap_util

    username = "testuser"
    password = "oopaimaipoojuozu"
    password_hash = b"33fb9ce05a55d4bc716068e987dfe3d3"
    #password_hash = stuff.gen_nt_hash(password)
    mschapv1_challenge = b"bc4ac1f4fa0ac85d"
    peer_nt_response = b"1b74d28fbe9d5812fc986a49af3a9ebfba6c39d4e0389f85"
    peer_challenge = b"a25a9bc4b9c9b05ab785cb0540dc6298"
    auth_challenge = b"3425354b7edfdd458f64bed60f8ef46d"

    result = mschap_util.verify(password_hash=password_hash,
                                challenge=mschapv1_challenge,
                                response=peer_nt_response)
    verify_status = result[0]
    if not verify_status:
        raise Exception("Wrong password.")

    auth_response = mschap.generate_authenticator_response(peer_nt_response,
                                                            peer_challenge,
                                                            auth_challenge,
                                                            username,
                                                            password_hash=password_hash)
    print("Authenticator Response : " + auth_response)

    password_hash_hash = mschap.hash_nt_password_hash(password_hash)
    master_key = mschap.get_master_key(password_hash_hash, peer_nt_response)
    print(b"MasterKey : " + encode(master_key, "hex"))

    master_receive_key = mschap.get_asymetric_start_key(master_key, 16, is_send=False, is_server=True)
    print(b"MppeRecvKey : " + encode(master_receive_key, "hex"))

    master_send_key = mschap.get_asymetric_start_key(master_key, 16, is_send=True, is_server=True)
    print(b"MppeSendKey : " + encode(master_send_key, "hex"))


    ## Test JWT stuff.
    #from otpme.lib import jwt
    #payload = {
    #        'data'          : 'some data',
    #        }

    ## RSA
    #key = config.host_data['key']
    #encoded = jwt.encode(payload, key=key, algorithm='RS256')
    #print(jwt.decode(encoded, key=key, algorithm='RS256'))

    ## HMAC
    #secret = "asgdljsdalj"
    #encoded = jwt.encode(payload, secret=secret, algorithm='HS256')
    #print(jwt.decode(encoded, secret=secret, algorithms=['HS256']))

    ## No encryption
    #encoded = jwt.encode(payload, algorithm='HS256')
    #print(jwt.decode(encoded, algorithms=['HS256']))


    ## read parameter from command line
    #parameter = sys.argv[2]

    ## test otp age verification stuff
    #import time
    #otp_used_time = os.path.getmtime("/tmp/test")
    ## calculate otp age
    #otp_age = time.time() - otp_used_time
    #print(otp_age)
    #print(motp_validity_time * 10 * 2)

    ## check if add_used_otp() works
    #user = User(name='tester')
    #if user.exists():
    #    token = user.token('motp')
    #    if token.exists():
    #        token.add_used_otp('abcd')
    #        print(token.is_used_otp('abcd'))


    ## test parent group selection
    #from otpme.lib.classes.accessgroup import AccessGroup
    #group = AccessGroup(name='smtp', realm=config.realm, site=config.site)
    #if group.exists():
    #    parent_tree = group.parents(recursive=True, sessions=True, return_type="name")
    #    for p in parent_tree:
    #        print(p)

    ## test session master search
    #group = AccessGroup(name='smtp', realm=config.realm, site=config.site)
    #if group.exists():
    #    session_master = group.parents(recursive=True, sessions=True, session_master=True, return_type="name")
    #    print(session_master)

    ## test child group selection
    #group = AccessGroup(name='mail', realm=config.realm, site=config.site)
    #if group.exists():
    #    child_tree = group.childs(recursive=True, sessions=True, return_type="name")
    #    for c in child_tree:
    #        print(c)

    ## test session master search
    #group = AccessGroup(name='test', realm=config.realm, site=config.site)
    #if group.exists():
    #    session_master = group.childs(recursive=True, sessions=True, session_master=True, return_type="instance")
    #    print(session_master.name)

    ## test logging
    #logger.critical("critical")
    #logger.error("error")
    #logger.warning("warning")
    #logger.info("info")
    #logger.debug("debug")

    ## check if object gets deleted from cache on .delete()
    #user = User(name='test', realm=config.realm, site=config.site)
    #if user.exists():
    #    print(user.uuid)
    #print(backend.object_cache[user.object_id])
    #user.delete()
    #print(backend.object_cache[user.object_id])

    # from otpme.lib.encryption import aes
    #
    #print(config.master_key)
    #aesdata = aes.encrypt(config.master_key, "My secret message!")
    #print(aes.decrypt(config.master_key, aesdata))


    ## test ldap server
    #from otpme.lib.ldap.server import LDAPServer
    #listen_address = "10.219.195.12"
    #list_port = "808"
    #s = LDAPServer(address=listen_address, port=list_port)
    #s.listen(use_ssl=False)
    #s.run()
