# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from fido2.utils import sha256
from fido2.ctap1 import SignatureData
from fido2.ctap1 import RegistrationData

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.protocols.utils import register_commands

from otpme.lib.classes.token \
            import get_acls \
            as _get_acls
from otpme.lib.classes.token \
            import get_value_acls \
            as _get_value_acls
from otpme.lib.classes.token \
            import get_default_acls \
            as _get_default_acls
from otpme.lib.classes.token \
            import get_recursive_default_acls \
            as _get_recursive_default_acls

from otpme.lib.exceptions import *

default_callback = config.get_callback()

logger = config.logger

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "attestation_cert",
                            "auth_script",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
                }

write_value_acls = {
                "edit"      : [
                            "attestation_cert",
                            "auth_script",
                            "offline_expiry",
                            "offline_unused_expiry",
                            ],
                "enable"    : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                "disable"   : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                }

default_acls = []

recursive_default_acls = []

commands = {
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_token_read_acls, \
        otpme_token_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_token_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_token_write_acls)
        return _read_acls, _write_acls
    otpme_token_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_token_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_token_read_value_acls, \
        otpme_token_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_token_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(write_value_acls,
                                                        otpme_token_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_token_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_token_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    token_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, token_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    token_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                token_recursive_default_acls)
    return _acls

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    """ Register object. """
    register_hooks()
    register_token_type()
    register_commands("token",
                    commands,
                    sub_type="fido2",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "deploy")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "fido2")

class Fido2Token(Token):
    """ Class for fido2 tokens. """
    commands = commands
    def __init__(self, object_id=None, user=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(Fido2Token, self).__init__(object_id=object_id,
                                            realm=realm,
                                            site=site,
                                            user=user,
                                            name=name,
                                            path=path,
                                            **kwargs)

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()
        # Set token type.
        self.token_type = "fido2"
        # Set password type.
        self.pass_type = "smartcard"
        # Set default values.
        self.reg_app_id = None
        self.reg_challenge = None
        self.key_handle = None
        self.public_key = None
        self.attestation_cert = None
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'fido2' ]

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'REG_APP_ID'          : {
                                            'var_name'      : 'reg_app_id',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'REG_CHALLENGE'       : {
                                            'var_name'      : 'reg_challenge',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'KEY_HANDLE'                : {
                                            'var_name'      : 'key_handle',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'PUBLIC_KEY'                : {
                                            'var_name'      : 'public_key',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'ATTESTATION_CERT'          : {
                                            'var_name'      : 'attestation_cert',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Token.set_variables(self)

    def get_offline_config(self, second_factor_usage=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        # FIXME: implement self.allow_offline_rsp!!!
        need_encryption = False
        #if self.allow_offline_rsp:
        #    need_encryption = True
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    def gen_challenge(self):
        """ Generate challenge. """
        challenge = os.urandom(32)
        challenge_hash = sha256(challenge)
        challenge_hash_hex = encode(challenge_hash, "hex")
        return challenge, challenge_hash, challenge_hash_hex

    @object_lock(full_lock=True)
    def pre_deploy(self, _caller="API",
        verbose_level=0, callback=default_callback):
        """ Deploy fido2 token. """
        # Generate registration ID.
        self.reg_app_id = "https://%s" % self.realm
        # Generate registration challenge.
        self.reg_challenge = self.gen_challenge()[2]
        reply = {
                'app_id'    : self.reg_app_id,
                'challenge' : self.reg_challenge,
                }
        self._write(callback=callback)
        return callback.ok(reply)

    @object_lock(full_lock=True)
    @backend.transaction
    def deploy(self, registration_data, uv="discouraged", _caller="API",
        verbose_level=0, callback=default_callback):
        """ Deploy fido2 token. """
        # Generate app id hash.
        app_id_hash = sha256(self.reg_app_id.encode())
        reg_challenge_hash = decode(self.reg_challenge, "hex")
        registration_data = RegistrationData.from_b64(registration_data)
        try:
            registration_data.verify(app_param=app_id_hash,
                                    client_param=reg_challenge_hash)
        except Exception as e:
            msg = "Failed to verify registration parameters: %s" % e
            return callback.error(msg)
        # Set key handle.
        self.key_handle = encode(registration_data.key_handle, "hex")
        # Set public key.
        self.public_key = encode(registration_data.public_key, "hex")
        # Write object.
        self._cache(callback=callback)
        msg = "Fido2 token deployed successful."
        return callback.ok(msg)

    def test(self, force=False, callback=default_callback, **kwargs):
        """ Test token authentication. """
        # Get app ID.
        app_id = self.reg_app_id
        # Generate authentication challenge.
        auth_challenge, \
        auth_challenge_hash, \
        auth_challenge_hash_hex = self.gen_challenge()
        smartcard_data = {
                    'token_path'    : self.rel_path,
                    'app_id'        : app_id,
                    'challenge'     : auth_challenge_hash_hex,
                    'key_handle'    : self.key_handle,
                    'pass_required' : False,
                    }
        # Do smartcard authentication on client.
        auth_response = callback.scauth(smartcard_type="fido2",
                                smartcard_data=smartcard_data)
        # Get signature data from response.
        try:
            signature_data = SignatureData.from_b64(auth_response)
        except Exception as e:
            msg = "Failed to load fido2 signature data."
            return callback.error(msg)
        # Generate app ID hash.
        app_id_bytes = app_id.encode()
        app_id_hash = sha256(app_id_bytes)
        # Load public key.
        public_key = decode(self.public_key, "hex")
        # Verify signature.
        try:
            signature_data.verify(app_param=app_id_hash,
                                client_param=auth_challenge_hash,
                                public_key=public_key)
        except Exception as e:
            msg = "Fido2 token response verification failed: %s" % e
            return callback.error(msg)
        msg = "Token verified successful: %s" % self.rel_path
        return callback.ok(msg)

    def verify(self, smartcard_data, callback=default_callback, **kwargs):
        """ Verify signature. """
        # Get challenge.
        challenge = smartcard_data['challenge']
        challenge = decode(challenge, "hex")
        # Get signature data from response.
        try:
            signature_data = smartcard_data['signature_data']
            signature_data = SignatureData.from_b64(signature_data)
        except Exception as e:
            msg = "Failed to load fido2 signature data."
            return callback.error(msg)
        # Generate app ID hash.
        app_id = self.reg_app_id
        app_id_bytes = app_id.encode()
        app_id_hash = sha256(app_id_bytes)
        # Load public key.
        public_key = decode(self.public_key, "hex")
        # Verify signature.
        try:
            signature_data.verify(app_param=app_id_hash,
                                client_param=challenge,
                                public_key=public_key)
        except Exception as e:
            msg = "Fido2 token response verification failed: %s" % e
            logger.critical(msg)
            return False
        return True

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, _caller="API", **kwargs):
        """ Add a fido2 token. """
        if _caller == "CLIENT":
            return_message = (_("NOTE: You have to deploy this fido2 token to "
                                "make it usable."))
            return callback.ok(return_message)
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:key_handle"):
            lines.append('KEY_HANDLE="%s"' % self.key_handle)
        else:
            lines.append('KEY_HANDLE=""')

        if self.verify_acl("view:attestation_cert"):
            lines.append('ATTESTATION_CERT="%s"' % self.attestation_cert)
        else:
            lines.append('ATTESTATION_CERT=""')

        return Token.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        """ Show token details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
