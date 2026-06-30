# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import encryption
from otpme.lib.audit import audit_log
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.encryption.ed25519 import Ed25519Key
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

logger = config.logger

default_callback = config.get_callback()

read_acls =  []
write_acls =  []

write_acls_acls =  [
                "generate",
            ]

read_value_acls = {
                "view"      : [
                            "key_type",
                            "auth_script",
                            "sign_public_key",
                            "encrypt_public_key",
                            "ssh_public_key",
                            "dot1x_secret",
                            "private_key_backup",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            "signature",
                            ],
            }

write_value_acls = {
                "add"       : [
                            "signature",
                            ],
                "delete"    : [
                            "signature",
                            ],
                "verify"    : [
                            "signature",
                            ],
                "edit"      : [
                            "key_type",
                            "sign_public_key",
                            "encrypt_public_key",
                            "ssh_public_key",
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
    'sign_public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_sign_public_key',
                    'oargs'             : ['public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'encrypt_public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_encrypt_public_key',
                    'oargs'             : ['public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_sign_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_sign_key',
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_encrypt_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_encrypt_key',
                    'job_type'          : 'process',
                    },
                },
            },
    'ssh_public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_ssh_public_key',
                    'oargs'             : ['ssh_public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'key_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_type',
                    'args'              : ['key_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_private_key_backup'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_private_key_backup',
                    'job_type'          : 'process',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'sign',
                    'oargs'             : ['tags', 'stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'resign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'resign',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sign',
                    'oargs'             : ['signature', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sign',
                    'oargs'             : ['username', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'verify_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign_data',
                    'oargs'             : ['tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
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
                    sub_type="yubikey_piv",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "key_type")
    config.register_auth_on_action_hook("token", "sign_public_key")
    config.register_auth_on_action_hook("token", "encrypt_public_key")
    config.register_auth_on_action_hook("token", "ssh_public_key")
    config.register_auth_on_action_hook("token", "show_config_parameters")
    config.register_auth_on_action_hook("token", "add_sign")
    config.register_auth_on_action_hook("token", "del_sign")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "yubikey_piv")
    config.register_ssh_token("yubikey_piv")

@match_class_typing
class YubikeypivToken(Token):
    """ Class for OTPme authentication with RSA tokens (e.g. yubikey-piv) """
    oidc_amr_values = ['hwk', 'sc', 'pin']

    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        user: Union[str,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        **kwargs,
        ):
        # Call parent class init.
        super().__init__(object_id=object_id,
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
        self.token_type = "yubikey_piv"
        # Set password type.
        self.pass_type = "smartcard"
        # Public keys come in pairs: sign for ECDSA-style verify,
        # encrypt for HPKE/RSA-OAEP wrap. On YubiKey-PIV they live in
        # slots 9A (AUTHENTICATION) and 9D (KEY_MANAGEMENT) respectively.
        self.sign_public_key = None
        self.sign_key_type = None
        self.encrypt_public_key = None
        self.encrypt_key_type = None
        # Set SSH key type.
        self.ssh_public_key = None
        self.key_type = "rsa"
        self.dot1x_secret = None
        self.support_dot1x = True
        self.valid_key_types = [ "rsa", "dsa" ]
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        # Token specific settings.
        self.need_password = True
        self.offline_pinnable = True
        self.signable = True
        self.signatures = {}
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'yubikey_piv' ]

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "KEY_TYPE",
                            "SIGN_PUBLIC_KEY",
                            "ENCRYPT_PUBLIC_KEY",
                            "SSH_PUBLIC_KEY",
                            "SIGNATURES",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "KEY_TYPE",
                            "SIGN_PUBLIC_KEY",
                            "ENCRYPT_PUBLIC_KEY",
                            "SSH_PUBLIC_KEY",
                            "SIGNATURES",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'SIGN_PUBLIC_KEY'           : {
                                            'var_name'      : 'sign_public_key',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'SIGN_KEY_TYPE'             : {
                                            'var_name'      : 'sign_key_type',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'ENCRYPT_PUBLIC_KEY'        : {
                                            'var_name'      : 'encrypt_public_key',
                                            'type'          : str,
                                            'required'      : False,
            'ENCRYPT_KEY_TYPE'             : {
                                            'var_name'      : 'encrypt_key_type',
                                            'type'          : str,
                                            'required'      : False,
                                        },
                                        },
            'SSH_PUBLIC_KEY'            : {
                                            'var_name'      : 'ssh_public_key',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'PRIVATE_KEY_BACKUP'        : {
                                            'var_name'      : 'private_key_backup',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            'DOT1X_SECRET'            : {
                                            'var_name'      : 'dot1x_secret',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'KEY_TYPE'                  : {
                                            'var_name'      : 'key_type',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'SIGNATURES'                : {
                                            'var_name'  : 'signatures',
                                            'type'      : dict,
                                            'required'  : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        offline_config['NEED_OFFLINE_ENCRYPTION'] = True
        return offline_config

    def get_offline_data(self):
        offline_data = {
                        'sign_public_key'       : self.sign_public_key,
                        'sign_key_type'         : self.sign_key_type,
                        'encrypt_public_key'    : self.encrypt_public_key,
                        'encrypt_key_type'      : self.encrypt_key_type,
                    }
        return offline_data

    def gen_challenge(self):
        """ Generate challenge. """
        challenge = os.urandom(32)
        challenge = challenge.hex()
        return challenge

    @check_acls(['edit:sign_public_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_sign_public_key(
        self,
        public_key: str,
        force: bool=False,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set tokens signing public key (verification of token-signed data). """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_sign_public_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if self.sign_public_key is not None:
            msg = _("Replace existing sign public key?: ")
            if not self.ask_change_confirmation(msg, force=force, callback=callback):
                return callback.abort()

        if public_key == "":
            self.sign_public_key = None
        else:
            self.sign_public_key = public_key

        return self._cache(callback=callback)

    @check_acls(['edit:encrypt_public_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_encrypt_public_key(
        self,
        public_key: str,
        force: bool=False,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set tokens encryption public key (wrap secrets for the token). """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_encrypt_public_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if self.encrypt_public_key is not None:
            msg = _("Replace existing encrypt public key?: ")
            if not self.ask_change_confirmation(msg, force=force, callback=callback):
                return callback.abort()

        if public_key == "":
            self.encrypt_public_key = None
        else:
            self.encrypt_public_key = public_key

        return self._cache(callback=callback)

    @check_acls(['edit:ssh_public_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_ssh_public_key(
        self,
        public_key: str,
        force: bool=False,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set tokens SSH public key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_ssh_public_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if self.ssh_public_key is not None:
            msg = _("Replace existing SSH public key?: ")
            if not self.ask_change_confirmation(msg, force=force, callback=callback):
                return callback.abort()

        if public_key == "":
            self.ssh_public_key = None
        else:
            self.ssh_public_key = public_key

        return self._cache(callback=callback)

    @check_acls(['edit:key_type'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_key_type(
        self,
        key_type: str="rsa",
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get supported hardware card/token types. """
        if not key_type in self.valid_key_types:
            msg = _("Unsupported key type: {key_type}")
            msg = msg.format(key_type=key_type)
            return callback.error(msg)
        if key_type == self.key_type:
            msg = _("Key type already set to: {key_type}")
            msg = msg.format(key_type=key_type)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_key_type",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.key_type = key_type
        return self._cache(callback=callback)

    @check_acls(['view:sign_public_key'])
    @audit_log()
    def dump_sign_key(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Dump tokens signing public key. """
        return callback.ok(self.sign_public_key)

    @check_acls(['view:encrypt_public_key'])
    @audit_log()
    def dump_encrypt_key(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Dump tokens encryption public key. """
        return callback.ok(self.encrypt_public_key)

    @check_acls(['view:private_key_backup'])
    @audit_log()
    def get_private_key_backup(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Dump tokens RSA public key. """
        if not self.private_key_backup:
            msg = _("No backup exists.")
            return callback.error(msg)
        return callback.ok(dict(self.private_key_backup))

    def verify_acl(self, action: str):
        """ Verify ACLs required to allow <action>. """
        # Parent class cannot know the ACL to allow verification of signatures
        # e.g. "view:script" for script objects and "view_public_key" for SSH
        # tokens.
        if action == "verify_signature":
            if self._verify_acl("verify:signature") \
            or self._verify_acl("view:signature") \
            or self._verify_acl("view:ssh_public_key"):
                return True

        if action == "get_signatures":
            if self._verify_acl("view:signature") \
            or self.verify_acl("view:ssh_public_key"):
                return True

        # Finally try to verify ACL via parent class method.
        if self._verify_acl(action):
            return True

        return  False

    @check_acls(['view:ssh_public_key'])
    def get_sign_data(self, callback: JobCallback=default_callback, **kwargs):
        """ Return public key to be signed by parent class method. """
        ssh_public_key = self.ssh_public_key
        return callback.ok(ssh_public_key)

    def test(self, callback: JobCallback=default_callback, **kwargs):
        """ Test if smartcard connected to the client can be verfied. """
        ok_message = _("Token verified successful: {token_path}")
        ok_message = ok_message.format(token_path=self.rel_path)
        error_message = _("Token verification failed.")
        # Gen challenge.
        challenge = self.gen_challenge()
        smartcard_data = {
                    'token_path'    : self.rel_path,
                    'challenge'     : challenge,
                    'pass_required' : True,
                    }
        signature = callback.scauth(smartcard_type="yubikey_piv",
                            smartcard_data=smartcard_data)
        # Verify signature.
        sc_data = {
                    'challenge' : challenge,
                    'signature' : signature,
                }
        status = self.verify(sc_data,
                            **kwargs)
        if status:
            return callback.ok(ok_message)
        return callback.error(error_message)

    def verify(self, smartcard_data: dict, **kwargs):
        """ Call default verify method. """
        challenge = smartcard_data['challenge']
        signature = smartcard_data['signature']
        if not self.sign_public_key:
            return
        key = encryption.load_public_key(self.sign_public_key)
        verify_args = {
                        'signature' : signature,
                        'message'   : challenge,
                    }
        if isinstance(key, RSAKey):
            verify_args['padding'] = "PSS"
            verify_args['algorithm'] = "SHA256"
            verify_args['encoding'] = "hex"
        if isinstance(key, Ed25519Key):
            verify_args['encoding'] = "hex"
        try:
            verify_status = key.verify(**verify_args)
        except Exception as e:
            verify_status = False
        if not verify_status:
            return False
        return True

    @object_lock(full_lock=True)
    def pre_deploy(
        self,
        pre_deploy_args: dict=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy token. """
        if pre_deploy_args is None:
            pre_deploy_args = {}
        response = {}
        try:
            restore_from_server = pre_deploy_args['restore_from_server']
        except KeyError:
            restore_from_server = False
        try:
            private_key_backup_key = self.get_config_parameter("private_key_backup_key")
        except Exception:
            private_key_backup_key = None
        if restore_from_server:
            try:
                response['private_key_backup'] = self.get_private_key_backup()
            except Exception as e:
                msg = _("Failed to get backup: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)
        if private_key_backup_key:
            response['private_key_backup_key'] = private_key_backup_key
        return callback.ok(response)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def deploy(
        self,
        sign_public_key: str,
        sign_key_type: str,
        encrypt_public_key: str,
        encrypt_key_type: str,
        add_user_key: bool=False,
        ssh_public_key: str=None,
        ssh_public_key_type: str=None,
        dot1x_secret: str=None,
        private_key_backup: Union[dict,None]=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy RSA key pair (sign + encrypt) to the token. """
        if verbose_level > 0:
            msg = _("Setting sign + encrypt public keys on token: {token_path}")
            msg = msg.format(token_path=self.rel_path)
            callback.send(msg)
        self.sign_public_key = sign_public_key
        self.sign_key_type = sign_key_type
        self.encrypt_public_key = encrypt_public_key
        self.sign_key_type = sign_key_type
        self.encrypt_key_type = encrypt_key_type
        if add_user_key:
            owner = self.owner
            result = backend.search(object_type="user",
                                    attribute="name",
                                    value=owner,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            user = result[0]
            user.sign_key_type = sign_key_type
            user.encrypt_key_type = encrypt_key_type
            sign_pub_b64 = encode(sign_public_key, "base64")
            encrypt_pub_b64 = encode(encrypt_public_key, "base64")
            user.change_sign_public_key(public_key=sign_pub_b64,
                                    verify_acls=False,
                                    force=True)
            user.change_encrypt_public_key(public_key=encrypt_pub_b64,
                                    verify_acls=False,
                                    force=True)
        if private_key_backup:
            self.private_key_backup = private_key_backup
        if ssh_public_key:
            self.ssh_public_key = ssh_public_key
            self.key_type = ssh_public_key_type
        if dot1x_secret:
            self.dot1x_secret = dot1x_secret
        msg = _("Yubikey PIV token deployed successful.")
        callback.send(msg)
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, callback: JobCallback=default_callback, **kwargs):
        """ Add a token. """
        return callback.ok()

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Chow token config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:sign_public_key"):
            lines.append(f'SIGN_PUBLIC_KEY="{self.sign_public_key}"')
        else:
            lines.append('SIGN_PUBLIC_KEY=""')

        if self.verify_acl("view:sign_key_type"):
            lines.append(f'SIGN_KEY_TYPE="{self.sign_key_type}"')
        else:
            lines.append('SIGN_KEY_TYPE=""')

        if self.verify_acl("view:encrypt_public_key"):
            lines.append(f'ENCRYPT_PUBLIC_KEY="{self.encrypt_public_key}"')
        else:
            lines.append('ENCRYPT_PUBLIC_KEY=""')

        if self.verify_acl("view:encrypt_key_type"):
            lines.append(f'ENCRYPT_KEY_TYPE="{self.encrypt_key_type}"')
        else:
            lines.append('ENCRYPT_KEY_TYPE=""')

        if self.verify_acl("view:ssh_public_key"):
            lines.append(f'SSH_PUBLIC_KEY="{self.ssh_public_key}"')
        else:
            lines.append('SSH_PUBLIC_KEY=""')

        if self.verify_acl("view:key_type"):
            lines.append(f'KEY_TYPE="{self.key_type}"')
        else:
            lines.append('KEY_TYPE=""')

        if self.verify_acl("view:dot1x_secret"):
            lines.append(f'DOT1X_SECRET="{self.dot1x_secret}"')
        else:
            lines.append('DOT1X_SECRET=""')

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
