# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
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
                            "secret",
                            "auth_script",
                            "public_key",
                            "private_key_backup",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "public_key",
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
    'public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_public_key',
                    'oargs'             : ['public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump_key',
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
    config.register_auth_on_action_hook("token", "public_key")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "yubikey_piv")

@match_class_typing
class YubikeypivToken(Token):
    """ Class for OTPme authentication with RSA tokens (e.g. yubikey-piv) """
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
        super(YubikeypivToken, self).__init__(object_id=object_id,
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
        self.secret_len = 0
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        # Token specific settings.
        self.need_password = True
        self.offline_pinnable = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'yubikey_piv' ]

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'PUBLIC_KEY'                : {
                                            'var_name'      : 'public_key',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'PRIVATE_KEY_BACKUP'        : {
                                            'var_name'      : 'private_key_backup',
                                            'type'          : dict,
                                            'required'      : False,
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
                        'public_key'        : self.public_key,
                    }
        return offline_data

    def gen_challenge(self):
        """ Generate challenge. """
        challenge = os.urandom(32)
        challenge = challenge.hex()
        return challenge

    @check_acls(['edit:public_key'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_public_key(
        self,
        public_key: str,
        force: bool=False,
        verbose_level: int=0,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set tokens RSA public key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("change_public_key",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {e}")
                msg = msg.format(e=e)
                return callback.error(msg)

        if self.public_key is not None and not force:
            if self.confirmation_policy != "force":
                ask = callback.ask("Replace existing public key?: ")
                if str(ask).lower() != "y":
                    return callback.abort()

        if public_key == "":
            self.public_key = None
        else:
            # Set public key.
            self.public_key = public_key

        return self._cache(callback=callback)

    @check_acls(['view:public_key'])
    @audit_log()
    def dump_key(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Dump tokens RSA public key. """
        return callback.ok(self.public_key)

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
        if not self.public_key:
            return
        key = RSAKey(key=self.public_key)
        try:
            verify_status = key.verify(signature=signature,
                                        message=challenge,
                                        padding='PSS',
                                        algorithm="SHA256",
                                        encoding="hex")
        except Exception:
            verify_status = False
        if not verify_status:
            return False
        return True

    @object_lock(full_lock=True)
    def pre_deploy(
        self,
        pre_deploy_args: dict={},
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy token. """
        response = {}
        try:
            restore_from_server = pre_deploy_args['restore_from_server']
        except KeyError:
            restore_from_server = False
        try:
            private_key_backup_key = self.get_config_parameter("private_key_backup_key")
        except:
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
        public_key: str,
        add_user_key: bool=False,
        private_key_backup: Union[dict,None]=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy RSA key token. """
        if verbose_level > 0:
            msg = _("Setting public key to token: {token_path}")
            msg = msg.format(token_path=self.rel_path)
            callback.send(msg)
        self.public_key = public_key
        if add_user_key:
            owner = self.owner
            result = backend.search(object_type="user",
                                    attribute="name",
                                    value=owner,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            user = result[0]
            pub_key_b64 = encode(public_key, "base64")
            user.change_public_key(public_key=pub_key_b64,
                                    verify_acls=False,
                                    force=True)
        if private_key_backup:
            self.private_key_backup = private_key_backup
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

        if self.verify_acl("view:public_key"):
            lines.append(f'PUBLIC_KEY="{self.public_key}"')
        else:
            lines.append('PUBLIC_KEY=""')

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
