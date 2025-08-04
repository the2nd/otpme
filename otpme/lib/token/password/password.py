# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.classes.token import Token
from otpme.lib.otpme_acl import check_acls
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
write_acls =  [
            "generate",
            "upgrade_pass_hash",
        ]

read_value_acls = {
                "view"      : [
                            "password",
                            "mschap",
                            "nt_hash",
                            "auth_script",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
        }

write_value_acls = {
                "edit"      : [
                            "password",
                            "auth_script",
                            "offline_expiry",
                            "offline_unused_expiry",
                            ],
                "enable"    : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            "mschap",
                            ],
                "disable"   : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            "mschap",
                            ],
                "generate"  : [
                            "mschap",
                            ],
                }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['enable_mschap'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'              : ['enable_mschap'],
                    'job_type'          : 'process',
                    },
                },
            },
    'password'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_password',
                    'oargs'             : ['auto_password', 'password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'upgrade_pass_hash'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'upgrade_pass_hash',
                    'oargs'             : ['hash_type', 'hash_args'],
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
    '2f_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_2f_token',
                    'args'              : ['second_factor_token'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_2f'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_2f_token',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_2f'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_2f_token',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_mschap'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_mschap',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_mschap'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_mschap',
                    'job_type'          : 'process',
                    },
                },
            },
    'gen_mschap'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'gen_mschap',
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
REGISTER_AFTER = ["otpme.lib.encryption.argon2"]

def register():
    """ Register object. """
    register_hooks()
    register_token_type()
    register_config_parameters()
    register_commands("token",
                    commands,
                    sub_type="password",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "resync")
    config.register_auth_on_action_hook("token", "change_2f_token")
    config.register_auth_on_action_hook("token", "enable_2f_token")
    config.register_auth_on_action_hook("token", "disable_2f_token")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "password")

def register_config_parameters():
    """ Registger config parameters. """
    # Default length of static passwords.
    object_types = [
                        'realm',
                        'site',
                        'unit',
                        'user',
                    ]
    # Allow to rename default token?
    config.register_config_parameter(name="default_static_pass_len",
                                    ctype=int,
                                    default_value=8,
                                    object_types=object_types)

@match_class_typing
class PasswordToken(Token):
    """ Class for static password 'tokens'. """
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
        super(PasswordToken, self).__init__(object_id=object_id,
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
        self.token_type = "password"
        # Set password type.
        self.pass_type = "static"
        # Set default values.
        self.password_hash = None
        self.need_password = True
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        self.mschap_enabled = False
        self.offline_pinnable = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy)
        # FIXME: implement deployment of yubikey in static mode (e.g. password via usb keyboard presses)
        self.supported_hardware_tokens = [ 'yubikey-static' ]
        # Valid token pass types that could be used as a second factor.
        self.valid_2f_pass_types = [ 'otp', 'smartcard' ]

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'PASSWORD_HASH'             : {
                                            'var_name'      : 'password_hash',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'PASSWORD_HASH_PARAMS'      : {
                                            'var_name'      : 'password_hash_params',
                                            'type'          : list,
                                        },

            'NT_HASH'                   : {
                                            'var_name'      : 'nt_hash',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'MSCHAP_ENABLED'            : {
                                            'var_name'      : 'mschap_enabled',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'SECOND_FACTOR_TOKEN'       : {
                                            'var_name'      : 'second_factor_token',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },

            'SECOND_FACTOR_TOKEN_ENABLED': {
                                            'var_name'      : 'second_factor_token_enabled',
                                            'type'          : bool,
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

    def get_offline_data(self):
        offline_data = {
                        'password_hash' : self.password_hash,
                    }
        return offline_data

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        need_encryption = True
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    @check_acls(['edit:2ftoken'])
    @object_lock(full_lock=True)
    @backend.transaction
    def change_2f_token(
        self,
        second_factor_token: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token second factor token. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_2f_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        if second_factor_token == "":
            self.second_factor_token = None
        else:
            # Get user instance of token owner.
            user = backend.get_object(object_type="user", uuid=self.owner_uuid)
            # Get token instance of 2f_token by name.
            sftoken = user.token(second_factor_token)
            if not sftoken:
                msg = (_("Token '%s' does not exist.") % second_factor_token)
                return callback.error(msg)
            if not sftoken.pass_type in self.valid_2f_pass_types:
                msg = (_("Token '%s' is not a valid second factor token.")
                        % sftoken.rel_path)
                return callback.error(msg)

            # Set 2f_token.
            self.second_factor_token = sftoken.uuid

        self.update_index('second_factor_token', self.second_factor_token)

        return self._cache(callback=callback)

    @check_acls(['enable:2ftoken'])
    @object_lock()
    @backend.transaction
    def enable_2f_token(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable the second factor token. """
        if self.second_factor_token_enabled:
            return callback.error("Second factor token already enabled.")

        if not self.second_factor_token:
            return callback.error("No second factor token configured.")

        # Check if second factor token is available.
        try:
            self.get_sftoken(callback=callback)
        except Exception as e:
            msg = (_("Unable to enable second factor token: %s") % e)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_2f_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable second factor token?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.second_factor_token_enabled = True
        self.update_index('second_factor_token_enabled', True)
        return self._cache(callback=callback)

    @check_acls(['disable:2ftoken'])
    @object_lock()
    @backend.transaction
    def disable_2f_token(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable the second factor token. """
        if not self.second_factor_token_enabled:
            return callback.error("Second factor token already disabled.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_2f_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Disable second factor token?: ")
                if answer.lower() != "y":
                    return callback.abort()

        self.second_factor_token_enabled = False
        self.update_index('second_factor_token_enabled', False)
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def resync(self, callback: JobCallback=default_callback, **kwargs):
        """ Wrapper method to call resync() of 2ftoken. """
        try:
            sftoken = self.get_sftoken()
        except Exception as e:
            return callback.error(_("Error loading second factor token: %s")
                                    % e)
        return sftoken.resync(callback=callback, **kwargs)

    def test(
        self,
        password: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Test if the given password/OTP can be verified by this token. """
        ok_message = "Token verified successful: %s" % self.rel_path
        error_message = "Password verification failed."

        pass_prompt = "Password: "
        ignore_2f_token = False
        # Check if a second factor token is enabled.
        if self.second_factor_token_enabled:
            try:
                sftoken = self.get_sftoken()
            except Exception as e:
                msg = (_("Error loading second factor token: %s") % e)
                return callback.error(msg)

            if sftoken.pass_type == "otp":
                pass_prompt = "Password+OTP: "
            if sftoken.pass_type == "smartcard":
                ignore_2f_token = True

        # Get password from user.
        if not password:
            password = callback.askpass(pass_prompt)

        if not password:
            return callback.error("Unable to get password.")

        # Verify smartcard token before password to prevent brute force attacks.
        verify_status = False
        verify_password = True
        if self.second_factor_token_enabled and sftoken.pass_type == "smartcard":
            if not sftoken.test(callback=callback):
                verify_password = False

        # Verify password only if U2F token was verified successful.
        if verify_password:
            verify_status = self.verify_static(password=str(password),
                                        ignore_2f_token=ignore_2f_token,
                                        **kwargs)
        if not verify_status:
            return callback.error(error_message)

        return callback.ok(ok_message)

    def verify(self, auth_type: str, **kwargs):
        """ Call default verify method. """
        if auth_type == "mschap":
            return self.verify_mschap_static(**kwargs)
        return self.verify_static(**kwargs)

    def verify_static(
        self,
        password: str,
        password_hash: Union[str,None]=None,
        smartcard_data: Union[dict,None]=None,
        ignore_2f_token: bool=False,
        session_uuid: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify given password against 'password' token. """
        log_used_otp_warning = False

        if not isinstance(password, str):
            msg = ("'password' needs to be of type str()")
            raise OTPmeException(msg)

        if not self.password_hash:
            return False

        # Verify second factor token if enabled.
        if not ignore_2f_token and self.second_factor_token_enabled:
            try:
                sftoken = self.get_sftoken()
            except Exception as e:
                msg = ("Error loading second factor token: %s" % e)
                logger.critical(msg)
                return None

            logger.debug("Verifying second factor token: %s"
                        % sftoken.rel_path)

            if sftoken.pass_type == "otp":
                log_used_otp_warning = True
                # FIXME: maybe we will add a policy for this later.
                # Check if token PIN is mandatory. By default we dont want a
                # user to type in the token PIN when used as second factor
                # token.
                if sftoken.pin_mandatory:
                    verify_pin = True
                    otp_includes_pin = True
                    cutoff_len = sftoken.pin_len + sftoken.otp_len
                else:
                    verify_pin = False
                    otp_includes_pin = False
                    cutoff_len = sftoken.otp_len

                # Cut off OTP from password.
                otp = password[-cutoff_len:]
                password = password[:-cutoff_len]

                # Create new password hash after OTP cutoff.
                password_hash = self.gen_password_hash(password)
                # Verify OTP with second factor token (and add to list of used
                # OTPs) _BEFORE_ static password is checked to prevent brute
                # force attacks with stolen OTP!
                if not sftoken.verify_otp(otp,
                                        otp_includes_pin=otp_includes_pin,
                                        session_uuid=session_uuid,
                                        verify_pin=verify_pin,
                                        sft=True):
                    return None

            elif sftoken.pass_type == "smartcard":
                if not smartcard_data:
                    msg = ("Missing smartcard authentication data "
                            "to verify second factor token: %s" % sftoken)
                    logger.warning(msg)
                    return None
                if not sftoken.verify(smartcard_data):
                    return None

            logger.debug("Second factor token verified successful: %s"
                        % sftoken.rel_path)

        # Create password hash if none was given.
        if not password_hash:
            # Show some debug info in offline mode.
            quiet = True
            if self.offline:
                quiet = False
            password_hash = self.gen_password_hash(password, quiet=quiet)

        # Verify password hash.
        if password_hash == self.password_hash:
            return True

        if log_used_otp_warning:
            msg = ("Added used OTP on failed password verify to "
                    "prevent brute force attacks.")
            logger.info(msg)

        # Default should be None -> Token hash does not match request.
        return None

        # This point should never be reached.
        msg = ("WARNING: You may have hit a BUG of Token().verify_static().")
        raise Exception(msg)

    @check_acls(['generate:mschap'])
    def gen_mschap(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Generate MSCHAP challenge response stuff for testing. """
        if not self.nt_hash:
            msg = "Missing NT HASH."
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("gen_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        # Use parent function to return MSCHAP stuff.
        return Token._gen_mschap(self,
                                password_hash=self.nt_hash,
                                callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(
        self,
        password: Union[str,None]=None,
        enable_mschap: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a token. """
        if enable_mschap:
            self.enable_mschap(force=True, quiet=True, callback=callback)

        pass_len = self.get_config_parameter("default_static_pass_len")
        if password is None:
            new_pass = stuff.gen_password(pass_len)
        else:
            new_pass = password

        self.change_password(password=new_pass,
                            verify_acls=False,
                            force=True,
                            callback=callback)

        return_message = ""
        if not enable_mschap:
            return_message = ("NOTE: You may want to add a second factor token "
                            "(e.g. OTP token) to improve security.")

        if self.verify_acl("view:password"):
            token_pass_msg = ("Token password: %s" % new_pass)
            if return_message:
                return_message = ("%s\n%s" % (return_message, token_pass_msg))
            else:
                return_message = token_pass_msg

        return callback.ok(return_message)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        second_factor_token_name = ""
        if self.verify_acl("view:2ftoken"):
            # Get 2f token instance:
            if self.second_factor_token:
                try:
                    sftoken = self.get_sftoken()
                    second_factor_token_name = sftoken.name
                except Exception as e:
                    callback.send(_("Error loading second factor token: %s")
                                    % e)
        lines.append('SECOND_FACTOR_TOKEN="%s"' % second_factor_token_name)

        second_factor_token_enabled = ""
        if self.verify_acl("view:2ftoken_status"):
            second_factor_token_enabled = self.second_factor_token_enabled
        lines.append('SECOND_FACTOR_TOKEN_ENABLED="%s"'
                    % second_factor_token_enabled)

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
