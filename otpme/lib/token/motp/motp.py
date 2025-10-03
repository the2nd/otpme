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
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import mschap_util
from otpme.lib.otp.motp import motp
from otpme.lib.audit import audit_log
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
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
            ]

read_value_acls = {
                "view"      : [
                            "secret",
                            "pin",
                            "auth_script",
                            "offset",
                            "validity_time",
                            "timedrift_tolerance",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
            }

write_value_acls = {
                "generate"  : [
                            "otp",
                            ],
                "edit"      : [
                            "secret",
                            "pin",
                            "auth_script",
                            "offset",
                            "validity_time",
                            "timedrift_tolerance",
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
    'secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_secret',
                    'oargs'             : ['auto_secret', 'secret'],
                    'job_type'          : 'process',
                    },
                },
            },
    'pin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_pin',
                    'oargs'             : ['auto_pin', 'pin'],
                    'job_type'          : 'process',
                    },
                },
            },
    'validity_time'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_validity_time',
                    'oargs'             : ['validity_time'],
                    'job_type'          : 'process',
                    },
                },
            },
    'timedrift_tolerance'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_timedrift_tolerance',
                    'oargs'             : ['timedrift_tolerance'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show_secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_secret',
                    'job_type'          : 'process',
                    },
                },
            },
    'show_pin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_pin',
                    'job_type'          : 'process',
                    },
                },
            },
    'gen'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'gen_otp',
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
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'oargs'             : ['password'],
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
    register_config_params()
    register_commands("token",
                    commands,
                    sub_type="motp",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "show_secret")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "motp")

def register_config_params():
    """ Register config params. """
    # Object types our config parameters are valid for.
    object_types = [
                    'site',
                    'unit',
                    'user',
                ]
    # MOTP validity time.
    config.register_config_parameter(name="motp_validity_time",
                                    ctype=int,
                                    default_value=3,
                                    object_types=object_types)
    # MOTP timedrift tolerance.
    config.register_config_parameter(name="motp_timedrift_tolerance",
                                    ctype=int,
                                    default_value=3,
                                    object_types=object_types)
    # MOTP default PIN length.
    config.register_config_parameter(name="motp_default_pin_len",
                                    ctype=int,
                                    default_value=4,
                                    object_types=object_types)
    # MOTP default length.
    config.register_config_parameter(name="motp_len",
                                    ctype=int,
                                    default_value=6,
                                    object_types=object_types)
    # MOTP default secret length.
    config.register_config_parameter(name="motp_secret_len",
                                    ctype=int,
                                    default_value=16,
                                    object_types=object_types)

@match_class_typing
class MotpToken(Token):
    """ Class for MOTP tokens. """
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
        super(MotpToken, self).__init__(object_id=object_id,
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
        self.token_type = "motp"
        # Set password type.
        self.pass_type = "otp"
        self.otp_type = "time"

        # Set default values.
        self.pin = None
        self.otp_len = None
        self.secret_len = None
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.sync_offline_otps = True
        self.keep_session = False
        self.pin_mandatory = True
        self.need_password = True
        #self.valid_otp_formats = [ '6digit" ]
        self.offset = 0
        self.validity_time = None
        self.timedrift_tolerance = None

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'PIN'                       : {
                                            'var_name'      : 'pin',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'OTP_LEN'                   : {
                                            'var_name'      : 'otp_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'SECRET_LEN'                : {
                                            'var_name'      : 'secret_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'OFFSET'                    : {
                                            'var_name'      : 'offset',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'VALIDITY_TIME'             : {
                                            'var_name'      : 'validity_time',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'TIMEDRIFT_TOLERANCE'       : {
                                            'var_name'      : 'timedrift_tolerance',
                                            'type'          : int,
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

    def gen_secret(self, token_secret: str, pin: str, ** kwargs):
        """ Generate server secret from token secret and PIN. """
        import hashlib
        token_secret = token_secret.encode("utf-8")
        hash_string = b"%s%s" % (pin.encode(), token_secret)
        sha512 = hashlib.sha512()
        sha512.update(hash_string)
        secret = sha512.hexdigest()
        secret = secret[0:self.secret_len]
        return secret

    @property
    def default_pin_len(self):
        default_pin_len = self.get_config_parameter("motp_default_pin_len")
        return default_pin_len

    def _change_pin(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change token PIN """
        return callback.ok()

    @check_acls(['edit:validity_time'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_validity_time(
        self,
        run_policies: bool=True,
        validity_time: Union[int,None]=None,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change token validity time. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_validity_time",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if validity_time is None:
            while True:
                answer = callback.ask(_("Validity time: "))
                try:
                    validity_time = int(answer)
                    break
                except:
                    pass

        if not isinstance(validity_time, int):
            msg = _("Need integer for <validity_time>.")
            return callback.error(msg)

        self.validity_time = validity_time

        return self._cache(callback=callback)

    @check_acls(['edit:timedrift_tolerance'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_timedrift_tolerance(
        self,
        run_policies: bool=True,
        timedrift_tolerance: Union[int,None]=None,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change token timedrift tolerance. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_timedrift_tolerance",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if timedrift_tolerance is None:
            while True:
                answer = callback.ask(_("Timedrift tolerance: "))
                try:
                    timedrift_tolerance = int(answer)
                    break
                except:
                    pass

        if not isinstance(timedrift_tolerance, int):
            msg = _("Need integer for <timedrift_tolerance>.")
            return callback.error(msg)

        self.timedrift_tolerance = timedrift_tolerance

        return self._cache(callback=callback)

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        # Make sure our object config is up-to-date.
        self.update_object_config()
        # Get a copy of our object config.
        offline_config = self.object_config.copy()

        # When used as second factor token (e.g. with ssh or password token) we
        # have a password/ssh-key to encrypt our config.
        if second_factor_usage:
            need_encryption = True
        else:
            # When not used as second factor we do not have a password to
            # encrypt our offline config.
            need_encryption = False

        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption

        return offline_config

    @check_acls(['generate:otp'])
    def gen_otp(
        self,
        otp_count: int=1,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Generate one or more OTPs for this token. """
        if not self.secret:
            return callback.error(_("Token secret missing."))

        if otp_count > 1:
            otps = motp.generate(secret=self.secret,
                                otp_count=otp_count,
                                otp_len=self.otp_len,
                                pin=self.pin)
            return otps
        else:
            otp = motp.generate(secret=self.secret,
                                otp_count=otp_count,
                                otp_len=self.otp_len,
                                pin=self.pin)
            if _caller != "API":
                return callback.ok(otp)
            return [otp]

    def test(
        self,
        password: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Test if the given OTP can be verified by this token. """
        ok_message = _("Token verified successful.")
        error_message = _("Token verification failed.")
        otp_prompt = _("OTP: ")
        if not password:
            password = callback.askpass(otp_prompt)
        if not password:
            return callback.error(_("Unable to get OTP."))
        status = self.verify_otp(otp=str(password), **kwargs)
        if status:
            return callback.ok(ok_message)
        return callback.error(error_message)

    def verify(
        self,
        challenge: Union[str,None]=None,
        response: Union[str,None]=None,
        **kwargs,
        ):
        """ Call default verify method. """
        if challenge and response:
            return self.verify_mschap_otp(challenge=challenge,
                                            response=response,
                                            **kwargs)
        else:
            return self.verify_otp(**kwargs)

    def verify_otp(
        self,
        otp: str,
        handle_used_otps: bool=True,
        session_uuid: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify OTP for this token. """

        if handle_used_otps:
            if self.is_used_otp(otp):
                return False

        # MOTP configuration option is in minutes. MOTP timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate times to verify OTP.
        validity_times = motp.get_validity_times(validity_time=validity_time,
                                        timedrift_tolerance=timedrift_tolerance,
                                        offset=self.offset)
        otp_epoch_time = validity_times[0]
        otp_validity_range = validity_times[1]
        otp_validity_start_time = validity_times[4]
        otp_validity_end_time = validity_times[5]

        # Log OTP timerange.
        log_msg = _("Verifiying OTP within timerange: start='{start}' end='{end}'.", log=True)[1]
        log_msg = log_msg.format(start=otp_validity_start_time, end=otp_validity_end_time)
        logger.debug(log_msg)
        # Verify OTP.
        if motp.verify(epoch_time=otp_epoch_time,
                        validity_range=otp_validity_range,
                        secret=self.secret, otp=otp,
                        otp_len=self.otp_len,
                        pin=self.pin):
            if handle_used_otps:
                self.add_used_otp(otp=otp,
                            session_uuid=session_uuid,
                            quiet=False)
            return True

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return None

        # This point should never be reached.
        msg = _("WARNING: You may have hit a BUG of Token().verify_otp().")
        raise Exception(msg)

    def verify_static(self, **kwargs):
        """ Verify given password against 'password' token. """
        msg = _("Verifying static passwords is not supported with token type: '{token_type}'.")
        msg = msg.format(token_type=self.token_type)
        raise OTPmeException(msg)

    def verify_mschap_static(self, **kwargs):
        """ Verify MSCHAP challenge/response against static passwords """
        msg = _("Verifying an static MSCHAP request is not supported with token type '{token_type}'.")
        msg = msg.format(token_type=self.token_type)
        raise OTPmeException(msg)

    def verify_mschap_otp(
        self,
        challenge: str,
        response: str,
        handle_used_otps: bool=True,
        session_uuid: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify MSCHAP challenge/response against OTP. """
        nt_key = None
        otp = None

        # MOTP configuration option is in minutes. MOTP timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate times to verify OTP.
        validity_times = motp.get_validity_times(validity_time=validity_time,
                                        timedrift_tolerance=timedrift_tolerance,
                                        offset=self.offset)
        otp_epoch_time = validity_times[0]
        otp_validity_range = validity_times[1]
        otp_validity_start_time = validity_times[4]
        otp_validity_end_time = validity_times[5]

        # Get all OTPs of this token for the given time range.
        otps = motp.generate(epoch_time=otp_epoch_time,
                            secret=self.secret,
                            pin=self.pin,
                            otp_count=otp_validity_range,
                            otp_len=self.otp_len)

        log_msg = _("Verifiying OTP within timerange: start='{start}' end='{end}'.", log=True)[1]
        log_msg = log_msg.format(start=otp_validity_start_time, end=otp_validity_end_time)
        logger.debug(log_msg)
        # Set default return_value.
        failed_return_value = False, False, False
        return_value = None, False, False
        # Walk through all valid OTPs.
        for otp in otps:
            # Get NT key from verify().
            nt_hash = stuff.gen_nt_hash(otp)
            status, nt_key = mschap_util.verify(nt_hash, challenge, response)
            if status:
                if handle_used_otps:
                    if self.is_used_otp(otp):
                        return failed_return_value
                    self.add_used_otp(otp=otp,
                                session_uuid=session_uuid,
                                quiet=False)
                return status, nt_key, otp

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return return_value

        # This point should never be reached.
        msg = _("WARNING: You may have hit a BUG of Token().verify_mschap_otp().")
        raise Exception(msg)

    @check_acls(['generate:otp'])
    def gen_mschap(
        self,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Generate MSCHAP challenge response stuff for testing. """
        if run_policies:
            try:
                self.run_policies("gen_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        otp = self.gen_otp()[0]
        return Token._gen_mschap(self, password=otp, callback=callback)

    def add_used_otp(
        self,
        otp: str,
        session_uuid: Union[str,None]=None,
        quiet: bool=True,
        ):
        """ Add OTP to list of already used OTPs for this token. """
        # In offline mode check if we should cache/sync used OTPs.
        if self.offline:
            if not self.sync_offline_otps:
                return True

        # MOTP configuration option is in minutes. MOTP timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate OTP validity times.
        validity_times = motp.get_validity_times(validity_time=validity_time,
                                            timedrift_tolerance=timedrift_tolerance,
                                            offset=self.offset)
        otp_epoch_time = validity_times[0]
        otp_validity_range = validity_times[1]

        # Multiply with 2 because we want an used OTP to be cached twice the
        # time it is valid.
        otp_validity_range = otp_validity_range * 2

        # Calculate OTP expiry timestamp.
        expiry = float(str(otp_epoch_time + otp_validity_range) + "0")

        # Add used OTP using parent class method.
        Token._add_used_otp(self, otp, expiry,
                            session_uuid=session_uuid,
                            quiet=quiet)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(
        self,
        no_token_infos: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a token. """
        # Get default MOTP settings.
        self.validity_time = self.get_config_parameter("motp_validity_time")
        self.timedrift_tolerance = self.get_config_parameter("motp_timedrift_tolerance")
        self.otp_len = self.get_config_parameter("motp_len")
        self.pin_len = self.default_pin_len
        self.pin = stuff.gen_pin(self.pin_len)
        self.secret_len = self.get_config_parameter("motp_secret_len")
        token_secret = stuff.gen_secret(self.secret_len)
        self.secret = self.gen_secret(token_secret=token_secret, pin=self.pin)
        # Generate salt for used OTP hashes.
        self.used_otp_salt = stuff.gen_secret(32)

        return_message = None
        if not no_token_infos:
            if self.verify_acl("view:secret"):
                return_message = _("Token secret: {secret}")
                return_message = return_message.format(secret=self.secret)
            if self.verify_acl("view:pin"):
                message = _("Token PIN: {pin}")
                message = message.format(pin=self.pin)
                if return_message:
                    return_message = f"{return_message}\n{message}"
                else:
                    return_message = message

        if return_message:
            return callback.ok(return_message)

        return callback.ok()

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token info. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:offset"):
            lines.append(f'OFFSET="{self.offset}"')
        else:
            lines.append('OFFSET=""')

        if self.verify_acl("view:timedrift_tolerance"):
            lines.append(f'TIMEDRIFT_TOLERANCE="{self.timedrift_tolerance}"')
        else:
            lines.append('TIMEDRIFT_TOLERANCE=""')

        if self.verify_acl("view:validity_time"):
            lines.append(f'VALIDITY_TIME="{self.validity_time}"')
        else:
            lines.append('VALIDITY_TIME=""')

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
