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
from otpme.lib.otp.motp import motp
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
write_acls =  []

write_acls_acls =  [
                "generate",
            ]

read_value_acls = {
                "view"      : [
                            "secret",
                            "auth_script",
                            "smartcard_id",
                            "slot",
                            "hmac_id",
                            "hmac_challenge",
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
                            "auth_script",
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

# Currently we only support yubikeys an there its most likely that slot 2 is
# used for HMAC authentication.
DEFAULT_SLOT = 2

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
    'show_secret'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_secret',
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
                    sub_type="yubikey_hmac",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "show_secret")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "yubikey_hmac")

def register_config_params():
    """ Register config params. """
    # Object types our config paramters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                ]
    # Default OTP length.
    config.register_config_parameter(name="otpme_hmac_otp_len",
                                    ctype=int,
                                    default_value=16,
                                    object_types=object_types)
    # Default secret length.
    config.register_config_parameter(name="otpme_hmac_secret_len",
                                    ctype=int,
                                    default_value=16,
                                    object_types=object_types)

@match_class_typing
class YubikeyhmacToken(Token):
    """ Class for OTPme authentication with HMAC tokens (e.g. yubikey) """
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
        super(YubikeyhmacToken, self).__init__(object_id=object_id,
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
        self.token_type = "yubikey_hmac"
        # Set password type.
        self.pass_type = "smartcard"
        self.otp_type = "time"
        self.offset = 0
        self.validity_time = 0
        self.timedrift_tolerance = 0
        self.otp_len = 0
        self.secret_len = 0
        self.auth_script_enabled = False
        # FIXME: implement offline token mode and something like below!!!
        #        mode1 = PIN is not saved anywhere but entered into the soft token.
        #        mode2 = PIN is saved on server in the token object and entered as OTP prefix.
        self.valid_modes = [ 'mode1', 'mode2']
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        # Token specific settings.
        self.smartcard_id = None
        self.hmac_id = None
        self.hmac_challenge = None
        self.slot = DEFAULT_SLOT
        self.need_password = True
        self.offline_pinnable = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'yubikey_hmac' ]

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'SMARTCARD_ID'              : {
                                            'var_name'      : 'smartcard_id',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'HMAC_ID'                   : {
                                            'var_name'      : 'hmac_id',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'HMAC_CHALLENGE'            : {
                                            'var_name'      : 'hmac_challenge',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'SLOT'                      : {
                                            'var_name'      : 'slot',
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
            'OTP_LEN'                   : {
                                            'var_name'      : 'otp_len',
                                            'type'          : int,
                                            'required'      : True,
                                        },
            'SECRET_LEN'                : {
                                            'var_name'      : 'secret_len',
                                            'type'          : int,
                                            'required'      : True,
                                        },
            }

        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Token.set_variables(self)

        if self.smartcard_id:
            # Set client options that will be used to configure access to
            # hardware tokens/smartcards when authenticating (e.g. yubikey
            # slot to use)
            self.client_options = {
                                'slot'  : self.slot,
                                }

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        offline_config['NEED_OFFLINE_ENCRYPTION'] = True
        return offline_config

    def get_offline_data(self):
        offline_data = {
                        'slot'              : self.slot,
                        'hmac_id'           : self.hmac_id,
                        'hmac_challenge'    : self.hmac_challenge,
                        'otp_len'           : self.otp_len,
                        'secret'            : self.secret,
                        'smartcard_id'      : self.smartcard_id,
                    }
        return offline_data

    @check_acls(['edit:validity_time'])
    @object_lock()
    @backend.transaction
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
                answer = callback.ask("Validity time: ")
                try:
                    validity_time = int(answer)
                    break
                except:
                    pass

        if not isinstance(int, validity_time):
            msg = "Need integer for <validity_time>."
            return callback.error(msg)

        self.validity_time = validity_time

        return self._cache(callback=callback)

    @check_acls(['edit:timedrift_tolerance'])
    @object_lock()
    @backend.transaction
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
                self.run_policies("change_validity_time",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if timedrift_tolerance is None:
            while True:
                answer = callback.ask("Timedrift tolerance: ")
                try:
                    timedrift_tolerance = int(answer)
                    break
                except:
                    pass

        if not isinstance(int, timedrift_tolerance):
            msg = "Need integer for <timedrift_tolerance>."
            return callback.error(msg)

        self.timedrift_tolerance = timedrift_tolerance

        return self._cache(callback=callback)

    @check_acls(['generate:otp'])
    def gen_otp(
        self,
        otp_count: int=1,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Generate one or more OTPs for this token. """
        if otp_count > 1:
            otps = motp.generate(secret=self.secret,
                                    otp_count=otp_count,
                                    otp_len=self.otp_len)
            return otps
        else:
            otp = motp.generate(secret=self.secret,
                                otp_count=1,
                                otp_len=self.otp_len)
            return [otp]

    def test(self, callback: JobCallback=default_callback, **kwargs):
        """ Test if smartcard connected to the client can be verfied. """
        ok_message = "Token verified successful: %s" % self.rel_path
        error_message = "Token verification failed."

        # Get optme OTP via HMAC challenge/response.
        smartcard_data = {
                    'token_path'    : self.rel_path,
                    'challenge'     : self.hmac_challenge,
                    'slot'          : self.slot,
                    'otp_len'       : self.otp_len,
                    'pass_required' : True,
                    }
        otp = callback.scauth(smartcard_type="yubikey_hmac",
                            smartcard_data=smartcard_data)
        # Verify OTP.
        status = self.verify_otp(otp=str(otp),
                                handle_used_otps=False,
                                **kwargs)
        if status:
            return callback.ok(ok_message)
        return callback.error(error_message)

    def verify(self, smartcard_data: dict, **kwargs):
        """ Call default verify method. """
        smartcard_id = smartcard_data['smartcard_id']
        if smartcard_id != self.smartcard_id:
            msg = "Received OTP for wrong smartcard: %s" % self.smartcard_id
            raise OTPmeExtension(msg)
        otp = smartcard_data['otp']
        return self.verify_otp(otp)

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

        # OTPME configuration option is in minutes. OTPme timestep is 10 seconds.
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
        msg = ("Verifiying OTP within timerange: start='%s' end='%s'."
                % (otp_validity_start_time, otp_validity_end_time))
        logger.debug(msg)
        # Verify OTP.
        if motp.verify(epoch_time=otp_epoch_time,
                        validity_range=otp_validity_range,
                        secret=self.secret,
                        otp=otp,
                        otp_len=self.otp_len):
            if handle_used_otps:
                self.add_used_otp(otp=otp,
                            session_uuid=session_uuid,
                            quiet=False)
            return True

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return None

        # This point should never be reached.
        msg = (_("WARNING: You may have hit a BUG of Token().verify_otp()."))
        raise Exception(msg)

    @check_acls(['generate:otp'])
    def gen_mschap(self, callback: JobCallback=default_callback, **kwargs):
        """ Generate MSCHAP challenge response stuff for testing. """
        otp = self.gen_otp()[0]
        return Token._gen_mschap(self, password=otp, callback=callback, **kwargs)

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

        # OTPME configuration option is in minutes. OTPME timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate times to verify OTP.
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
    def deploy(
        self,
        smartcard_id: str,
        secret: str,
        hmac_challenge: str,
        hmac_id: str,
        slot: int=DEFAULT_SLOT,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy HMAC token. """
        if verbose_level > 0:
            callback.send(_("Setting smartcard ID to token: %s")
                            % self.rel_path)
        self.smartcard_id = str(smartcard_id)
        if verbose_level > 0:
            callback.send(_("Setting HMAC ID to token: %s") % self.rel_path)
        self.hmac_id = str(hmac_id)
        if verbose_level > 0:
            callback.send(_("Setting HMAC challenge to token: %s") % self.rel_path)
        self.hmac_challenge = str(hmac_challenge)
        if verbose_level > 0:
            callback.send(_("Setting secret to token: %s") % self.rel_path)
        self.secret = str(secret)
        if verbose_level > 0:
            callback.send(_("Configuring token for slot: %s") % slot)
        self.slot = slot
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, callback: JobCallback=default_callback, **kwargs):
        """ Add a token. """
        # Get default HOTP settings.
        self.validity_time = self.get_config_parameter("otpme_validity_time")
        self.timedrift_tolerance = self.get_config_parameter("otpme_timedrift_tolerance")
        self.secret_len = self.get_config_parameter("otpme_hmac_secret_len")
        self.otp_len = self.get_config_parameter("otpme_hmac_otp_len")
        self.secret = stuff.gen_secret(self.secret_len)
        # Generate salt for used OTP hashes.
        self.used_otp_salt = stuff.gen_secret(32)
        return callback.ok()

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Chow token config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:offset"):
            lines.append('OFFSET="%s"' % self.offset)
        else:
            lines.append('OFFSET=""')

        if self.verify_acl("view:slot"):
            lines.append('SLOT="%s"' % self.slot)
        else:
            lines.append('SLOT=""')

        if self.verify_acl("view:smartcard_id"):
            lines.append('SMARTCARD_ID="%s"' % self.smartcard_id)
        else:
            lines.append('SMARTCARD_ID=""')

        if self.verify_acl("view:hmac_id"):
            lines.append('HMAC_ID="%s"' % self.hmac_id)
        else:
            lines.append('HMAC_ID=""')

        if self.verify_acl("view:hmac_challenge"):
            lines.append('HMAC_CHALLENGE="%s"' % self.hmac_challenge)
        else:
            lines.append('HMAC_CHALLENGE=""')

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
