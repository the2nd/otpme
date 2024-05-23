# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import mschap_util
from otpme.lib.otp.otpme import otpme
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls

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

# xxxxxxxxxxxxxx
# FIXME: implement different OTP formats
read_value_acls = {
                "view"      : [
                            "secret",
                            "auth_script",
                            "offline_status",
                            "validity_time",
                            "timedrift_tolerance",
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
                            "pin",
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                "disable"   : [
                            "pin",
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

def register_hooks():
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "show_secret")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "otpme")

def register_config_params():
    """ Register config params. """
    # Object types our config parameters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                ]
    # OTPME validity time.
    config.register_config_parameter(name="otpme_validity_time",
                                    ctype=int,
                                    default_value=3,
                                    object_types=object_types)
    # OTPME timedrift tolerance.
    config.register_config_parameter(name="otpme_timedrift_tolerance",
                                    ctype=int,
                                    default_value=3,
                                    object_types=object_types)
    # OTPME default PIN length.
    config.register_config_parameter(name="otpme_default_pin_len",
                                    ctype=int,
                                    default_value=4,
                                    object_types=object_types)
    # OTPME default length.
    config.register_config_parameter(name="otpme_otp_len",
                                    ctype=int,
                                    default_value=6,
                                    object_types=object_types)
    # OTPME default secret length.
    config.register_config_parameter(name="otpme_secret_len",
                                    ctype=int,
                                    default_value=16,
                                    object_types=object_types)

class OtpmeToken(Token):
    """ Class for OTPme tokens. """
    def __init__(self, object_id=None, user=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(OtpmeToken, self).__init__(object_id=object_id,
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
        self.token_type = "otpme"
        # Set password type.
        self.pass_type = "otp"
        self.otp_type = "time"
        # Set default values.
        self.offset = 0
        self.validity_time = None
        self.timedrift_tolerance = None
        self.auth_script_enabled = False
        # FIXME: implement offline token mode and something like below!!!
        #        mode1 = PIN is not saved anywhere but entered into the soft token.
        #        mode2 = PIN is saved on server in the token object and entered as OTP prefix.
        self.valid_modes = [ 'mode1', 'mode2']
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        self.need_password = True

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
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

    @property
    def otp_len(self):
        """ Get OTP len. """
        otp_len  = self.get_config_parameter("otpme_otp_len")
        return otp_len

    @property
    def secret_len(self):
        """ Get token secret length. """
        secret_len = self.get_config_parameter("otpme_secret_len")
        return secret_len

    def get_offline_config(self, second_factor_usage=False):
        """ Get offline config of token. """
        offline_config = self.object_config.copy()
        # Disable encryption cause OTPme tokens do not contain a static part
        # we could use to encrypt it.
        need_encryption = False
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        # FIXME: use argon hash here? do we need argon in android app??
        # When used as offline token we need a special secret.
        offline_secret = stuff.gen_md5("OFFLINE:%s" % self.secret)
        # Add offline secret to config.
        offline_config['OFFLINE_SECRET'] = offline_secret
        # Remove normal secret.
        offline_config.pop('SECRET')
        return offline_config

    @check_acls(['edit:validity_time'])
    @object_lock()
    @backend.transaction
    def change_validity_time(self, run_policies=True, validity_time=None,
        _caller="API", callback=default_callback, **kwargs):
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
    def change_timedrift_tolerance(self, run_policies=True, timedrift_tolerance=None,
        _caller="API", callback=default_callback, **kwargs):
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
    def gen_otp(self, otp_count=1, callback=default_callback, **kwargs):
        """ Generate one or more otps for this token. """
        if not self.secret:
            return callback.error("Token secret missing.")

        if otp_count > 1:
            otps = otpme.generate(secret=self.secret,
                                otp_count=otp_count,
                                otp_len=self.otp_len)
            return otps
        else:
            otp = otpme.generate(secret=self.secret,
                                otp_count=1,
                                otp_len=self.otp_len)
            return [otp]

    def test(self, password=None, callback=default_callback, **kwargs):
        """ Test if the given OTP can be verified by this token. """
        ok_message = "Token verified successful."
        error_message = "Token verification failed."
        otp_prompt = "OTP: "
        if not password:
            password = callback.askpass(otp_prompt)
        if not password:
            return callback.error("Unable to get OTP.")
        status = self.verify_otp(otp=str(password), **kwargs)
        if status:
            return callback.ok(ok_message)
        return callback.error(error_message)

    def verify(self, challenge=None, response=None, **kwargs):
        """ Call default verify method """
        if challenge and response:
            return self.verify_mschap_otp(challenge=challenge,
                                            response=response,
                                            **kwargs)
        else:
            return self.verify_otp(**kwargs)

    def verify_otp(self, otp, handle_used_otps=True,
        session_uuid=None, **kwargs):
        """ Verify OTP for this token.  """
        if handle_used_otps:
            if self.is_used_otp(otp):
                return False

        # OTPME configuration option is in minutes. OTPME timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate times to verify OTP.
        validity_times = otpme.get_validity_times(validity_time=validity_time,
                                        timedrift_tolerance=timedrift_tolerance,
                                        offset=self.offset)
        otp_epoch_time = validity_times[0]
        otp_validity_range = validity_times[1]
        otp_validity_start_time = validity_times[4]
        otp_validity_end_time = validity_times[5]

        # Log OTP timerange.
        logger.debug("Verifiying OTP within timerange: start='%s' "
                    "end='%s'."
                    % (otp_validity_start_time, otp_validity_end_time))
        # Verify OTP.
        if otpme.verify(epoch_time=otp_epoch_time,
                        validity_range=otp_validity_range,
                        secret=self.secret,
                        otp=otp, otp_len=self.otp_len):
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

    def verify_mschap_otp(self, challenge, response,
        session_uuid=None, handle_used_otps=True, **kwargs):
        """ Verify MSCHAP challenge/response against OTPs. """
        nt_key = None
        otp = None

        # OTPME configuration option is in minutes. OTPME timestep is 10 seconds.
        # So we have to multiply with 6.
        validity_time = self.validity_time * 6
        timedrift_tolerance = self.timedrift_tolerance * 6

        # Calculate times to verify OTP.
        validity_times = otpme.get_validity_times(validity_time=validity_time,
                                        timedrift_tolerance=timedrift_tolerance,
                                        offset=self.offset)
        otp_epoch_time = validity_times[0]
        otp_validity_range = validity_times[1]
        otp_validity_start_time = validity_times[4]
        otp_validity_end_time = validity_times[5]

        # Get all OTPs of this token for the given time range.
        otps = otpme.generate(epoch_time=otp_epoch_time,
                            secret=self.secret,
                            otp_count=otp_validity_range,
                            otp_len=self.otp_len)

        logger.debug("Verifiying OTP within timerange: start='%s' end='%s'."
                    % (otp_validity_start_time, otp_validity_end_time))
        # Set default return values.
        failed_return_value = False, False, False
        return_value = None, False, False
        # Walk through all valid OTPs.
        for otp in otps:
            # Get NT key from verify().
            status, \
            nt_key = mschap_util.verify(stuff.gen_nt_hash(otp),
                                        challenge, response)
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
        msg = (_("WARNING: You may have hit a BUG of Token().verify_mschap_otp()."))
        raise Exception(msg)

    @check_acls(['generate:otp'])
    def gen_mschap(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Generate MSCHAP challenge response stuff for testing. """
        if run_policies:
            try:
                self.run_policies("gen_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        otp = self.gen_otp()[0]
        return Token._gen_mschap(self,
                                password=otp,
                                callback=default_callback,
                                **kwargs)

    def add_used_otp(self, otp, session_uuid=None, quiet=True):
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
        validity_times = otpme.get_validity_times(validity_time=validity_time,
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
    def _add(self, callback=default_callback, verify_acls=True, **kwargs):
        """ Add a token. """
        # Get default HOTP settings.
        self.validity_time = self.get_config_parameter("otpme_validity_time")
        self.timedrift_tolerance = self.get_config_parameter("otpme_timedrift_tolerance")

        self.secret = stuff.gen_secret(self.secret_len)
        # FIXME: We should gen a deploy PIN that can be used to set the token
        #        secret one time.
        pin_len = self.get_config_parameter("otpme_default_pin_len")
        self.deploy_pin = stuff.gen_pin(pin_len)
        # Generate salt for used OTP hashes.
        self.used_otp_salt = stuff.gen_secret(32)
        return_message = None
        show_deploy_pin = True
        if verify_acls:
            if not self.verify_acl("view:pin"):
                show_deploy_pin = False
        if show_deploy_pin:
            return_message = "Deploy PIN: %s" % self.deploy_pin
        return callback.ok(return_message)

    def show_config(self, callback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:offset"):
            lines.append('OFFSET="%s"' % self.offset)
        else:
            lines.append('OFFSET=""')

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
