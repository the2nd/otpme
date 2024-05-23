# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
#from pyotp.totp import TOTP
from datetime import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import qrcode
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.otp.oath import totp
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import decode
from otpme.lib.token.oath.oath import OathToken
from otpme.lib.third_party.oath_toolkit import uri
from otpme.lib.token.oath.oath import OATH_OTP_FORMATS
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
                            "otp_format",
                            "mode",
                            "period",
                            "forward_drift",
                            "backward_drift",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
            }

write_value_acls = {
                "generate"  : [
                            "otp",
                            "qrcode",
                            ],
                "edit"      : [
                            "secret",
                            "pin",
                            "auth_script",
                            "otp_format",
                            "mode",
                            "period",
                            "forward_drift",
                            "backward_drift",
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
    'pin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_pin',
                    'oargs'             : ['auto_pin', 'pin'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_pin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_pin',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_pin'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_pin',
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
    'gen_qrcode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'gen_qrcode',
                    'oargs'             : ['qrcode_file'],
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
    'otp_format'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_otp_format',
                    'args'              : ['otp_format'],
                    'job_type'          : 'process',
                    },
                },
            },
    'mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_mode',
                    'args'              : ['new_mode'],
                    'job_type'          : 'process',
                    },
                },
            },
    'check_period'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_period',
                    'oargs'             : ['period'],
                    'job_type'          : 'process',
                    },
                },
            },
    'backward_drift'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_backward_drift',
                    'job_type'          : 'process',
                    },
                },
            },
    'forward_drift'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_forward_drift',
                    'oargs'             : ['forward_drift'],
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
                    sub_type="totp",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "gen_qrcode")
    config.register_auth_on_action_hook("token", "change_mode")
    config.register_auth_on_action_hook("token", "show_secret")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "totp")

def register_config_params():
    """ Register config params. """
    # Object types our config paramters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                ]
    # Default TOTP OTP format.
    config.register_config_parameter(name="totp_format",
                                    ctype=str,
                                    default_value="dec6",
                                    valid_values=list(OATH_OTP_FORMATS),
                                    object_types=object_types)
    # TOTP check period.
    config.register_config_parameter(name="totp_period",
                                    ctype=int,
                                    default_value=30,
                                    object_types=object_types)
    # Default TOTP PIN length.
    config.register_config_parameter(name="totp_default_pin_len",
                                    ctype=int,
                                    default_value=4,
                                    object_types=object_types)
    # TOTP forward drift tolerance.
    config.register_config_parameter(name="totp_forward_drift",
                                    ctype=int,
                                    default_value=1,
                                    object_types=object_types)
    # TOTP backward drift tolerance.
    config.register_config_parameter(name="totp_backward_drift",
                                    ctype=int,
                                    default_value=1,
                                    object_types=object_types)
    # The TOTP secret length.
    config.register_config_parameter(name="totp_secret_len",
                                    ctype=int,
                                    default_value=10,
                                    object_types=object_types)

class TotpToken(OathToken):
    """ Class for OATH TOTP tokens. """
    def __init__(self, object_id=None, user=None, name=None,
        realm=None, site=None, path=None, **kwargs):
        # Call parent class init.
        super(TotpToken, self).__init__(object_id=object_id,
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
        # Set default values.
        self.token_type = "totp"
        self.pass_type = "otp"
        self.otp_type = "time"

        self.otp_format = None
        self.need_password = True
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False

        # TOTP specific settings
        # FIXME: make this per token config setting!
        self.drift = 0
        self.period = None
        self.forward_drift = None
        self.backward_drift = None
        # Token ACLs to add to new token via tokenacls policy.
        self.token_acls = [
                            'generate:otp',
                            'generate:qrcode',
                        ]
        self.user_acls = []
        self.creator_acls = []

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'PIN'                       : {
                                            'var_name'      : 'pin',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'PIN_ENABLED'               : {
                                            'var_name'      : 'pin_enabled',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'PIN_LEN'                   : {
                                            'var_name'      : 'pin_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'SERVER_SECRET'             : {
                                            'var_name'      : 'server_secret',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'OTP_FORMAT'                : {
                                            'var_name'      : 'otp_format',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'PERIOD'                    : {
                                            'var_name'      : 'period',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'FORWARD_DRIFT'             : {
                                            'var_name'      : 'forward_drift',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'BACKWARD_DRIFT'             : {
                                            'var_name'      : 'backward_drift',
                                            'type'          : int,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return super(TotpToken, self)._get_object_config(token_config=token_config)

    def set_variables(self):
        """ Set instance variables """
        # Run parent class method that may override default values with those
        # read from config.
        super(TotpToken, self).set_variables()
        # In mode2 the PIN is mandatory.
        if self.mode == "mode2":
            self.pin_enabled = True
            self.pin_mandatory = True
        else:
            self.pin_mandatory = False

    @property
    def secret_len(self):
        """ Get token secret length. """
        secret_len = self.get_config_parameter("totp_secret_len")
        return secret_len

    @check_acls(['edit:period'])
    @object_lock()
    @backend.transaction
    def change_period(self, run_policies=True, period=None,
        _caller="API", callback=default_callback, **kwargs):
        """ Change token check period. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_check_period",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if period is None:
            while True:
                answer = callback.ask("Check period: ")
                try:
                    period = int(answer)
                    break
                except:
                    pass

        self.period = period

        return self._cache(callback=callback)

    @check_acls(['edit:backward_drift'])
    @object_lock()
    @backend.transaction
    def change_backward_drift(self, run_policies=True, backward_drift=None,
        _caller="API", callback=default_callback, **kwargs):
        """ Change token check backward_drift. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_check_period",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if backward_drift is None:
            while True:
                answer = callback.ask("Backward drift: ")
                try:
                    backward_drift = int(answer)
                    break
                except:
                    pass

        self.backward_drift = backward_drift

        return self._cache(callback=callback)

    @check_acls(['edit:forward_drift'])
    @object_lock()
    @backend.transaction
    def change_forward_drift(self, run_policies=True, forward_drift=None,
        _caller="API", callback=default_callback, **kwargs):
        """ Change token check forward_drift. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_check_period",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if forward_drift is None:
            while True:
                answer = callback.ask("Forward drift: ")
                try:
                    forward_drift = int(answer)
                    break
                except:
                    pass

        self.forward_drift = forward_drift

        return self._cache(callback=callback)

    @check_acls(['generate:otp'])
    def gen_otp(self, otp_count=1, secret=None, prefix_pin=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Generate one or more OTPs for this token. """
        if not secret:
            if self.mode == "mode1":
                secret = self.get_secret(callback=callback)
            if self.mode == "mode2":
                pin = callback.askpass("Please enter PIN: ")
                if len(pin) != self.pin_len:
                    msg = "Invalid PIN."
                    return callback.error(msg)
                secret = self.get_secret(pin=pin, callback=callback)

        if not secret:
            callback.error("Unable to get token secret.")

        epoch_time = time.time()
        if otp_count > 1:
            otps = []
            for i in range(0, otp_count):
                otp = totp.generate_totp(epoch_time=epoch_time,
                                        secret=secret,
                                        period=self.period,
                                        format=self.otp_format)
                if prefix_pin:
                    otp = "%s%s" % (prefix_pin, otp)
                otps.append(otp)
                epoch_time = epoch_time + (i * self.period)
            if _caller == "CLIENT":
                return callback.ok(otps)
            return otps
        otp = totp.generate_totp(epoch_time=epoch_time,
                                secret=secret,
                                period=self.period,
                                format=self.otp_format)
        if prefix_pin:
            otp = "%s%s" % (prefix_pin, otp)
        if _caller == "CLIENT":
            return callback.ok(otp)
        return [otp]

    def verify_otp(self, otp, secret=None, handle_used_otps=True,
        mode=None, otp_includes_pin=True, verify_pin=True, sft=None,
        recursive_use=False, session_uuid=None, **kwargs):
        """ Verify OTP for this token.  """
        # Make sure OTP is str().
        otp = str(otp)

        if handle_used_otps:
            if self.is_used_otp(otp):
                return False

        pin = None

        # Mode indicates for which mode we have to verify the OTP (e.g. if
        # the OTP includes the PIN)
        if not mode:
            mode = self.mode

        # If PIN is disabled OTP does not include a PIN we could verify.
        if mode == "mode1":
            if not self.pin_enabled:
                verify_pin = False
                # We decide on token mode if OTP includes a PIN because we
                # allow to "emulate" the given token mode (e.g. use in
                # change_mode())
                otp_includes_pin = False
        # In mode2 no PIN verification can be done as the PIN is not
        # saved on server side.
        if mode == "mode2":
            verify_pin = False

        # Get PIN from OTP if needed.
        if otp_includes_pin:
            if len(otp) < (int(self.pin_len) + int(self.otp_len)):
                logger.debug("Token PIN enabled but the given OTP is too short "
                            "to include a PIN!")
                return None
            _otp = otp[self.pin_len:]
            pin = otp[:self.pin_len]
        else:
            _otp = otp

        # Calculate epoch time to verify OTP.
        epoch_time = time.time()

        # Calculate times for log entry.
        otp_validity_range_start_timestamp = float(epoch_time - (self.period * self.backward_drift))
        otp_validity_range_start_timestamp = float(str(otp_validity_range_start_timestamp)[:-2])
        otp_validity_range_end_timestamp = float(epoch_time + (self.period + self.forward_drift))
        otp_validity_range_end_timestamp = float(str(otp_validity_range_end_timestamp)[:-2])
        otp_validity_start_time = str(datetime.fromtimestamp(otp_validity_range_start_timestamp))
        otp_validity_end_time = str(datetime.fromtimestamp(otp_validity_range_end_timestamp))

        # Tokens do not include a PIN in offline config we could verify here.
        # The PIN is verified in different ways:
        # - in mode1 by using it to en-/decrypt the token config.
        # - in mode2 the token secret is derived from server_secret+PIN and
        #   thus OTP verification fails with the wrong PIN.
        # We also have no PIN lenght in our config to make brute force
        # attacks harder and thus we have to try all possible PIN lenghts.
        # The increased load should not be noticeable and outweigh the added
        # security.
        if self.offline and self.pin_enabled:
            verify_pin = False
            if not sft and not recursive_use:
                org_pin_len = self.pin_len
                self.pin_len = 0
                while True:
                    if self.pin_len >= (len(otp) - self.otp_len):
                        self.pin_len = org_pin_len
                        return None
                    self.pin_len += 1
                    status = self.verify_otp(otp,
                                            secret=secret,
                                            handle_used_otps=handle_used_otps,
                                            mode=mode,
                                            otp_includes_pin=otp_includes_pin,
                                            verify_pin=False,
                                            recursive_use=True,
                                            **kwargs)
                    if status:
                        self.pin_len = org_pin_len
                        return status

        # If we got a secret this request is to verify the secret itself
        # (e.g. mode change).
        if not secret:
            # Get token secret.
            secret = self.get_secret(pin=pin)

        # Log OTP time range.
        logger.debug("Verifiying OTP within timerange: start='%s' end='%s'."
                    % (otp_validity_start_time, otp_validity_end_time))
        # Verify OTP.
        # FIXME: check if token drift needs update here?
        totp_status, \
        totp_drift = totp.verify_totp(epoch_time,
                                    secret=secret,
                                    period=self.period,
                                    otp=_otp,
                                    format=self.otp_format,
                                    backward_drift=self.backward_drift,
                                    forward_drift=self.forward_drift,
                                    drift=self.drift)
        if totp_status:
            # Verify PIN.
            if verify_pin:
                if pin != self.pin:
                    logger.debug("Got wrong token PIN: %s" % self.rel_path)
                    # FIXME: A wrong PIN is not definitively a failed login
                    #        with this token because it may be used as a
                    #        second factor token (e.g. a password token)
                    #        where a static password is prefixed and the PIN
                    #        verification is disabled. It would be nice to
                    #        prevent brute forcing the PIN with a stolen OTP
                    #        here but for this we need to change the concept
                    #        of add_used_otp() here and in User().authenticate()
                    return None
            if handle_used_otps:
                # Only log message for the first OTP we add.
                self.add_used_otp(otp=otp,
                                session_uuid=session_uuid,
                                quiet=False)
                if otp_includes_pin:
                    self.add_used_otp(otp=_otp, session_uuid=session_uuid)
            return otp

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return None

        # This point should never be reached.
        msg = (_("WARNING: You may have hit a BUG of Token().verify_otp()."))
        raise Exception(msg)

    def verify_mschap_otp(self, challenge, response,
        handle_used_otps=True, session_uuid=None, **kwargs):
        """ Verify MSCHAP challenge/response against OTPs. """
        from otpme.lib import mschap_util
        nt_key = None
        otp = None
        _otp = None

        # Set default return values.
        failed_return_value = False, False, False
        return_value = None, False, False

        # Cannot verify token in mode2.
        if self.mode == "mode2":
            return return_value

        pin = None
        if self.pin_enabled:
            pin = self.pin

        # Calculate epoch time to verify OTP.
        epoch_time = time.time()

        # Calculate times for log entry.
        otp_validity_range_start_timestamp = float(epoch_time - (self.period * self.backward_drift))
        otp_validity_range_start_timestamp = float(str(otp_validity_range_start_timestamp)[:-2])
        otp_validity_range_end_timestamp = float(epoch_time + (self.period + self.forward_drift))
        otp_validity_range_end_timestamp = float(str(otp_validity_range_end_timestamp)[:-2])
        otp_validity_start_time = str(datetime.fromtimestamp(otp_validity_range_start_timestamp))
        otp_validity_end_time = str(datetime.fromtimestamp(otp_validity_range_end_timestamp))

        # xxxxxxxxxxxxxxxxxxxxx
        # FIXME: we also need OTPs from self.backward_drift here!
        # Get list with valid OTPs of this token.
        otps = self.gen_otp(otp_count=self.forward_drift + 1,
                            prefix_pin=pin,
                            verify_acls=False)

        logger.debug("Verifiying OTP within timerange: start='%s' end='%s'."
                    % (otp_validity_start_time, otp_validity_end_time))
        # Walk through all valid OTPs.
        for _otp in otps:
            # Get NT key from verify().
            status, nt_key = mschap_util.verify(stuff.gen_nt_hash(_otp),
                                                challenge, response)
            if status:
                if handle_used_otps:
                    if self.is_used_otp(_otp):
                        return failed_return_value
                    self.add_used_otp(otp=_otp,
                                    session_uuid=session_uuid,
                                    quiet=False)
                    if self.pin_enabled:
                        otp = _otp[self.pin_len:]
                        self.add_used_otp(otp=otp, session_uuid=session_uuid)
                return status, nt_key, _otp

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return return_value

        # This point should never be reached.
        msg = ("WARNING: You may have hit a BUG of Token().verify_mschap_otp().")
        raise Exception(msg)

    @check_acls(['generate:qrcode'])
    def gen_qrcode(self, pin=None, qrcode_file=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Generate QRCode to deploy token secret. """
        if run_policies:
            try:
                self.run_policies("gen_qrcode",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if pin is None:
            if self.mode == "mode2":
                pin = callback.askpass("Please enter PIN: ")
                if len(pin) != self.pin_len:
                    msg = "Invalid PIN."
                    return callback.error(msg)

        # Get secret to gen QRCode.
        secret = self.get_secret(pin=pin)
        secret = decode(secret, "base32")
        secret = secret.encode()

        # Gen OATH URI.
        user_string = "%s@%s" % (self.rel_path, self.realm)
        #oath_uri = TOTP(secret)
        #oath_uri = oath_uri.provisioning_uri(name=user_string,
        #                                    issuer_name=config.my_name)
        # Use oath-toolkit.
        oath_uri = uri.generate(key_type=self.token_type,
                                key=secret,
                                user=user_string,
                                issuer=config.my_name,
                                counter=None)

        # Generate QRcode.
        _qrcode = qrcode.gen_qrcode(oath_uri, "terminal")

        # xxxxxxxxxxxxx
        # FIXME: how to create png/svg image without writing to file?
        return callback.ok(_qrcode)

    def add_used_otp(self, otp, session_uuid=None, quiet=True):
        """ Add used OTP for this user/token. """
        # In offline mode we do not add used OTPs to make brute force attacks
        # harder (no OTP hash saved to disk).
        if self.offline:
            return True
        # Cache TOTPs twice the time they are valid.
        expiry = time.time() + (self.period * self.forward_drift * 2)
        # Add used OTP using parent class method.
        self._add_used_otp(otp, expiry,
                        session_uuid=session_uuid,
                        quiet=quiet)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, *args, **kwargs):
        """ Add a token. """
        # Get default TOTP settings.
        self.otp_format = self.get_config_parameter("totp_format")
        self.period = self.get_config_parameter("totp_period")
        self.forward_drift = self.get_config_parameter("totp_forward_drift")
        self.backward_drift = self.get_config_parameter("totp_backward_drift")
        return super(TotpToken, self)._add(*args, **kwargs)

    def show_config(self, callback=default_callback, **kwargs):
        """ Show token info. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []

        period = ""
        if self.verify_acl("view:period") \
        or self.verify_acl("edit:period"):
            period = str(self.period)
        lines.append('PERIOD="%s"' % period)

        backward_drift = ""
        if self.verify_acl("view:backward_drift") \
        or self.verify_acl("edit:backward_drift"):
            backward_drift = str(self.backward_drift)
        lines.append('BACKWARD_DRIFT="%s"' % backward_drift)

        forward_drift = ""
        if self.verify_acl("view:forward_drift") \
        or self.verify_acl("edit:forward_drift"):
            forward_drift = str(self.forward_drift)
        lines.append('FORWARD_DRIFT="%s"' % forward_drift)

        server_secret = ""
        if self.verify_acl("view:server_secret"):
            server_secret = str(self.server_secret)
        lines.append('SERVER_SECRET="%s"' % server_secret)

        return super(TotpToken, self).show_config(config_lines=lines,
                                                callback=callback,
                                                **kwargs)

    def show(self, **kwargs):
        """ Show token details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
