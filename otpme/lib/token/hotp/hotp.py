# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from typing import Union
from pyotp.hotp import HOTP

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import qrcode
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.otp.oath import hotp
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.token.oath.oath import OathToken
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
                "resync",
        ]

read_value_acls = {
                "view"      : [
                            "secret",
                            "server_secret",
                            "pin",
                            "auth_script",
                            "counter_check_range",
                            "mode",
                            "counter_sync_time",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            "token_counter",
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
                            "counter_check_range",
                            "mode",
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
    'resync'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'resync',
                    'oargs'             : ['otp'],
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
    'mode'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_mode',
                    'args'              : ['new_mode'],
                    'job_type'          : 'process',
                    },
                },
            },
    'counter_check_range'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_counter_check_range',
                    'oargs'             : ['counter_check_range'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_token_counter'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_token_counter',
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
    register_config_params()
    register_commands("token",
                    commands,
                    sub_type="hotp",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "resync")
    config.register_auth_on_action_hook("token", "gen_mschap")
    config.register_auth_on_action_hook("token", "gen_qrcode")
    config.register_auth_on_action_hook("token", "change_mode")
    config.register_auth_on_action_hook("token", "show_secret")
    config.register_auth_on_action_hook("token", "change_counter_check_range")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "hotp")

def register_config_params():
    """ Register config params. """
    # Valid object types for our config parameters..
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                ]
    # Counter check range when doing HOTP auth.
    config.register_config_parameter(name="hotp_check_range",
                                    ctype=int,
                                    default_value=32,
                                    object_types=object_types)
    # Counter check range when doing token resync.
    config.register_config_parameter(name="hotp_resync_check_range",
                                    ctype=int,
                                    default_value=1024,
                                    object_types=object_types)
    # The HOTP default PIN length.
    config.register_config_parameter(name="hotp_default_pin_len",
                                    ctype=int,
                                    default_value=4,
                                    object_types=object_types)
    # The HOTP secret length.
    config.register_config_parameter(name="hotp_secret_len",
                                    ctype=int,
                                    default_value=10,
                                    object_types=object_types)

@match_class_typing
class HotpToken(OathToken):
    """ Class for OATH HOTP tokens. """
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
        super(HotpToken, self).__init__(object_id=object_id,
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
        self.token_type = "hotp"
        self.pass_type = "otp"
        self.otp_type = "counter"
        self.secret_len = None

        self.need_password = True
        self.auth_script_enabled = False
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False

        # HOTP specific settings.
        self.counter_check_range = None
        self.counter_sync_time = 1.0
        self.sync_offline_token_counter = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'yubikey_hotp' ]
        # This dict is filled with used OTP(s) and its counters and read by
        # self.add_used_otp() to get the token counter that needs to be saved.
        self.otp_cache = {}
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

            'COUNTER'                   : {
                                            'var_name'      : 'get_token_counter',
                                            'type'          : int,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'COUNTER_SYNC_TIME'         : {
                                            'var_name'      : 'counter_sync_time',
                                            'type'          : float,
                                            'force_type'    : True,
                                            'required'      : False,
                                        },

            'COUNTER_CHECK_RANGE'       : {
                                            'var_name'      : 'counter_check_range',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'SECRET_LEN'                : {
                                            'var_name'      : 'secret_len',
                                            'type'          : int,
                                            'required'      : False,
                                        },

            'SECRET_ENCODING'           : {
                                            'var_name'      : 'secret_encoding',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return super(HotpToken, self)._get_object_config(token_config=token_config)

    def set_variables(self):
        """ Set instance variables """
        # Run parent class method that may override default values with those
        # read from config.
        super(HotpToken, self).set_variables()
        # In mode2 the PIN is mandatory.
        if self.mode == "mode2":
            self.pin_enabled = True
            self.pin_mandatory = True
        else:
            self.pin_mandatory = False

    @property
    def default_pin_len(self):
        default_pin_len = self.get_config_parameter("hotp_default_pin_len")
        return default_pin_len

    def update_otp_cache(self, otp: str, counter: int):
        """ Add OTP + counter to OTP cache. """
        self.otp_cache[otp] = counter

    def get_counter_range(self):
        """ Get start/stop counter for this token. """
        start = self.get_token_counter() + 1
        end = start + self.counter_check_range
        return start, end

    @check_acls(['view:token_counter'])
    def show_token_counter(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        token_counter = self.get_token_counter()
        return callback.ok(token_counter)

    def get_offline_data(self):
        offline_data = {}
        if self.mode == "mode1":
            offline_data['secret'] = self.secret
        if self.mode == "mode2":
            offline_data['server_secret'] = self.server_secret
        return offline_data

    @check_acls(['generate:otp'])
    def gen_otp(
        self,
        secret: Union[str,None]=None,
        prefix_pin: str=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """
        Generate one or more OTPs for this token within the valid counter range.
        """
        if not secret:
            if self.mode == "mode1":
                secret = self.get_secret(encoding="base32", callback=callback)
            if self.mode == "mode2":
                pin = callback.askpass("Please enter PIN: ")
                if len(pin) != self.pin_len:
                    msg = "Invalid PIN."
                    return callback.error(msg)
                secret = self.get_secret(encoding="base32",
                                        pin=pin,
                                        callback=callback)

        if not secret:
            return callback.error("Unable to get token secret.")

        token_counter_start, token_counter_end = self.get_counter_range()
        token_counter = token_counter_start + 1
        otp = hotp.generate_hotp(token_counter, secret)
        if prefix_pin:
            otp = "%s%s" % (prefix_pin, otp)
        self.update_otp_cache(otp, token_counter)
        if _caller == "CLIENT":
            return callback.ok(otp)
        return otp

    def verify_otp(
        self,
        otp: str,
        secret: Union[str,None]=None,
        handle_used_otps: bool=True,
        mode: str=None,
        otp_includes_pin: bool=True,
        verify_pin: bool=True,
        sft: Union[bool,None]=None,
        recursive_use: bool=False,
        session_uuid: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify OTP for this token. """
        pin = None

        if handle_used_otps:
            if self.is_used_otp(otp):
                return False

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

        # Get token counter check range.
        token_counter_start, token_counter_end = self.get_counter_range()

        # Tokens do not include a PIN in offline config we could verify here.
        # The PIN is verified in different ways:
        # - in mode1 by using it to en-/decrypt the token config.
        # - in mode2 the token secret is derived from server_secret+PIN and
        #   thus OTP verification fails with the wrong PIN.
        # If not used as second factor token we also have no PIN length in
        # our config to make brute force attacks harder and thus we have to
        # try all possible PIN lengths. The increased load should not be
        # noticeable and outweigh the added security.
        if self.offline and self.pin_enabled:
            verify_pin = False
            if not sft and not recursive_use:
                org_pin_len = self.pin_len
                self.pin_len = 2
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
                                            sft=None,
                                            recursive_use=True,
                                            **kwargs)
                    if status:
                        self.pin_len = org_pin_len
                        return status

        # Get PIN from OTP if needed.
        if otp_includes_pin:
            if len(otp) < (int(self.pin_len) + int(self.otp_len)):
                msg = ("Token PIN enabled but the given OTP is too "
                        "short to include a PIN!")
                logger.debug(msg)
                return None
            _otp = otp[self.pin_len:]
            try:
                pin = otp[:self.pin_len]
            except ValueError:
                msg = "OTP does not include a PIN."
                logger.info(msg)
                return None
        else:
            _otp = otp

        # If we got a secret this request is to verify the secret itself
        # (e.g. mode change)
        if not secret:
            # Get token secret.
            secret = self.get_secret(pin=pin, encoding="base32")

        # Log token counter range.
        msg = ("Verifiying OTP within counter range: start='%s' end='%s'."
                % (token_counter_start, token_counter_end))
        logger.debug(msg)

        # Verify OTP.
        hotp_status, \
        hotp_count = hotp.verify_hotp(counter_start=token_counter_start,
                                    counter_end=token_counter_end,
                                    secret=secret, otp=_otp)
        if hotp_status:
            self.update_otp_cache(otp, hotp_count)
            if otp_includes_pin:
                self.update_otp_cache(_otp, hotp_count)
            # Make sure the OTP was not already used (counter must be higher
            # than the one from the last used OTP).
            token_counter = self.get_token_counter()
            if hotp_count > token_counter:
                # Verify PIN.
                if verify_pin:
                    # FIXME: A wrong PIN is not definitively a failed login
                    #        with this token because it may be used as a
                    #        second factor token (e.g. a password token)
                    #        where a static password is prefixed and the PIN
                    #        verification is disabled. It would be nice to
                    #        prevent brute forcing the PIN with a stolen OTP
                    #        here but for this we need to change the concept
                    #        of add_used_otp() here and in User().authenticate()
                    if pin != self.pin:
                        logger.debug("Got wrong token PIN: %s" % self.rel_path)
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

    def verify_mschap_otp(
        self,
        challenge: str,
        response: str,
        session_uuid: Union[str,None]=None,
        handle_used_otps: bool=True,
        **kwargs,
        ):
        """ Verify MSCHAP challenge/response against OTPs """
        from otpme.lib import mschap_util

        nt_key = None
        otp = None
        _otp = None
        # Set default return values.
        return_value = None, None, None
        failed_return_value = False, None, None

        # Cannot verify token in mode2.
        if self.mode == "mode2":
            return return_value

        pin = None
        if self.pin_enabled:
            pin = self.pin

        # Get token counter check range.
        token_counter_start, token_counter_end = self.get_counter_range()

        # Get list with valid OTPs of this token for the given counter range.
        otps = self.gen_otp(otp_count=self.counter_check_range,
                            prefix_pin=pin,
                            verify_acls=False)

        msg = ("Verifiying OTP within counter range: start='%s' end='%s'."
                % (token_counter_start, token_counter_end))
        logger.debug(msg)

        # Get secret.
        secret = self.get_secret(pin=pin, encoding="base32")

        # Walk through all valid OTPs.
        for _otp in otps:
            # Get NT key from verify().
            status, \
            nt_key = mschap_util.verify(stuff.gen_nt_hash(_otp),
                                        challenge, response)
            if status:
                if self.pin_enabled:
                    otp = _otp[self.pin_len:]
                    check_otp = otp
                else:
                    check_otp = _otp

                # Verify OTP.
                hotp_status, \
                hotp_count = hotp.verify_hotp(counter_start=token_counter_start,
                                            counter_end=token_counter_end,
                                            secret=secret, otp=check_otp)

                if hotp_status:
                    # Make sure the OTP was not already used (counter must be higher
                    # than the one from the last used OTP).
                    if hotp_count > self.get_token_counter():
                        if handle_used_otps:
                            if self.is_used_otp(_otp):
                                return failed_return_value
                            # Add OTP to used OTPs.
                            self.update_otp_cache(_otp, hotp_count)
                            self.add_used_otp(otp=_otp,
                                session_uuid=session_uuid)
                            # Add OTP without PIN to used OTPs.
                            if otp:
                                self.update_otp_cache(otp, hotp_count)
                                self.add_used_otp(otp=otp,
                                                session_uuid=session_uuid,
                                                quiet=False)
                        return status, nt_key, _otp

        # Default should be None (which means no valid OTP found but not
        # definitively failed because we havent found an already used OTP)
        return return_value

        # This point should never be reached.
        msg = ("WARNING: You may have hit a BUG of Token().verify_mschap_otp().")
        raise Exception(msg)

    @check_acls(['generate:qrcode'])
    def gen_qrcode(
        self,
        pin: Union[str,None]=None,
        qrcode_file: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Generate QRCode for token deployment. """
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
        secret = self.get_secret(pin=pin, encoding="base32")

        token_counter_start, token_counter_end = self.get_counter_range()

        # Gen OATH URI.
        user_string = "%s@%s" % (self.rel_path, self.realm)
        oath_uri = HOTP(secret)
        oath_uri = oath_uri.provisioning_uri(name=user_string,
                                            issuer_name=config.my_name,
                                            initial_count=token_counter_start)
        # Generate QRcode.
        _qrcode = qrcode.gen_qrcode(oath_uri, "terminal")
        # xxxxxxxxxxxxx
        # FIXME: How to create png/svg image without writing to file?
        return callback.ok(_qrcode)

    @check_acls(['resync'])
    @object_lock(full_lock=True)
    @backend.transaction
    def resync(
        self,
        otp: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Resync our counter state with token by given OTP. """
        from otpme.lib.otp.oath import hotp
        if not otp:
            otp = callback.askpass("Please enter OTP: ")

        if not otp:
            return callback.error("Unable to get OTP.")

        # Make sure OTP is str().
        otp = str(otp)

        if len(otp) < self.otp_len:
            return callback.error("OTP too short.")
        if len(otp) > self.otp_len:
            return callback.error("OTP too long.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("resync",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        pin = None
        if self.mode == "mode2":
            pin = callback.askpass("Please enter PIN: ")
            if len(pin) != self.pin_len:
                msg = "Invalid PIN."
                return callback.error(msg)

        # Get token secret.
        token_secret = self.get_secret(encoding="base32",
                                        pin=pin,
                                        callback=callback)

        # Get current token counter.
        current_counter = self.get_token_counter()

        # Get resync check range.
        resync_check_range = self.get_config_parameter("hotp_resync_check_range")

        # We will check resync_check_range below and above the current counter.
        token_counter_start = 0
        if current_counter >= resync_check_range:
            token_counter_start = current_counter - resync_check_range
        token_counter_end = current_counter + resync_check_range

        hotp_status, \
        hotp_count = hotp.verify_hotp(counter_start=token_counter_start,
                                        counter_end=token_counter_end,
                                        secret=token_secret,
                                        otp=otp)
        if not hotp_status:
            return callback.error("Unable to synchronize token.")

        # Add OTP with counter to our cache.
        self.update_otp_cache(otp, hotp_count)
        # Set new sync timestamp.
        self.counter_sync_time = time.time()

        try:
            self.add_used_otp(otp, resync=True)
        except Exception as e:
            msg = "Error adding OTP to list of used OTPs: %s" % e
            return callback.error(msg)

        if self.allow_offline:
            msg = (_("Offline usage enabled for token. You "
                    "should re-login after token resync!"))
            callback.send(msg)

        msg = (_("Token synchronized successful. Current counter: %s")
                % hotp_count)
        callback.send(msg)

        return self._cache(callback=callback)

    def add_used_otp(
        self,
        otp: str,
        resync: bool=False,
        session_uuid: Union[str,None]=None,
        quiet: bool=True,
        ):
        """ Add used OTP + counter for this user/token. """
        try:
            token_counter = self.otp_cache[otp]
        except:
            msg = ("WARNING: Unable to find counter for the given OTP.")
            raise OTPmeException(msg)

        # Update counter in token config on resync.
        if resync:
            self.object_config['COUNTER'] = token_counter
            # Remove old token counter objects on resync.
            counter_list = self._get_token_counter()
            for x in counter_list:
                x.delete()

        # Add used token counter using parent class method.
        self._add_token_counter(token_counter=token_counter,
                                session_uuid=session_uuid)

        # FIXME: how long to cache already used HOTPs?
        expiry = time.time() + 86400

        # In offline mode we do not add used OTPs to make brute force attacks
        # harder (no OTP hash saved to disk)
        if self.offline:
            return True

        # Add used OTP using parent class method
        try:
            self._add_used_otp(otp=otp,
                            expiry=expiry,
                            session_uuid=session_uuid,
                            sync_time=self.counter_sync_time,
                            quiet=quiet)
        except Exception as e:
            msg = "Failed to add used OTP: %s" % e
            raise OTPmeException(msg)

    def _check_range_format(
        self,
        check_range: int,
        callback: JobCallback=default_callback,
        ):
        """ Check if the given counter range is valid. """
        if not isinstance(check_range, int):
            msg = "Counter check range must be an integer."
            return callback.error(msg)
        if check_range > 0:
            return callback.ok()
        msg = (_("Counter check range must be greater than 0."))
        return callback.error(msg)

    @check_acls(['edit:counter_check_range'])
    @object_lock()
    @backend.transaction
    def change_counter_check_range(
        self,
        run_policies: bool=True,
        counter_check_range: Union[int,None]=None,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change token counter check range. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_counter_check_range",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if counter_check_range is None:
            while True:
                answer = callback.ask("Counter check range: ")
                try:
                    counter_check_range = int(answer)
                except:
                    pass
                check_status, \
                check_message = self._check_range_format(counter_check_range)
                if check_status:
                    break
                else:
                    callback.send(check_message)
        else:
            check_status, \
            check_message = self._check_range_format(counter_check_range)
            if not check_status:
                return callback.error(check_message)

        self.counter_check_range = counter_check_range

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def deploy(
        self,
        server_secret: str,
        secret_len: int,
        pin: str,
        secret_encoding: str,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy HOTP token """
        if not self.check_pin(pin=pin, callback=callback):
            return callback.error("Invalid PIN.")

        msg = (_("Setting received server secret to token: %s") % self.rel_path)
        callback.send(msg)

        self.mode = "mode2"
        self.secret = None
        self.server_secret = server_secret
        self.secret_len = secret_len
        self.secret_encoding = secret_encoding

        if verbose_level > 0:
            token_secret = self.get_secret(encoding="base32", pin=pin)
            msg = (_("Token secret: %s") % token_secret)
            callback.send(msg)

        msg = ("You have to resync the token after re-deploying.")
        callback.send(msg)

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, *args, **kwargs):
        """ Add a token. """
        # Get default TOTP settings.
        self.secret_len = self.get_config_parameter("hotp_secret_len")
        self.counter_check_range = self.get_config_parameter("hotp_check_range")
        return super(HotpToken, self)._add(*args, **kwargs)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token info. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []

        counter_check_range = ""
        if self.verify_acl("view:counter_check_range") \
        or self.verify_acl("edit:counter_check_range"):
            counter_check_range = str(self.counter_check_range)
        lines.append('COUNTER_CHECK_RANGE="%s"' % counter_check_range)

        counter_sync_time = ""
        if self.verify_acl("view:counter_sync_time") \
        or self.verify_acl("resync"):
            counter_sync_time = str(self.counter_sync_time)
        lines.append('COUNTER_SYNC_TIME="%s"' % counter_sync_time)

        server_secret = ""
        if self.verify_acl("view:server_secret"):
            server_secret = str(self.server_secret)
        lines.append('SERVER_SECRET="%s"' % server_secret)

        return super(HotpToken, self).show_config(config_lines=lines,
                                                callback=callback,
                                                **kwargs)

    def show(self, **kwargs):
        """ Show token details """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
