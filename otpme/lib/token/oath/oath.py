# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import pyotp
import base64
import hashlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

# OATH OTP formats and the resulting OTP lens.
OATH_OTP_FORMATS = {
        'dec4'          : 4,
        'dec6'          : 6,
        'dec7'          : 7,
        'dec8'          : 8,
        'hex'           : 4,
        'hex-notrunc'   : 4,
        }

class OathToken(Token):
    """ Base class for OATH tokens. """
    def __init__(self, *args, **kwargs):
        # Call parent class init.
        self.valid_otp_formats = OATH_OTP_FORMATS
        self.pin = None
        self.pin_len = None
        self.pin_enabled = True
        self.valid_modes = [ 'mode1', 'mode2' ]
        self.pin_mandatory = True
        self.secret = None
        self.server_secret = None
        self.supports_qrcode = True
        super(OathToken, self).__init__(*args, **kwargs)
        # Default token mode should be mode2 which is more secure for offline
        # usage. This value must be initialized after super().
        self.mode = "mode2"

    @property
    def otp_len(self):
        """ Set OTP len depending on the configured OTP format. """
        try:
            otp_len = OATH_OTP_FORMATS[self.otp_format]
        except:
            otp_len = 6
        return otp_len

    def get_offline_config(self, second_factor_usage=False):
        """ Get offline config of token. (e.g. without PIN). """
        # Make sure our object config is up-to-date.
        self.update_object_config()
        # Get a copy of our object config.
        offline_config = self.object_config.copy()
        # In offline mode we never need the PIN.
        offline_config['PIN'] = ''

        need_encryption = True
        if self.mode == "mode1":
            # In mode1 we do not need the server secret in offline config.
            offline_config['SERVER_SECRET'] = ''
            if not self.pin_enabled:
                need_encryption = False

        if self.mode == "mode2":
            # In mode2 there should be no HOTP secret so make sure we empty it.
            offline_config['SECRET'] = ''
            # In mode2 the token config includes only the server secret which is
            # used in conjunction with the PIN to generate the HOTP secret. In
            # offline mode the token config will include neither, not the PIN
            # and not the HOTP secret. Thus its relatively save to store it
            # unencrypted. Using the PIN to encrypt the token secret (like its
            # done in mode1) is much more susceptible to brute force attacks.
            need_encryption = False

        # FIXME: how to decided if encryption is needed in second factor usage??
        # When used as second factor token (e.g. with ssh or password token) it
        # is probably saver to encrypt our config. If the first factor token is
        # a weak password this may not be true but we currently have not way to
        # get this info at this stage.
        if second_factor_usage:
            need_encryption = True
        else:
            # Wnen not used as second factor token remove PIN len from config to
            # make brute force attacks harder.
            offline_config['PIN_LEN'] = ''

        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption

        return offline_config

    def get_secret(self, pin=None, mode=None,
        callback=default_callback, _caller="API", ** kwargs):
        """ Get token secret """
        if not mode:
            mode = self.mode
        if mode == "mode1":
            secret = str(self.secret)
        else:
            if not pin:
                msg = "Cannot generate secret without PIN."
                return callback.error(msg)
            pin = str(pin)
            pin = pin.encode("utf-8")
            server_secret = self.server_secret
            if isinstance(server_secret, str):
                server_secret = server_secret.encode("utf-8")
            hash_string = b"%s%s" % (pin, server_secret)
            sha512 = hashlib.sha512()
            sha512.update(hash_string)
            secret = sha512.hexdigest()
            secret = secret.encode()
            secret = secret[0:self.secret_len]
            secret = base64.b32encode(secret)
            secret = secret.decode()
        if _caller == "API":
            return secret
        return callback.ok(secret)

    @check_acls(['edit:mode'])
    @object_lock()
    @backend.transaction
    def change_mode(self, new_mode, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change token operation mode. """
        # Make sure new mode is of type string.
        new_mode = str(new_mode)

        if not new_mode in self.valid_modes:
            return callback.error(_("Unknown mode: %s") % new_mode)

        if new_mode == self.mode:
            return callback.error(_("Token already in mode: %s") % new_mode)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_mode",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if new_mode == "mode1":
            if not force:
                pin = callback.askpass("Please enter PIN: ")
                pin = str(pin)
                if len(pin) != self.pin_len:
                    msg = "Invalid PIN."
                    return callback.error(msg)
                self.secret = self.get_secret(pin=pin)
                self.pin = pin
            self.pin_mandatory = False
            return_message = (_("Token switched to mode1."))

        if new_mode == "mode2":
            # If we have a server secret we can try to switch back to mode2
            # without re-deploying token.
            if self.server_secret:
                if not force:
                    pin_otp = None
                    if not pin_otp:
                        pin_otp = callback.askpass("Please enter PIN+OTP: ")

                    if pin_otp is None:
                        return callback.error("Unable to get PIN+OTP.")

                    # Make sure PIN+OTP is str().
                    pin_otp = str(pin_otp)

                    # Split OTP in PIN and OTP.
                    pin = pin_otp[:self.pin_len]

                    # Generate secret from server secret and PIN.
                    secret = self.get_secret(pin=pin,
                                            mode="mode2",
                                            callback=callback)
                    # Verify OTP.
                    if not self.verify_otp(otp=pin_otp, secret=secret, mode="mode2"):
                        msg = "Wrong PIN or token out of sync."
                        return callback.error(msg)

                    # Make sure OTP cannot be re-used.
                    otp = pin_otp[self.pin_len:]
                    try:
                        self.add_used_otp(otp=otp)
                    except Exception as e:
                        msg = "Error adding OTP to list of used OTPs: %s" % e
                        return callback.error(msg)

                self.pin = None
                self.secret = None
                return_message = (_("Token switched to mode2."))
            else:
                msg = (_("WARNING: Changing token mode to 'mode2' requires "
                        "re-deployment of the token!"))
                callback.send(msg)
                if not force:
                    new_pin = None
                    while True:
                        new_pin1 = str(callback.askpass("New PIN:", null_ok=True))
                        if new_pin1 == "":
                            if new_pin:
                                break
                            else:
                                continue
                        if not self.check_pin(pin=new_pin1, callback=callback):
                            continue
                        new_pin2 = callback.askpass("Repeat PIN: ")
                        if new_pin1 == new_pin2:
                            new_pin = new_pin1
                            break
                    self.server_secret = stuff.gen_secret(self.secret_len, "base32")
                    token_secret = self.get_secret(pin=new_pin,
                                                    mode="mode2",
                                                    callback=callback)
                    return_message = (_("New token secret: %s") % token_secret)
                    msg = ("Please re-sync token after deploying secret to token!")
                    callback.send(msg)
                self.pin = None
                self.secret = None
                self.pin_enabled = True
                self.pin_mandatory = True

        # Set new mode.
        self.mode = new_mode

        callback.send(return_message)

        return self._cache(callback=callback)

    def _enable_pin(self, pre=False, callback=default_callback, **kwargs):
        """ Enable token PIN. """
        return True

    def _disable_pin(self, pre=False, callback=default_callback, **kwargs):
        """ Disable token PIN. """
        if not pre:
            return True
        if self.mode == "mode2":
            if self.allow_offline:
                msg = (_("WARNING: Offline usage is enabled for this token. "
                        "Anybody who is able to access the offline token file "
                        "is able to use it for login."))
                callback.send(msg)
        return True

    def _change_secret(self, secret=None, pre=False,
        force=False, callback=default_callback, **kwargs):
        """ Handle stuff when changing token secret """
        if self.mode == "mode2":
            if pre:
                msg = (_("WARNING: Changing the secret of a token in mode2 is "
                    "not supported. The secret changes if you change the PIN."))
                callback.send(msg)
                return callback.error()
        else:
            if pre and not force:
                msg = (_("WARNING: Changing the secret requires a "
                        "re-deployment of the token."))
                callback.send(msg)
                answer = callback.ask("Change token secret?: ")
                if answer.lower() == "y":
                    return callback.ok()
                else:
                    return callback.error()
            msg = "Please re-sync token after changing the secret!"
            callback.send(msg)
            self.server_secret = None
        return callback.ok()

    def change_pin(self, *args, callback=default_callback, **kwargs):
        """ Change token PIN. """
        result =  super(OathToken, self).change_pin(*args,
                                                callback=callback,
                                                **kwargs)
        if not result:
            return result
        if self.mode == "mode2":
            self.pin = None
        return self._cache(callback=callback)

    def _change_pin(self, pin=None, pre=False,
        force=False, callback=default_callback, **kwargs):
        """ Handle stuff when changing token PIN """
        if self.mode == "mode2":
            if pre and not force:
                msg = (_("WARNING: Changing the PIN of a token in mode2 "
                        "requires a re-deployment of the token."))
                callback.send(msg)
                answer = callback.ask("Change token PIN?: ")
                if answer.lower() == "y":
                    return callback.ok()
                else:
                    return callback.error()
            self.server_secret = stuff.gen_secret(self.secret_len, "base32")
            token_secret = self.get_secret(pin=pin, callback=callback)
            callback.send(_("New token secret: %s") % token_secret)
            msg = "Please re-sync token after deploying secret to token!"
            callback.send(msg)

        elif self.server_secret:
            if pre and not force:
                msg = (_("WARNING: This token was previously used in mode2. "
                        "Changing the PIN requires a re-deployment when "
                        "changing back to mode2."))
                callback.send(msg)
                answer = callback.ask("Change token PIN?: ")
                if answer.lower() == "y":
                    return callback.ok()
                else:
                    return callback.error()
            self.server_secret = None

        # Update PIN length.
        if not pre:
            self.pin_len = len(str(pin))

        return callback.ok()

    def _enable_offline(self, pre=False, callback=default_callback, **kwargs):
        """ Handle stuff when enabling offline mode. """
        if pre:
            if self.mode == "mode1":
                msg = (_("WARNING: Anybody who gets access to the offline "
                        "token file is able to use it for logins and can see "
                        "your PIN in clear-text!!"))
                callback.send(msg)
                msg = (_("You should consider changing token mode to mode2!!"))
                callback.send(msg)
            else:
                msg = (_("INFO: Offline OTP tokens are by design vulnerable "
                        "for brute force attacks if an attacker is able to "
                        "steal them (e.g. from a notebook)"))
                callback.send(msg)
        return True

    def test(self, password=None, callback=default_callback, **kwargs):
        """ Test if the given OTP can be verified by this token. """
        ok_message = "Token verified successful."
        error_message = "Token verification failed."
        if self.pin_enabled:
            otp_prompt = "PIN+OTP: "
        else:
            otp_prompt = "OTP: "
        if not password:
            password = callback.askpass(otp_prompt)
        if not password:
            return callback.error("Unable to get password.")
        status = self.verify_otp(otp=str(password), **kwargs)
        if status:
            return callback.ok(ok_message)
        return callback.error(error_message)

    def verify(self, challenge=None, response=None, **kwargs):
        """ Call default verify method. """
        if challenge and response:
            return self.verify_mschap_otp(challenge=challenge,
                                            response=response,
                                            **kwargs)
        return self.verify_otp(**kwargs)

    def verify_static(self, **kwargs):
        """ Verify given password against 'password' token. """
        msg = (_("Verifying static passwords is not supported with token type: "
                "'%s'.") % self.token_type)
        raise OTPmeException(msg)

    def verify_mschap_static(self, **kwargs):
        """ Verify MSCHAP challenge/response against static passwords. """
        msg = (_("Verifying an static MSCHAP request is not supported with "
                "token type '%s'.") % self.token_type)
        raise OTPmeException(msg)

    @check_acls(['generate:otp'])
    def gen_mschap(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Generate MSCHAP challenge response stuff for testing. """
        if self.mode == "mode2":
            msg = "Cannot gen MSCHAP data in mode2."
            return callback.error(msg)

        pin = None
        if self.mode == "mode1":
            if self.pin_enabled:
                pin = self.pin

        if run_policies:
            try:
                self.run_policies("gen_mschap",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        otp = self.gen_otp(prefix_pin=pin, verify_acls=False)[0]

        return super(OathToken, self)._gen_mschap(password=otp, callback=callback)

    @object_lock(full_lock=True)
    def pre_deploy(self, _caller="API", verbose_level=0,
        callback=default_callback, **kwargs):
        reply = {
                'secret_len'    : self.secret_len,
                }
        return callback.ok(reply)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, gen_qrcode=True, no_token_infos=False,
        verify_acls=True, callback=default_callback, **kwargs):
        """ Add a token. """
        # Gen server secret.
        #self.server_secret = pyotp.random_base32()
        self.server_secret = stuff.gen_secret(self.secret_len, "base32")
        # Gen PIN.
        default_pin_len = self.get_config_parameter("hotp_default_pin_len")
        pin = stuff.gen_pin(default_pin_len)
        self.pin_len = default_pin_len
        # Get token secret.
        token_secret = self.get_secret(pin=pin, callback=callback)
        # Generate salt for used OTP hashes.
        self.used_otp_salt = stuff.gen_secret(32)
        return_message = None
        show_pin = True
        show_secret = True
        if not no_token_infos:
            if verify_acls:
                if not self.verify_acl("view:secret"):
                    gen_qrcode = False
                    show_secret = False
            if gen_qrcode:
                term_qrcode = self.gen_qrcode(pin=pin, run_policies=False)
                return_message = term_qrcode
            if show_secret:
                if return_message:
                    return_message = "%sToken secret: %s" % (return_message, token_secret)
                else:
                    return_message = "Token secret: %s" % token_secret
            if verify_acls:
                if not self.verify_acl("view:pin"):
                    show_pin = False
            if show_pin:
                message = "Token PIN: %s" % pin
                if return_message:
                    return_message = "%s\n%s" % (return_message, message)
                else:
                    return_message = message
        if return_message:
            return callback.ok(return_message)
        return callback.ok()

    @check_acls(['view_all:secret'])
    def show_secret(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Show object secret. """
        if run_policies:
            try:
                self.run_policies("show_secret",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        pin = None
        if self.mode == "mode2":
            pin = callback.askpass("Please enter PIN: ")
            if pin is None:
                msg = "Cannot show secret without PIN."
                return callback.error(msg)
            pin = str(pin)
            if len(pin) != self.pin_len:
                msg = "Invalid PIN."
                return callback.error(msg)

        token_secret = self.get_secret(pin=pin, callback=callback)
        callback.send(token_secret)

        return callback.ok()
