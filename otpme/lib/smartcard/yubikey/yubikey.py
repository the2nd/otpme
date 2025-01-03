# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
try:
    import yubico
except ImportError as e:
    msg = "Unable to load module: %s" % e
    print(msg)

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff
from otpme.lib import system_command
from otpme.lib.encoding.base import encode

from otpme.lib.exceptions import *

logger = config.logger

yubikey_gpg_reset_string = b"""
/hex
scd serialno
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 e6 00 00
scd apdu 00 44 00 00
/echo Card has been successfully reset.
"""

def get(debug=False, print_devices=False):
    """ Try to find yubikey and return instance """
    try:
        YK = yubico.find_yubikey(debug=debug)
    except yubico.yubico_exception.YubicoError as e:
        if e.reason == "No YubiKey found":
            raise NoSmartcardFound(e.reason)
        raise Exception(_("Error: %s") % e.reason)

    if config.debug_enabled:
        logger.debug("Found Yubikey: %s" % YK.model)
        logger.debug("Version: %s" % YK.version())

    if print_devices:
        msg = "Found Yubikey: %s" % YK.model
        print(msg)
        msg = "Version: %s" % YK.version()
        print(msg)

    return YK

class Yubikey(object):
    """ Class to access yubikey tokens """
    otpme_auth_types = []
    def __init__(self, autodetect=True, debug=False):
        # Set smartcard type
        self.type = "yubikey"
        # Will be set by OTPmeClient() when doing preauth_check
        self.options = {}

        if autodetect:
            self.detect()
        else:
            self.yubikey = None

    def detect(self, debug=False, print_devices=False):
        """ Try to find yubikey """
        # Get yubikey instance
        self.yubikey = get(debug=debug, print_devices=print_devices)

    def get_id(self):
        """ Get smartcard ID. Used to get settings (e.g. slot) from authd on login """
        return str(self.get_serial())

    def get_serial(self, **kwargs):
        """ Returns yubikey serial """
        return self.yubikey.serial()

    def get_slot(self):
        """ Get slot from options or set default """
        try:
            slot = self.options['slot']
        except:
            slot = 2
        return slot

    def set_mode(self, mode="82"):
        """ Set yubikey mode """
        #  FIXME: We should use python-yubico for this:
        #         https://github.com/Yubico/python-yubico/issues/21
        # Set yubikey mode (http://forum.yubico.com/viewtopic.php?f=26&t=1171)
        # OTP HID-only (0x80): The key behaves like a regular YubiKey
        #                      or YubiKey Nano when inserted. This is
        #                      the factory setting.
        # OpenPGP CCID-only (0x81): The key only operates as an OpenPGP
        #                           CCID smartcard token when inserted.
        #                           The button acts to enable/disable
        #                           the reader.
        # OTP HID+OpenPGP CCID (0x82): The key is visible both as an HOTP HID
        #                              device and OpenPGP CCID smartcard. The
        #                              button functions as on a regular YubiKey.
        yubikey_mode_command = [ 'ykpersonalize', '-y', '-m', mode ]
        command_returncode, \
        command_stdout, \
        command_stderr, \
        command_pid = system_command.run(command=yubikey_mode_command)
        if command_returncode != 0:
            raise Exception(_("Error setting yubikey mode: %s")
                            % command_stderr)
        return True

    def set_serial_visible(self, slot=None, visible=True, **kwargs):
        """ Set SERIAL_API_VISIBLE flag """
        if slot == None:
            slot = self.get_slot()

        # make sure slot is int()
        slot = int(slot)

        try:
            yk_cfg = self.yubikey.init_config()
            yk_cfg.extended_flag('SERIAL_API_VISIBLE', visible)
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("ERROR: %s") % e.reason)

        try:
            self.yubikey.write_config(yk_cfg, slot=slot)
            return True
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("Error writing config: %s") % e.reason)
        except Exception as e:
            raise Exception(_("Error writing config: %s") % e)

    def add_hmac_sha1(self, slot=None, key=None, **kwargs):
        """ Add HMAC-SHA1 config to given yubikey slot """
        if slot is None:
            slot = self.get_slot()
        # Make sure slot is int().
        slot = int(slot)
        # Gen token key.
        if not key:
            key = stuff.gen_secret(len=20)
        if isinstance(key, str):
            key = key.encode()
        try:
            yk_cfg = self.yubikey.init_config()
            yk_cfg.mode_challenge_response(b'h:%s' % key, type='HMAC', variable=True)
            yk_cfg.extended_flag('SERIAL_API_VISIBLE', True)
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("ERROR: %s") % e.reason)

        try:
            self.yubikey.write_config(yk_cfg, slot=slot)
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("Error writing config: %s") % e.reason)
        except Exception as e:
            raise Exception(_("Error writing config: %s") % e)

        # Return HMAC secret on success.
        return key

    def add_oath_hotp(self, slot=None, key=None, **kwargs):
        """ Add OATH HOTP config to given yubikey slot """
        if slot == None:
            slot = self.get_slot()
        # Make sure slot is int().
        slot = int(slot)
        # Gen token key.
        if not key:
            key = stuff.gen_secret(len=20)
        if isinstance(key, str):
            key = key.encode()
        try:
            yk_cfg = self.yubikey.init_config()
            yk_cfg.mode_oath_hotp(b'h:%s' % key)
            yk_cfg.extended_flag('SERIAL_API_VISIBLE', True)
            yk_cfg.ticket_flag('APPEND_CR', True)
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("ERROR: %s") % e.reason)

        try:
            self.yubikey.write_config(yk_cfg, slot=slot)
        except yubico.yubico_exception.YubicoError as e:
            raise Exception(_("Error writing config: %s") % e.reason)
        except Exception as e:
            raise Exception(_("Error writing config: %s") % e)

        # return HMAC secret on success
        return key

    def send_challenge(self, challenge, slot=None, **kwargs):
        """ send challenge to yubikey and return response """
        if slot == None:
            slot = self.get_slot()
        # Make sure slot is int().
        slot = int(slot)
        if isinstance(challenge, str):
            challenge = challenge.encode()
        response = self.yubikey.challenge_response(challenge, slot=slot)
        return encode(response, "hex")

    def reset_gpg(self):
        """ Reset yubikey's GPG applet. """
        # Make sure we get english messages from gpg-connect-agent
        old_lang = os.environ['LANG']
        os.environ['LANG'] = ''
        yubikey_reset_command = [ 'gpg-connect-agent', '-r', '/dev/stdin' ]
        proc = system_command.run(command=yubikey_reset_command,
                                    return_proc=True)
        proc.stdin.write(yubikey_gpg_reset_string)
        command_stdout, command_stderr = proc.communicate()
        command_stdout = command_stdout.decode()
        command_stderr = command_stderr.decode()
        #command_returncode = proc.returncode
        os.environ['LANG'] = old_lang
        command_output = "%s\n%s" % (command_stdout, command_stderr)
        for line in command_output.split('\n'):
            if line.endswith('Card has been successfully reset.'):
                return True
        raise Exception(_("Resetting GPG applet failed: %s") % command_stderr)
