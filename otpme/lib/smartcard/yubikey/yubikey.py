# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
try:
    from yubikit.yubiotp import SLOT
    from yubikit.core import TRANSPORT
    from ykman.device import list_all_devices
    from ykman.device import list_otp_devices
    from yubikit.management import CAPABILITY
    from yubikit.core.otp import OtpConnection
    from yubikit.yubiotp import YubiOtpSession
    from yubikit.management import DeviceConfig
    from yubikit.management import ManagementSession
    from yubikit.yubiotp import HotpSlotConfiguration
    from yubikit.yubiotp import HmacSha1SlotConfiguration
    from yubikit.core.smartcard import SmartCardConnection
except ImportError as e:
    msg = _("Unable to load module: {error}")
    msg = msg.format(error=e)
    print(msg)

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
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
    devices = list_all_devices()
    if not devices:
        raise NoSmartcardFound("No YubiKey found")

    device, info = devices[0]

    if config.debug_enabled:
        log_msg = _("Found Yubikey: serial={serial}", log=True)[1]
        log_msg = log_msg.format(serial=info.serial)
        logger.debug(log_msg)
        log_msg = _("Version: {version}", log=True)[1]
        log_msg = log_msg.format(version=info.version)
        logger.debug(log_msg)

    if print_devices:
        msg = _("Found Yubikey: serial={serial}")
        msg = msg.format(serial=info.serial)
        print(msg)
        msg = _("Version: {version}")
        msg = msg.format(version=info.version)
        print(msg)

    return device, info

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
            self.device = None
            self.info = None

    def detect(self, debug=False, print_devices=False):
        """ Try to find yubikey """
        # Get yubikey instance
        self.device, self.info = get(debug=debug, print_devices=print_devices)

    def get_id(self):
        """ Get smartcard ID. Used to get settings (e.g. slot) from authd on login """
        return str(self.get_serial())

    def get_serial(self, **kwargs):
        """ Returns yubikey serial """
        return self.info.serial

    def get_slot(self):
        """ Get slot from options or set default """
        try:
            slot = self.options['slot']
        except:
            slot = 2
        return slot

    def _get_yk_slot(self, slot):
        """ Map integer slot number to SLOT enum """
        if slot == 1:
            return SLOT.ONE
        return SLOT.TWO

    def _open_otp_session(self):
        """ Open YubiOtpSession via OTP HID, with SmartCard fallback for config writes """
        # 1) Try OtpConnection on composite device.
        if self.device.supports_connection(OtpConnection):
            conn = self.device.open_connection(OtpConnection)
            return conn, YubiOtpSession(conn)
        # 2) Composite device has no OTP HID - try listing OTP HID devices directly.
        try:
            otp_devs = list_otp_devices()
            if otp_devs:
                conn = otp_devs[0].open_connection(OtpConnection)
                return conn, YubiOtpSession(conn)
        except Exception:
            pass
        # 3) Fall back to SmartCardConnection (works for config writes,
        #    but challenge-response may fail over CCID).
        if self.device.supports_connection(SmartCardConnection):
            conn = self.device.open_connection(SmartCardConnection)
            return conn, YubiOtpSession(conn)
        raise Exception("YubiKey does not support OTP or SmartCard connection")

    def set_mode(self, mode="82"):
        """ Set yubikey mode """
        # mode "82" = OTP HID + OpenPGP CCID
        capabilities = CAPABILITY.OTP | CAPABILITY.OPENPGP
        device_config = DeviceConfig(
            enabled_capabilities={TRANSPORT.USB: capabilities},
        )
        for conn_type in (SmartCardConnection, OtpConnection):
            if self.device.supports_connection(conn_type):
                with self.device.open_connection(conn_type) as conn:
                    mgmt = ManagementSession(conn)
                    mgmt.write_device_config(device_config, reboot=True)
                break
        else:
            raise Exception("YubiKey does not support SmartCard or OTP connection")
        return True

    def set_serial_visible(self, slot=None, visible=True, **kwargs):
        """ No-op - serial is always readable via ykman """
        pass

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
        yk_slot = self._get_yk_slot(slot)
        # key is hex-encoded, convert to raw bytes for yubikit.
        raw_key = bytes.fromhex(key.decode())
        slot_config = HmacSha1SlotConfiguration(raw_key)
        conn, session = self._open_otp_session()
        try:
            session.put_configuration(yk_slot, slot_config)
        finally:
            conn.close()
        # Return HMAC secret on success (hex-encoded, as before).
        return key

    def add_oath_hotp(self, slot=None, key=None, **kwargs):
        """ Add OATH HOTP config to given yubikey slot """
        if slot is None:
            slot = self.get_slot()
        # Make sure slot is int().
        slot = int(slot)
        # Gen token key.
        if not key:
            key = stuff.gen_secret(len=20)
        if isinstance(key, str):
            key = key.encode()
        yk_slot = self._get_yk_slot(slot)
        # key is hex-encoded, convert to raw bytes for yubikit.
        raw_key = bytes.fromhex(key.decode())
        slot_config = HotpSlotConfiguration(raw_key)
        conn, session = self._open_otp_session()
        try:
            session.put_configuration(yk_slot, slot_config)
        finally:
            conn.close()
        # Return HMAC secret on success (hex-encoded, as before).
        return key

    def send_challenge(self, challenge, slot=None, **kwargs):
        """ Send challenge to yubikey and return response """
        if slot is None:
            slot = self.get_slot()
        # Make sure slot is int().
        slot = int(slot)
        if isinstance(challenge, str):
            challenge = challenge.encode()
        yk_slot = self._get_yk_slot(slot)
        conn, session = self._open_otp_session()
        try:
            response = session.calculate_hmac_sha1(yk_slot, challenge)
        except Exception as e:
            conn.close()
            if not isinstance(conn, OtpConnection):
                msg = ("HMAC challenge-response failed over SmartCard/CCID. "
                       "OTP HID access is required - check that /dev/hidraw* "
                       "devices are accessible (udev rules, permissions).")
                raise Exception(msg) from e
            raise
        conn.close()
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
        command_output = f"{command_stdout}\n{command_stderr}"
        for line in command_output.split('\n'):
            if line.endswith('Card has been successfully reset.'):
                return True
        msg = _("Resetting GPG applet failed: {error}")
        msg = msg.format(error=command_stderr)
        raise Exception(msg)
