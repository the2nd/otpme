# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import cli
from otpme.lib import json
from otpme.lib import config
from otpme.lib.help import command_map
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.smartcard.yubikey import piv
#from otpme.lib.messages import error_message

from otpme.lib. exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_smartcard_type("yubikey_piv", YubikeypivClientHandler, YubikeypivServerHandler)

class YubikeypivClientHandler(object):
    def __init__(self, sc_type, token_rel_path, token_options=None,
        message_method=print, error_message_method=print):
        self.local_command_args = {}
        self.token_type = "yubikey_piv"
        self.smartcard_type = sc_type
        self.token_rel_path = token_rel_path
        self.token_options = token_options
        self.master_backup_key_file = None
        self.restore_from_server = False
        self.message_method = message_method
        self.error_message_method = error_message_method
        # FIXME: pam message methods from pam.py does not work with sddm
        #       and adds some strange delay.
        self.message_method = print
        self.error_message_method = print
        self.logger = config.logger

    def parse_syntax(self, command_handler):
        # Get command syntax.
        try:
            command_syntax = command_map['token']['yubikey_piv']['deploy']['cmd']
        except:
            msg = _("Unknown token type: {type}")
            msg = msg.format(type=self.smartcard_type)
            raise OTPmeException(msg)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            self.object_identifier, \
            self.local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_handler.command_line)
        except Exception as e:
            if str(e) == "help":
                exception = command_handler.get_help()
                raise ShowHelp(exception)
            elif str(e) != "":
                msg = str(e)
                exception = command_handler.get_help(message=msg)
                raise ShowHelp(exception)

    def get_pre_deploy_args(self, command_handler):
        self.parse_syntax(command_handler)
        try:
            self.restore_from_server = self.local_command_args['restore_from_server']
        except KeyError:
            self.restore_from_server = False
        try:
            self.master_backup_key_file = self.local_command_args['backup_key_file']
        except KeyError:
            if self.restore_from_server:
                msg = _("Restore from server requires --backup-key-file.")
                raise OTPmeException(msg)
        pre_deploy_args = {'restore_from_server':self.restore_from_server}
        return pre_deploy_args

    def handle_deploy(self, command_handler, no_token_write=False, pre_deploy_result={}, **kwargs):
        try:
            private_key_backup_key = pre_deploy_result['private_key_backup_key']
        except KeyError:
            private_key_backup_key = None

        try:
            server_private_key_backup = pre_deploy_result['private_key_backup']
        except KeyError:
            server_private_key_backup = None

        try:
            add_user_key = self.local_command_args['add_user_key']
        except KeyError:
            add_user_key = False

        # Handle deployment of yubikey PIV applet.
        public_key = None
        private_key_backup = None
        if no_token_write:
            if self.restore_from_server:
                msg = _("-n conflicts with --restore-from-server")
                raise OTPmeException(msg)
            # Try to get public key of already initialized yubikey.
            public_key = piv.get_public_key()
            public_key = public_key.public_bytes(Encoding.PEM,
                                            PublicFormat.SubjectPublicKeyInfo)
            public_key = public_key.decode()
        else:
            try:
                key_len = self.local_command_args['key_len']
            except:
                key_len = 2048

            backup_file = None
            restore_file = None
            if self.restore_from_server:
                if not server_private_key_backup:
                    msg = _("Got no private key backup from server.")
                    raise OTPmeException(msg)
            else:
                try:
                    backup_file = self.local_command_args['backup_file']
                except:
                    backup_file = None
                try:
                    restore_file = self.local_command_args['restore_file']
                except:
                    restore_file = None
                    if private_key_backup_key is None:
                        backup_file = "/dev/shm/" + object_identifier.replace("/", "_")

            if restore_file and not os.path.exists(restore_file):
                msg = _("Restore file does not exist: {file}")
                msg = msg.format(file=restore_file)
                raise OTPmeException(msg)

            # We cannot backup and restore at the same time.
            if restore_file and backup_file:
                return command_handler.get_help(command="deploy",
                                                subcommand=token_type,
                                                command_map=command_map)
            if backup_file:
                if os.path.exists(backup_file):
                    msg = _("Backup file already exists: {backup_file}")
                    msg = msg.format(backup_file=backup_file)
                    raise OTPmeException(msg)

            if self.restore_from_server:
                # Get key backup and parameters.
                try:
                    enc_mod = server_private_key_backup['enc_mod']
                except KeyError:
                    msg = _("Server key backup misses encryption module.")
                    raise OTPmeException(msg)
                try:
                    enc_key_encrypted = server_private_key_backup['enc_key']
                except KeyError:
                    msg = _("Server key backup misses encryption key.")
                    raise OTPmeException(msg)
                try:
                    _private_key_backup = server_private_key_backup['private_key_backup']
                except KeyError:
                    msg = _("Server key backup misses private key.")
                    raise OTPmeException(msg)
                # Try to load backup key.
                try:
                    backup_key = RSAKey(key_file=self.master_backup_key_file)
                except TypeError as e:
                    backup_key_pass = cli.read_pass(prompt='Master backup key password: ')
                    try:
                        backup_key = RSAKey(key_file=self.master_backup_key_file,
                                            key_password=backup_key_pass)
                    except Exception as e:
                        msg = _("Error loading masetr backup key: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg)
                # Try to decrypt fernet key.
                try:
                    enc_key_encrypted = bytes.fromhex(enc_key_encrypted)
                    enc_key = backup_key.decrypt(enc_key_encrypted)
                except Exception as e:
                    msg = _("Failed to decrypt fernet backup key: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg)
                try:
                    enc_mod = config.get_encryption_module(enc_mod)
                except Exception as e:
                    msg = _("Failed to load backup key encryption: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg)
                try:
                    _private_key_backup = json.decode(_private_key_backup,
                                                    encryption=enc_mod,
                                                    enc_key=enc_key)
                except Exception as e:
                    msg = _("Faild to decode key backup: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg)
                try:
                    private_key_pem = _private_key_backup['private_key']
                except KeyError:
                    msg = _("Private key backup does not include private key.")
                    raise OTPmeException(msg)
                try:
                    token_key = RSAKey(key=private_key_pem)
                except Exception as e:
                    msg = _("Failed to load backup key: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg)
            elif restore_file:
                try:
                    token_key = RSAKey(key_file=restore_file)
                except TypeError:
                    backup_password = cli.read_pass(prompt='Key file password: ')
                    try:
                        token_key = RSAKey(key_file=restore_file,
                                    key_password=backup_password)
                    except Exception as e:
                        msg = _("Error loading RSA key: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg)
                except Exception as e:
                    msg = _("Error loading RSA key: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg)
                # Get private key as PEM.
                private_key_pem = token_key.export_private_key(encoding='PEM')
            else:
                try:
                    token_key = RSAKey(bits=key_len)
                except Exception as e:
                    msg = _("Error creating RSA key: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg)

                if private_key_backup_key is None:
                    # Backup RSA key.
                    x = cli.user_input("Use token password to protect backup file? (y/n) ")
                    if x.lower() != "n":
                        backup_password = token_password
                    else:
                        backup_password = cli.get_password(prompt="Backup password: ", min_len=8)

                    private_key_enc_pem = token_key.export_private_key(encoding='PEM',
                                                                password=backup_password)
                    try:
                        fd = open(backup_file, "w")
                    except Exception as e:
                        msg = _("Failed to open backup file: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg)
                    # Write key.
                    try:
                        fd.write(private_key_enc_pem)
                    finally:
                        fd.close()
                else:
                    try:
                        backup_key_pub = RSAKey(key=private_key_backup_key)
                    except Exception as e:
                        msg = _("Error loading backup key: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg)
                    try:
                        enc_mod = config.get_encryption_module("FERNET")
                    except Exception as e:
                        msg = _("Failed to load backup key encryption: {error}")
                        msg = msg.format(error=e)
                        raise OTPmeException(msg)
                    # Gen fernet encryption key.
                    enc_key = enc_mod.gen_key()
                    # Get private key as PEM.
                    private_key_pem = token_key.export_private_key(encoding='PEM')
                    private_key_backup = {
                                    'private_key'   : private_key_pem,
                                    }
                    try:
                        private_key_backup = json.encode(private_key_backup,
                                                        encryption=enc_mod,
                                                        enc_key=enc_key)
                    except Exception as e:
                        msg = _("Faild to build preauth request: {error}")
                        msg = msg.format(error=e)
                        raise OTPmeException(msg)
                    # Encrypt fernet key with backup key.
                    enc_key_encrypted = backup_key_pub.encrypt(enc_key)
                    enc_key_encrypted = enc_key_encrypted.hex()
                    # Build private key backup dict.
                    private_key_backup = {
                                            'enc_mod'               : 'FERNET',
                                            'enc_key'               : enc_key_encrypted,
                                            'private_key_backup'    : private_key_backup,
                                        }

            # Reset PIV.
            reset_status = piv.reset()
            if not reset_status:
                msg = _("Aborted.")
                raise OTPmeException(msg)

            # Get token password.
            token_password = cli.get_password(prompt='Token password: ', min_len=8)

            # Set PIN/PUK.
            piv.change_pin(old_pin=piv.DEFAULT_PIN, new_pin=token_password)
            piv.change_puk(old_puk=piv.DEFAULT_PUK, new_puk=token_password)

            # Write RSA key to yubikey.
            piv.import_rsa_key(private_key=private_key_pem,
                                slot="AUTHENTICATION",
                                pin=token_password)
                                #serial=serial)
            public_key = token_key.export_public_key(encoding="PEM")

        # Without public key we cannot continue.
        if not public_key:
            msg = (_("Cannot continue without public key."))
            raise OTPmeException(msg)
        # Add SSH public key to deployment args.
        deploy_args = {}
        deploy_args['public_key'] = public_key
        deploy_args['add_user_key'] = add_user_key
        if private_key_backup:
            deploy_args['private_key_backup'] = private_key_backup

        return deploy_args

    def handle_preauth(self, smartcard, password):
        challenge = self.token_options['challenge']
        # Sign challenge.
        try:
            signature = smartcard.sign_challenge(slot="AUTHENTICATION",
                                            pin=password,
                                            challenge=challenge)
        except OTPmeException as e:
            msg = _("Error signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        smartcard_data = self.token_options.copy()
        smartcard_data['signature'] = signature
        smartcard_data['token_rel_path'] = self.token_rel_path
        return smartcard_data

    def handle_authentication(self, smartcard, smartcard_data, password, **kwargs):
        challenge = smartcard_data['challenge']
        # Sign challenge.
        try:
            signature = smartcard.sign_challenge(slot="AUTHENTICATION",
                                            pin=password,
                                            challenge=challenge)
        except OTPmeException as e:
            msg = _("Error sending signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        return signature

    def handle_offline_token_challenge(self, smartcard, password, enc_challenge, **kwargs):
        try:
            enc_pass = smartcard.derive_password(challenge=enc_challenge,
                                                pin=password,
                                                slot="AUTHENTICATION")
        except Exception as e:
            msg = _("Error sending offline token encryption challenge to smartcard: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)
        return enc_pass

    def handle_offline_challenge(self, smartcard, token, password, enc_challenge, **kwargs):
        try:
            enc_pass = smartcard.derive_password(challenge=enc_challenge,
                                                pin=password,
                                                slot="AUTHENTICATION")
        except Exception as e:
            msg = _("Error sending offline encryption challenge to smartcard: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)
        return enc_pass

    def get_smartcard_data(self, smartcard, token, password, **kwargs):
        challenge = token.gen_challenge()
        # Sign challenge.
        try:
            signature = smartcard.sign_challenge(slot="AUTHENTICATION",
                                            pin=password,
                                            challenge=challenge)
        except OTPmeException as e:
            msg = _("Error signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise AuthFailed(msg)
        smartcard_data = {
                        'challenge' : challenge,
                        'signature' : signature,
                        }
        return smartcard_data

class YubikeypivServerHandler(object):
    def __init__(self):
        self.token_type = None
        self.challenge = None

    def handle_preauth(self, token):
        challenge = token.gen_challenge()
        self.challenge = challenge
        self.token_type = token.token_type
        token_options = {
                    'token_type'    : token.token_type,
                    'challenge'     : challenge,
                    'pass_required' : True,
                    }
        return token_options

    def prepare_authentication(self, smartcard_data):
        return smartcard_data

class Yubikeypiv(object):
    """ Class to access yubikey PIV tokens. """
    otpme_auth_types = [ "yubikey_piv" ]
    def __init__(self, autodetect=True, debug=False):
        # Set smartcard type
        self.type = "yubikey_piv"
        # Will be set by OTPmeClient() when doing preauth_check
        self.options = {}

        if autodetect:
            self.detect()

    def detect(self, debug=False, print_devices=False):
        """ Try to find yubikey PIV. """
        x = piv.detect()
        if not x:
            msg = _("No yubikey (PIV) found.")
            raise OTPmeException(msg)

    def sign_challenge(self, challenge, pin, slot="AUTHENTICATION", **kwargs):
        """ Sign challenge with yubikey-piv."""
        if isinstance(challenge, str):
            challenge = challenge.encode()
        try:
            signature = piv.sign(data=challenge,
                                slot=slot,
                                pin=pin,
                                padding="pss")
        except Exception as e:
            raise
        signature = signature.hex()
        return signature

    def derive_password(self, challenge, pin, length=32, slot="AUTHENTICATION"):
        pw = piv.derive_password(challenge=challenge,
                                pin=pin,
                                slot=slot,
                                length=length)
        return pw
