# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json as stdlib_json
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import cli
from otpme.lib import json
from otpme.lib import sotp
from otpme.lib import config
from otpme.lib import encryption
from otpme.lib.help import command_map
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.smartcard.yubikey import piv


# PIV slot roles used by this handler.
SIGN_SLOT = "AUTHENTICATION"     # 9A — ECDSA/RSA sign, derive_password
ENCRYPT_SLOT = "KEY_MANAGEMENT"  # 9D — RSA-decrypt / ECDH-unwrap


def _load_backup_file(path):
    """ Load a deploy backup file. New format: JSON dict
    {'sign_key': PEM, 'encrypt_key': PEM}. """
    with open(path, "r") as fd:
        data = stdlib_json.load(fd)
    if not isinstance(data, dict) or 'sign_key' not in data \
            or 'encrypt_key' not in data:
        raise OTPmeException(
            "Backup file must contain JSON dict with "
            "'sign_key' and 'encrypt_key' PEMs."
        )
    return data['sign_key'], data['encrypt_key']


def _write_backup_file(path, sign_pem, encrypt_pem):
    data = {'sign_key': sign_pem, 'encrypt_key': encrypt_pem}
    with open(path, "w") as fd:
        stdlib_json.dump(data, fd, indent=2)


def _load_private_pem(pem):
    """ Algo-agnostic PEM loader for deploy paths.

    Tries cleartext first (server-restore PEMs are cleartext after the
    fernet envelope is unwrapped), falls back to a password prompt for
    PEMs encrypted via export_private_key(password=...) (local backup
    file path). Dispatches to the right wrapper (RSAKey / Ed25519Key /
    X25519Key) via the encryption factory. """
    try:
        return encryption.load_private_key(pem)
    except TypeError:
        pw = cli.read_pass(prompt='Key file password: ')
        return encryption.load_private_key(pem, password=pw)

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
        self.enc_challenge = None
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
        except Exception:
            msg = _("Unknown token type: {type}")
            msg = msg.format(type=self.smartcard_type)
            raise OTPmeException(msg) from None

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
                raise ShowHelp(exception) from e
            elif str(e) != "":
                msg = str(e)
                exception = command_handler.get_help(message=msg)
                raise ShowHelp(exception) from e

    def get_pre_deploy_args(self, command_handler, **kwargs):
        self.parse_syntax(command_handler)
        try:
            self.restore_from_server = self.local_command_args['restore_from_server']
        except KeyError:
            self.restore_from_server = False
        try:
            self.master_backup_key_file = self.local_command_args['backup_key_file']
        except KeyError as err:
            if self.restore_from_server:
                msg = _("Restore from server requires --backup-key-file.")
                raise OTPmeException(msg) from err
        pre_deploy_args = {'restore_from_server':self.restore_from_server}
        return pre_deploy_args

    def handle_deploy(self, command_handler, no_token_write=False, pre_deploy_result=None, **kwargs):
        if pre_deploy_result is None:
            pre_deploy_result = {}
        try:
            private_key_backup_key = pre_deploy_result['private_key_backup_key']
        except Exception:
            private_key_backup_key = None

        try:
            server_private_key_backup = pre_deploy_result['private_key_backup']
        except Exception:
            server_private_key_backup = None

        try:
            add_user_key = self.local_command_args['add_user_key']
        except KeyError:
            add_user_key = False

        # Pick algos for the two slots. Defaults stay rsa for back-compat;
        # ed25519/x25519 need YubiKey firmware 5.7+ (the YubiKey will
        # reject put_key with a UnsupportedAlgorithm error otherwise).
        sign_algo = self.local_command_args.get('sign_algo', 'rsa')
        encrypt_algo = self.local_command_args.get('encrypt_algo', 'rsa')
        valid_sign = {"rsa", "ed25519"}
        valid_encrypt = {"rsa", "x25519"}
        if sign_algo not in valid_sign:
            msg = _("Invalid --sign-algo: {algo} (expected one of {valid})")
            msg = msg.format(algo=sign_algo,
                             valid=", ".join(sorted(valid_sign)))
            raise OTPmeException(msg)
        if encrypt_algo not in valid_encrypt:
            msg = _("Invalid --encrypt-algo: {algo} (expected one of {valid})")
            msg = msg.format(algo=encrypt_algo,
                             valid=", ".join(sorted(valid_encrypt)))
            raise OTPmeException(msg)

        sign_public_key = None
        encrypt_public_key = None
        sign_key_type = None
        encrypt_key_type = None
        private_key_backup = None

        if no_token_write:
            token_password = cli.read_pass(prompt='Smartcard password: ')
            if self.restore_from_server:
                msg = _("-n conflicts with --restore-from-server")
                raise OTPmeException(msg)
            # Read both slots from an already-initialized yubikey.
            sign_pub = piv.get_public_key(slot=SIGN_SLOT)
            encrypt_pub = piv.get_public_key(slot=ENCRYPT_SLOT)
            # Detect what algos are actually on the card so the token
            # object stores the correct sign_key_type / encrypt_key_type.
            sign_key_type = piv.algo_for_public_key(sign_pub)
            encrypt_key_type = piv.algo_for_public_key(encrypt_pub)
            sign_public_key = sign_pub.public_bytes(Encoding.PEM,
                                            PublicFormat.SubjectPublicKeyInfo).decode()
            encrypt_public_key = encrypt_pub.public_bytes(Encoding.PEM,
                                            PublicFormat.SubjectPublicKeyInfo).decode()
            # SSH key always derives from the sign key (SSH is signature-based).
            ssh_public_key = sign_pub.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
            ssh_public_key_type, \
            ssh_public_key = ssh_public_key.decode().split()
            ssh_public_key_type = ssh_public_key_type.split("-")[1]
        else:
            try:
                key_len = self.local_command_args['key_len']
            except Exception:
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
                except Exception:
                    backup_file = None
                try:
                    restore_file = self.local_command_args['restore_file']
                except Exception:
                    restore_file = None
                    if private_key_backup_key is None:
                        backup_file = "/dev/shm/" + self.object_identifier.replace("/", "_")

            if restore_file and not os.path.exists(restore_file):
                msg = _("Restore file does not exist: {file}")
                msg = msg.format(file=restore_file)
                raise OTPmeException(msg)

            # We cannot backup and restore at the same time.
            if restore_file and backup_file:
                return command_handler.get_help(command="deploy",
                                                subcommand=self.token_type,
                                                command_map=command_map)
            if backup_file and os.path.exists(backup_file):
                msg = _("Backup file already exists: {backup_file}")
                msg = msg.format(backup_file=backup_file)
                raise OTPmeException(msg)

            # Get token password.
            token_password = cli.get_password(prompt='Smartcard password: ', min_len=8)

            if self.restore_from_server:
                # Decrypt server-side backup envelope and pull out both PEMs.
                try:
                    enc_mod = server_private_key_backup['enc_mod']
                    enc_key_encrypted = server_private_key_backup['enc_key']
                    _private_key_backup = server_private_key_backup['private_key_backup']
                except KeyError as err:
                    msg = _("Server key backup missing field: {err}")
                    msg = msg.format(err=err)
                    raise OTPmeException(msg) from err
                # Load the user's master backup key (used to wrap the fernet key).
                try:
                    backup_key = RSAKey(key_file=self.master_backup_key_file)
                except TypeError:
                    backup_key_pass = cli.read_pass(prompt='Master backup key password: ')
                    try:
                        backup_key = RSAKey(key_file=self.master_backup_key_file,
                                            key_password=backup_key_pass)
                    except Exception as e:
                        msg = _("Error loading master backup key: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg) from e
                try:
                    enc_key_encrypted = bytes.fromhex(enc_key_encrypted)
                    enc_key = backup_key.decrypt(enc_key_encrypted)
                except Exception as e:
                    msg = _("Failed to decrypt fernet backup key: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg) from e
                try:
                    enc_mod = config.get_encryption_module(enc_mod)
                except Exception as e:
                    msg = _("Failed to load backup key encryption: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg) from e
                try:
                    _private_key_backup = json.decode(_private_key_backup,
                                                    encryption=enc_mod,
                                                    enc_key=enc_key)
                except Exception as e:
                    msg = _("Failed to decode key backup: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg) from e
                try:
                    sign_private_pem = _private_key_backup['sign_key']
                    encrypt_private_pem = _private_key_backup['encrypt_key']
                except KeyError as err:
                    msg = _("Server backup missing key: {err}")
                    msg = msg.format(err=err)
                    raise OTPmeException(msg) from err
                try:
                    sign_token_key = _load_private_pem(sign_private_pem)
                    encrypt_token_key = _load_private_pem(encrypt_private_pem)
                except Exception as e:
                    msg = _("Failed to load backup keys: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg) from e
            elif restore_file:
                try:
                    sign_private_pem, encrypt_private_pem = _load_backup_file(restore_file)
                    sign_token_key = _load_private_pem(sign_private_pem)
                    encrypt_token_key = _load_private_pem(encrypt_private_pem)
                except Exception as e:
                    msg = _("Error loading keys from {file}: {e}")
                    msg = msg.format(file=restore_file, e=e)
                    raise OTPmeException(msg) from e
            else:
                # Gen the two key pairs via the algo-dispatching factory.
                # key_len only meaningful for RSA; 25519 curves fixed-size.
                try:
                    sign_kwargs = {"bits": key_len} if sign_algo == "rsa" else {}
                    enc_kwargs = {"bits": key_len} if encrypt_algo == "rsa" else {}
                    sign_token_key = encryption.gen_keypair(sign_algo, **sign_kwargs)
                    encrypt_token_key = encryption.gen_keypair(encrypt_algo, **enc_kwargs)
                except Exception as e:
                    msg = _("Error creating token keys: {e}")
                    msg = msg.format(e=e)
                    raise OTPmeException(msg) from e

                if private_key_backup_key is None:
                    # Local backup file (JSON dict, each PEM password-encrypted).
                    x = cli.user_input("Use token password to protect backup file? (y/n) ")
                    if x.lower() != "n":
                        backup_password = token_password
                    else:
                        backup_password = cli.get_password(prompt="Backup password: ", min_len=8)

                    sign_pem_enc = sign_token_key.export_private_key(encoding='PEM',
                                                                password=backup_password)
                    encrypt_pem_enc = encrypt_token_key.export_private_key(encoding='PEM',
                                                                password=backup_password)
                    try:
                        _write_backup_file(backup_file, sign_pem_enc, encrypt_pem_enc)
                    except Exception as e:
                        msg = _("Failed to write backup file: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg) from e
                else:
                    # Server-side backup: encrypt both PEMs under a fresh fernet key,
                    # then wrap that fernet key with the user's master backup pubkey.
                    try:
                        backup_key_pub = RSAKey(key=private_key_backup_key)
                    except Exception as e:
                        msg = _("Error loading backup key: {e}")
                        msg = msg.format(e=e)
                        raise OTPmeException(msg) from e
                    try:
                        enc_mod = config.get_encryption_module("FERNET")
                    except Exception as e:
                        msg = _("Failed to load backup key encryption: {error}")
                        msg = msg.format(error=e)
                        raise OTPmeException(msg) from e
                    enc_key = enc_mod.gen_key()
                    backup_content = {
                            'sign_key'      : sign_token_key.export_private_key(encoding='PEM'),
                            'encrypt_key'   : encrypt_token_key.export_private_key(encoding='PEM'),
                        }
                    try:
                        backup_content_enc = json.encode(backup_content,
                                                        encryption=enc_mod,
                                                        enc_key=enc_key)
                    except Exception as e:
                        msg = _("Failed to encode key backup: {error}")
                        msg = msg.format(error=e)
                        raise OTPmeException(msg) from e
                    enc_key_encrypted = backup_key_pub.encrypt(enc_key).hex()
                    private_key_backup = {
                                            'enc_mod'               : 'FERNET',
                                            'enc_key'               : enc_key_encrypted,
                                            'private_key_backup'    : backup_content_enc,
                                        }

            # Reset PIV applet and set PIN/PUK.
            reset_status = piv.reset()
            if not reset_status:
                msg = _("Aborted.")
                raise OTPmeException(msg)

            piv.change_pin(old_pin=piv.DEFAULT_PIN, new_pin=token_password)
            piv.change_puk(old_puk=piv.DEFAULT_PUK, new_puk=token_password)

            # Algos come from the actual loaded key objects -- that
            # covers gen (where they match the CLI flags), restore-file
            # and restore-from-server (where the file/server dictates
            # what we actually have). CLI --sign-algo / --encrypt-algo
            # are only consumed in the gen branch.
            sign_key_type = piv.algo_for_public_key(sign_token_key.public_key)
            encrypt_key_type = piv.algo_for_public_key(encrypt_token_key.public_key)

            # Import sign key → 9A, encrypt key → 9D. import_private_key
            # dispatches cert-signature hash per algo and skips the cert
            # entirely for X25519 (X25519 can't self-sign).
            piv.import_private_key(
                private_key=sign_token_key.export_private_key(encoding='PEM'),
                slot=SIGN_SLOT,
                pin=token_password)
            piv.import_private_key(
                private_key=encrypt_token_key.export_private_key(encoding='PEM'),
                slot=ENCRYPT_SLOT,
                pin=token_password)

            # Replace the factory-default management key with a fresh
            # random one, stored PIN-protected on the card. Done after
            # imports so they still authenticate with DEFAULT_MGMT_KEY.
            try:
                piv.protect_management_key(pin=token_password)
            except Exception as e:
                msg = _("Failed to protect management key: {error}")
                msg = msg.format(error=e)
                raise OTPmeException(msg) from e

            sign_public_key = sign_token_key.export_public_key(encoding="PEM")
            encrypt_public_key = encrypt_token_key.export_public_key(encoding="PEM")
            # SSH always uses the sign key.
            ssh_public_key_type, \
            ssh_public_key = sign_token_key.ssh_public_key.decode().split()
            ssh_public_key_type = ssh_public_key_type.split("-")[1]

        if not sign_public_key or not encrypt_public_key:
            msg = _("Cannot continue without sign + encrypt public keys.")
            raise OTPmeException(msg)

        # Derive dot1x secret on the sign slot (deterministic primitive).
        try:
            dot1x_secret = piv.derive_password(challenge="dot1x",
                                    pin=token_password,
                                    slot=SIGN_SLOT,
                                    length=32)
        except Exception as e:
            msg = _("Error deriving dot1x secret: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e

        deploy_args = {}
        deploy_args['sign_public_key'] = sign_public_key
        deploy_args['encrypt_public_key'] = encrypt_public_key
        deploy_args['sign_key_type'] = sign_key_type
        deploy_args['encrypt_key_type'] = encrypt_key_type
        deploy_args['add_user_key'] = add_user_key
        deploy_args['ssh_public_key'] = ssh_public_key
        deploy_args['ssh_public_key_type'] = ssh_public_key_type
        if dot1x_secret:
            deploy_args['dot1x_secret'] = dot1x_secret
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
        except Exception as e:
            msg = _("Error signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise SmartcardAuthFailed(msg) from e
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
        except Exception as e:
            msg = _("Error sending signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise SmartcardAuthFailed(msg) from e
        return signature

    def handle_offline_token_challenge(self, smartcard, password, enc_challenge, **kwargs):
        try:
            enc_pass = smartcard.derive_password(challenge=enc_challenge,
                                                pin=password,
                                                slot="AUTHENTICATION")
        except Exception as e:
            msg = _("Error sending offline token encryption challenge to smartcard: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        return enc_pass

    def handle_offline_challenge(self, smartcard, token, password, enc_challenge, **kwargs):
        try:
            enc_pass = smartcard.derive_password(challenge=enc_challenge,
                                                pin=password,
                                                slot="AUTHENTICATION")
        except Exception as e:
            msg = _("Error sending offline encryption challenge to smartcard: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        return enc_pass

    def get_smartcard_data(self, smartcard, token, password, **kwargs):
        challenge = token.gen_challenge()
        # Sign challenge.
        try:
            signature = smartcard.sign_challenge(slot="AUTHENTICATION",
                                            pin=password,
                                            challenge=challenge)
        except Exception as e:
            msg = _("Error signing challenge with smartcard: {error}")
            msg = msg.format(error=e)
            raise SmartcardAuthFailed(msg) from e
        smartcard_data = {
                        'challenge' : challenge,
                        'signature' : signature,
                        }
        return smartcard_data

    def handle_dot1x(self, smartcard, password, **kwargs):
        try:
            secret = smartcard.derive_password(challenge="dot1x",
                                            pin=password,
                                            slot="AUTHENTICATION")
        except Exception as e:
            msg = _("Error sending offline encryption challenge to smartcard: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        otp = sotp.gen(password_hash=secret)
        return otp

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

    def get_ssh_public_key(self, slot="AUTHENTICATION"):
        public_key = piv.get_public_key(slot=slot)
        ssh_pub = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        ssh_pub = ssh_pub.decode()
        return ssh_pub
