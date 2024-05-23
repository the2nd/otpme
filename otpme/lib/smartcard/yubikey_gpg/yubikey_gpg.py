# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import cli
from otpme.lib import config
from otpme.lib.gpg import utils as gpg
#from otpme.lib.messages import error_message
from otpme.lib.smartcard.yubikey import deploy
from otpme.lib.smartcard.yubikey.yubikey import Yubikey

from otpme.lib. exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    config.register_smartcard_type("yubikey-gpg", YubikeygpgClientHandler, YubikeygpgServerHandler)

class YubikeygpgClientHandler(object):
    deploy_commmand_map = {
            'yubikey-gpg' : {
                            '_cmd_usage_help' : 'Usage: otpme-token deploy -t {token_type} [-d -b <backup_file> -r <restore_file>] [token]',
                            'cmd'   :   '-t ::token_type:: -n :no_token_write=True: -b :gpg_backup_file: -r :gpg_restore_file: -d :debug=True: [|object|]',
                            '_help' :   {
                                            'cmd'                   : 'initialize yubikey GPG applet',
                                            '-b <file>'             : 'write GPG backup to file (default /dev/shm/User_Name.gpg)',
                                            '-r <file>'             : 'restore GPG configuration from backup file',
                                            '-n'                    : 'do NOT reconfigure yubikey, just add token data to OTPme token',
                                            '-d'                    : 'enable token related debug output',
                                        },
                            },

        }

    def __init__(self, sc_type, token_rel_path, token_options=None,
        message_method=print, error_message_method=print):
        self.smartcard_type = sc_type
        self.token_rel_path = token_rel_path
        self.token_options = token_options
        self.message_method = message_method
        self.error_message_method = error_message_method
        # FIXME: pam message methods from pam.py does not work with sddm
        #       and adds some strange delay.
        self.message_method = print
        self.error_message_method = print
        self.logger = config.logger

    def handle_deploy(self, command_handler, no_token_write=False, **kwargs):
        # Get command syntax.
        try:
            command_syntax = self.deploy_commmand_map[self.smartcard_type]['cmd']
        except:
            msg = (_("Unknown token type: %s") % self.smartcard_type)
            raise OTPmeException(msg)

        # Set token command help.
        token_command_map = {'token' : self.deploy_commmand_map}

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_handler.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                exception = command_handler.get_help(command_map=token_command_map)
                raise ShowHelp(exception)
            elif str(e) != "":
                msg = str(e)
                exception = command_handler.get_help(message=msg,
                                            command_map=token_command_map)
                raise ShowHelp(exception)

        # Handle deployment of yubikey GPG applet (token type ssh in OTPme)
        ssh_public_key = None
        if no_token_write:
            # Try to get SSH public key of already initialized yubikey.
            ssh_public_key = gpg.get_ssh_public_key()
        else:
            try:
                gpg_backup_file = local_command_args['gpg_backup_file']
            except:
                gpg_backup_file = None

            try:
                gpg_restore_file = local_command_args['gpg_restore_file']
            except:
                gpg_restore_file = None

            if gpg_restore_file and not os.path.exists(gpg_restore_file):
                msg = (_("Restore file does not exist: %s")
                        % gpg_restore_file)
                raise OTPmeException(msg)

            # We cannot backup and restore at the same time.
            if gpg_restore_file and gpg_backup_file:
                return self.get_help(command="deploy",
                                    subcommand=token_type,
                                    command_map=token_command_map)

            # Start yubikey deploy.
            ssh_public_key = deploy.gpg_applet(gpg_backup_file,
                                                gpg_restore_file)

        # Without public key we cannot continue.
        if not ssh_public_key:
            msg = (_("Cannot continue without SSH public key."))
            raise OTPmeException(msg)
        # Add SSH public key to deployment args.
        deploy_args['public_key'] = ssh_public_key

        return deploy_args

    def handle_preauth(self, **kwargs):
        smartcard_data = {}
        return smartcard_data

    def handle_authentication(self, **kwargs):
        return None

    def handle_offline_token_challenge(self, **kwargs):
        return None

    def handle_offline_challenge(self, **kwargs):
        return None

    def get_smartcard_data(self, **kwargs):
        smartcard_data = {}
        return smartcard_data

class YubikeygpgServerHandler(object):
    def handle_preauth(self, token):
        token_options = {
                    'token_type'        : token.token_type,
                    'smartcard_id'      : token.smartcard_id,
                    'challenge'         : token.hmac_challenge,
                    'otp_len'           : token.otp_len,
                    'slot'              : token.slot,
                    'pass_required'     : True,
                    }
        return token_options

    def prepare_authentication(self, smartcard_data):
        return smartcard_data

class Yubikeygpg(Yubikey):
    """ Class for yubikey HMAC tokens. """
    # Set supported auth types
    otpme_auth_types = [ "yubikey-gpg" ]

