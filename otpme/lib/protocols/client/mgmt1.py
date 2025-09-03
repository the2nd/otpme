# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.encoding.base import encode
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-mgmt-1.0"

def register():
    config.register_otpme_protocol("mgmtd", PROTOCOL_VERSION)

class OTPmeMgmtP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-mgmt-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "mgmtd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeMgmtP1, self).__init__(self.daemon, **kwargs)

    def send_command(self, command, command_args={}, client_type="RAPI"):
        """ Send command to mgmtd. """
        args = {}
        # Add given command args.
        for opt in command_args:
            args[opt] = command_args[opt]
        # Indicates a remote API call.
        args['_caller'] = client_type
        # Set default args but do not override exiting args.
        if not 'verbose_level' in args:
            args['verbose_level'] = config.verbose_level
        if not 'force' in args:
            args['force'] = config.force
        args['job_timeout'] = config.job_timeout
        args['lock_timeout'] = config.lock_timeout
        args['lock_wait_timeout'] = config.lock_wait_timeout
        args['lock_reload_on_change'] = config.ignore_changed_objects

        if client_type == "CLIENT":
            self.print_messages = True
        else:
            self.print_messages = False

        # Send command to daemon.
        try:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send(command=command,
                                            command_args=args,
                                            handle_response=True)
        except Exception as e:
            config.raise_exception()
            status = False
            reply = str(e)

        if status is False:
            config.raise_exception()
            raise OTPmeException(reply)

        ## FIXME: We need a RAPI and better reply format etc.!!
        #if isinstance(reply, list):
        #    # RAPI connection may return list with all callback messages. The
        #    # result is always the last message. Previous messages may be
        #    # notifications that normally would be printed to the screen (e.g.
        #    # token deleted)
        #    reply = reply[-1]

        return status, reply

    def search(self, command):
        """ Search OTPme objects. """
        # Encode search command.
        command_base64 = encode("\0".join(command), "base64")
        # Build daemon command.
        command_args = {
                        'subcommand'        :'search',
                        'search_command'    :command_base64,
                        }
        #daemon_command = "backend search %s" % command_base64
        daemon_command = "backend"
        # Send command
        status, result = self.send_command(daemon_command, command_args)
        return result

    def get_name_by_uuid(self, uuid):
        """ Resolve UUID to object name. """
        search_command = [
                        'attribute=uuid',
                        'value=%s' % uuid,
                        'return_type=name'
                        ]
        return self.search(search_command)

    def get_uuid_by_oid(self, object_id):
        """ Resolve OID to UUID. """
        # Build daemon command.
        command_args = {
                        "subcommand"    : 'get_uuid',
                        "object_id"     : object_id,
                        }
        daemon_command = "backend"
        # Send command
        status, x_uuid = self.send_command(daemon_command, command_args)
        return x_uuid

    def get_role_users(self, role_name, return_type="name"):
        """ Get all users that have a token assigned to role. """
        self.logger.debug("Requesting role member users: %s" % role_name)
        command = "role"
        command_args = {
                        'subcommand'        : 'list_users',
                        'object_identifier' : role_name,
                        'return_type'       : return_type,
                        }
        try:
            status, reply = self.send_command(command, command_args)
            if reply and "," in reply:
                users = reply.split(",")
            else:
                users = [reply]
        except Exception as e:
            msg = (_("Unable to get role member users: %s") % e)
            raise OTPmeException(msg)
        return users

    def get_user_key(self, username=None, user_uuid=None, private=False):
        """ Get users RSA key. """
        if not username and not user_uuid:
            msg = (_("Need 'username' or 'user_uuid'."))
            raise OTPmeException(msg)
        self.logger.debug("Requesting users RSA key...")
        command = "user"
        command_args = {}
        command_args['subcommand'] = "dump_key"
        command_args['object_identifier'] = username
        if private:
            command_args['private'] = True
        try:
            status, user_key = self.send_command(command, command_args)
        except Exception as e:
            msg = (_("Unable to get users RSA key: %s") % e)
            raise OTPmeException(msg)
        return user_key

    def get_user_key_mode(self, username):
        """ Get key key mode (client or server) for the given user. """
        self.logger.debug("Requesting users key mode...")
        command = "user"
        command_args = {
                        'subcommand'        : 'get_key_mode',
                        'object_identifier' : username,
                        }
        try:
            status, key_mode = self.send_command(command, command_args)
        except Exception as e:
            msg = (_("Unable to get users key mode: %s") % e)
            raise OTPmeException(msg)
        if not key_mode:
            key_mode = None
        return key_mode

    def get_user_key_script_path(self, username):
        """ Get users key script path and options. """
        self.logger.debug("Selecting user key script...")
        key_script_path = None
        key_script_opts = None
        command = "user"
        command_args = {}
        command_args['object_identifier'] = username
        command_args['subcommand'] = "get_key_script"
        command_args['return_type'] = "path"
        try:
            status, reply = self.send_command(command, command_args)
            if reply:
                key_script_path = reply[0][0]
                key_script_opts = reply[0][1]
        except Exception as e:
            msg = (_("Unable to get user key script name: %s") % e)
            raise OTPmeException(msg)
        return key_script_path, key_script_opts

    def get_user_ssh_script_path(self, username):
        """ Get users SSH agent script name and options. """
        self.logger.debug("Selecting user SSH agent script...")
        ssh_script_path = None
        ssh_script_opts = None
        command = "user"
        command_args = {}
        command_args['subcommand'] = "get_ssh_script"
        command_args['object_identifier'] = username
        command_args['return_type'] = "name"
        try:
            status, reply = self.send_command(command, command_args)
            if reply:
                ssh_script_path = reply.split(" ")[0]
                ssh_script_opts = " ".join(reply.split(" ")[1:])
        except Exception as e:
            msg = (_("Unable to get user SSH agent script name: %s"))
            raise OTPmeException(msg)
        return ssh_script_path, ssh_script_opts

    def get_script(self, script_path):
        """ Get script. """
        self.logger.debug("Requesting script: %s" % script_path)
        command = "script"
        command_args = {}
        command_args['subcommand'] = "dump"
        command_args['object_identifier'] = script_path
        try:
            status, script = self.send_command(command, command_args)
        except Exception as e:
            msg = (_("Unable to get script: %s") %e)
            raise OTPmeException(msg)
        return script

    def get_script_sign(self, script_path, username=None, user_uuid=None):
        """ Get script signature(s). """
        self.logger.debug("Requesting script signatures: %s" % script_path)
        command = "script"
        command_args = {}
        command_args['subcommand'] = "get_sign"
        command_args['object_identifier'] = script_path
        script_signatures = []
        if username:
            command_args['username'] = username
        if user_uuid:
            command_args['user_uuid'] = user_uuid
        try:
            status, script_signatures = self.send_command(command,
                                        command_args=command_args)
        except Exception as e:
            msg = (_("Unable to get script signatures: %s") % e)
            raise OTPmeException(msg)
        return script_signatures

    def set_user_key(self, username, key, private=False, force=None):
        """ Set users RSA key. """
        command = "user"
        command_args = {}
        command_args['object_identifier'] = username
        if private:
            command_args['subcommand'] = "private_key"
            command_args['private_key'] = key
            key_type = "private"
        else:
            command_args['subcommand'] = "public_key"
            command_args['public_key'] = key
            key_type = "public"

        # set_user_key() needs an force option independent of config.force
        # to allow forcing when called from "key_pass" command.
        if force is not None:
            command_args['force'] = force

        self.logger.debug("Sending %s key to server..." % key_type)
        try:
            self.send_command(command, command_args)
        except Exception as e:
            msg = (_("Unable to set users %s key: %s") % (key_type, e))
            raise OTPmeException(msg)
