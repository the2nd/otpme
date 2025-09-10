# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import glob
import pprint
import datetime
#from prettytable import ALL
from prettytable import FRAME
from prettytable import NONE
from prettytable import PrettyTable

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import cli
from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_pass
from otpme.lib import init_otpme
from otpme.lib import connections
from otpme.lib.help import get_help
from otpme.lib.messages import message
from otpme.lib.encoding.base import encode
from otpme.lib.messages import error_message
from otpme.lib.register import register_module
from otpme.lib.debug import add_debug_decorators
from otpme.lib.compression.base import get_uncompressed_size

from otpme.lib.exceptions import *

add_debug_decorators()

class CommandHandler(object):
    """ Handle OTPme commands. """
    def __init__(self, interactive=True):
        from otpme.lib.help import command_map
        #register_module("otpme.lib.connections")
        # Get logger.
        self.logger = config.logger
        self.mgmt_client = None
        self.command_map = command_map
        self.command = None
        self.subcommand = None
        self.help_command = None
        self.command_line = []
        # May hold users private key password.
        self.user_key_pass = None
        # May hold user password.
        self.user_password = None
        # May hold a password to decrypt some AES data (e.g. users private RSA key)
        self.user_aes_pass = None
        self.init_done = False
        self.interactive = interactive

    def __getattr__(self, name):
        """ Forward method call to OTPmeMgmtClient(). """
        try:
            attr = self.__getattribute__(name)
            return attr
        except AttributeError:
            pass
        def handler_function(*args,**kwargs):
            mgmt_client = self.get_mgmt_client()
            try:
                method = getattr(mgmt_client, name)
            except:
                msg = "Unknown method: %s: %s" % (mgmt_client.__class__, name)
                raise OTPmeException(msg)
            return method(*args, **kwargs)
        return handler_function

    def init(self, **kwargs):
        if self.init_done:
            return
        if not os.path.exists(config.uuid_file):
            return
        register_module('otpme.lib.trash')
        init_otpme(**kwargs)
        self.init_done = True

    def get_help(self, message="", command=None,
        subcommand=None, command_map=None):
        """ Handle help stuff. """
        if not command:
            command = self.help_command
        if not subcommand:
            subcommand = self.subcommand
        if not command_map:
            command_map = self.command_map

        help_msg = get_help(command=command,
                            subcommand=subcommand,
                            command_map=command_map)
        if message:
            help_msg = "%s\n\n%s" % (help_msg, message)

        return help_msg

    def get_mgmt_client(self, username=None, password=None):
        """ Get OTPme management client connection. """
        from otpme.lib.classes.mgmt_client import OTPmeMgmtClient
        # In API mode no login is required.
        if not config.use_api and config.use_agent:
            login_status = self.get_login_status()
            if not login_status:
                raise OTPmeException("Not logged in.")

        # Return existing mgmt client.
        if self.mgmt_client:
            return self.mgmt_client

        login_data = {
                    config.realm : {
                                'username' : username,
                                'password' : password,
                                },
                    }
        self.mgmt_client = OTPmeMgmtClient(login_data=login_data,
                                        interactive=self.interactive,
                                        aes_pass=self.user_aes_pass)
        return self.mgmt_client

    def get_command_syntax(self, command, subcommand):
        """ Get command syntax. """
        try:
            command_syntax = self.command_map[command]['main'][subcommand]['cmd']
        except KeyError:
            mod_name = config.cli_object_type
            command_syntax = self.command_map[command][mod_name][subcommand]['cmd']
        return command_syntax

    def send_command(self, daemon="mgmtd", socket_uri=None, realm=config.realm,
        site=config.site, command=None, subcommand=None, command_line=None,
        command_args=None, username=None, password=None, aes_pass=None,
        parse_command_syntax=True, object_list=[], interactive=None,
        timeout=30, client_type="CLIENT"):
        """ Send the given command to the given daemon. """
        if interactive is None:
            interactive = self.interactive

        if daemon == "hostd":
            daemon_conn = connections.get("hostd", interactive=interactive)
            status, \
            status_code, \
            reply, \
            binary_data = daemon_conn.send(command, command_args=command_args)
            return reply

        if not command:
            command = self.command
        if not subcommand:
            subcommand = self.subcommand
        if not command_line:
            command_line = self.command_line
        if not command_args:
            command_args = self.command_args
        if not password:
            password = self.user_password
        if not aes_pass:
            aes_pass = self.user_aes_pass

        # FIXME: this should not be needed after we have migrated otpme.py to
        #        to be a Class().
        # Make sure we remove old job ID.
        try:
            command_args.pop('job_uuid')
        except:
            pass

        if parse_command_syntax:
            if not command in self.command_map:
                raise OTPmeException(_("Unknown command: %s") % command)

            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except Exception as e:
                help_text = self.get_help(_("Unknown command: %s") % subcommand)
                raise OTPmeException(help_text)

            # Parse command line.
            try:
                object_cmd, \
                object_required, \
                object_list, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=command_args)
            except Exception as e:
                config.raise_exception()
                if str(e) == "help":
                    help_text = self.get_help()
                    raise OTPmeException(help_text)
                elif str(e) != "":
                    help_text = self.get_help(str(e))
                    raise OTPmeException(help_text)

            # Get default object if needed.
            if object_cmd and object_required and not object_list:
                if self.get_default_object:
                    object_list = self.get_default_object()
                else:
                    help_text = self.get_help(_("Error: Please give %s") % command)
                    raise OTPmeException(help_text)

        if not isinstance(object_list, list):
            object_list = [object_list]

        if daemon == "mgmtd":
            if config.use_api:
                username = config.system_user()
            # Get management client.
            mgmt_client = self.get_mgmt_client(username, password)
            status, \
            reply = mgmt_client.send(command=command,
                                    subcommand=subcommand,
                                    command_args=command_args,
                                    object_list=object_list,
                                    client_type=client_type)
        elif daemon == "authd":
            # Get connection to authd.
            if realm is None:
                realm = config.realm
            if site is None:
                site = config.site

            conn_kwargs = {}
            if socket_uri is not None:
                conn_kwargs = {}
                conn_kwargs['use_ssl'] = False
                conn_kwargs['auto_auth'] = False
                conn_kwargs['timeout'] = timeout
                conn_kwargs['auto_preauth'] = False
                conn_kwargs['local_socket'] = True
                conn_kwargs['handle_host_auth'] = False
                conn_kwargs['handle_user_auth'] = False
                conn_kwargs['encrypt_session'] = False

            if username:
                conn_kwargs['username'] = username

            daemon_conn = connections.get("authd",
                                        realm=realm,
                                        site=site,
                                        socket_uri=socket_uri,
                                        interactive=interactive,
                                        **conn_kwargs)
            # Send auth request.
            self.logger.debug("Sending authentication request...")
            status, \
            status_code, \
            reply, \
            binary_data = daemon_conn.send(command, command_args)

            log_method = self.logger.warning
            if status:
                log_method = self.logger.debug
            auth_message = reply['message']
            msg = "Received authentication reply: %s" % auth_message
            log_method(msg)

        elif daemon == "syncd":
            # Get connection to syncd.
            daemon_conn = connections.get("syncd",
                                        realm=realm,
                                        site=site,
                                        interactive=interactive)
            # Send request.
            self.logger.debug("Sending request to syncd...")
            status, \
            status_code, \
            reply, \
            binary_data = daemon_conn.send(command, command_args)

            self.logger.debug("Received reply: %s" % reply)

        # None means user aborted the action.
        if status is None:
            message= (_("Command aborted"))
            if reply:
                message = (_("Command aborted: %s" % reply))
            raise OTPmeException(message)

        if status is False:
            if isinstance(reply, dict):
                reply = pprint.pformat(reply)
            if isinstance(reply, list):
                reply = "\n".join(reply)
            if config.debug_enabled:
                msg = ("Command failed: %s %s %s"
                            % (command,
                            command,
                            command_args))
                reply = msg + "\n" + reply
            raise OTPmeException(reply)

        return reply

    def handle_command(self, command, command_line, client_type="CLIENT"):
        """ Handle given command. """
        register_module("otpme.lib.protocols.otpme_client")
        if config.use_api:
            # We need to register controld to get e.g. config.daemon_shutdown.
            register_module("otpme.lib.daemon.controld")
            register_module("otpme.lib.protocols.server.mgmt1")
        # Add newline to command output?
        self.newline = True
        # Command args we send to the server.
        self.command_args = {}
        # Can hold function to get default object if none was given.
        self.get_default_object = None

        msg = "Processing command: %s: %s" % (command, command_line)
        self.logger.debug(msg)

        try:
            need_command = self.command_map[command][config.cli_object_type]['_need_command']
        except KeyError:
            try:
                need_command = self.command_map[command]['main']['_need_command']
            except KeyError:
                need_command = False

        subcommand = None
        if need_command:
            # Try to get command name from command line.
            try:
                subcommand = command_line.pop(0)
            except:
                pass

        # Set commands to be re-used in other methods.
        self.command = command
        if self.help_command is None:
            self.help_command = command
        self.subcommand = subcommand
        self.command_line = command_line

        # Start get-auth-keys before doing other stuff (e.g. get login user).
        if command == "get-authorized-keys":
            try:
                username = command_line[0]
            except:
                return self.get_help()
            return self.get_authorized_keys(username)

        if command == "controld":
            register_module('otpme.lib.daemon.controld')
            return self.handle_daemon_command(command_line, command, subcommand)

        if command == "agent":
            return self.handle_agent_command(subcommand)

        if command == "tool" and subcommand == "detect_smartcard":
            return self.handle_smartcard_detection(command, subcommand)

        if command == "mount":
            return self.handle_mount(command, subcommand)

        # Get password from stdin if --stdin-pass was given.
        if config.read_stdin_pass:
            self.user_password = config.stdin_pass
        else:
            self.user_password = None

        # Init realm.
        if command == "realm" and subcommand == "init":
            from otpme.lib import multiprocessing
            from otpme.lib.register import register_modules
            # Register modules.
            register_modules()
            # We need to do a realm init in API mode.
            config.use_api = True
            # Mark ongoing realm init.
            config.realm_init = True
            # Disable locking on realm init.
            config.locking_enabled = False
            # Make sure index is ready.
            _index = config.get_index_module()
            _index.command("init")
            if not _index.status():
                _index.start()
            # Make sure cache is started.
            _cache = config.get_cache_module()
            if not _cache.status():
                _cache.start()
            init_otpme()
            # Create shared dicts/lists.
            multiprocessing.create_shared_objects()
            # Enable cache.
            cache.init()
            cache.enable()
            return self.send_command(daemon="mgmtd")

        # Init backend in API mode.
        if config.use_api:
            _index = config.get_index_module()
            if _index.need_start:
                if not _index.status():
                    msg = "Index not started."
                    raise OTPmeException(msg)
            _cache = config.get_cache_module()
            if not _cache.status():
                msg = "Cache not started."
                raise OTPmeException(msg)

            #from otpme.lib.register import register_modules
            ## Register modules.
            #register_modules()
            register_module('otpme.lib.host')
            register_module('otpme.lib.cache')
            register_module('otpme.lib.multiprocessing')
            register_module('otpme.lib.daemon.clusterd')
            # Enable cache.
            cache.init()
            cache.enable()

            if not (command == "realm" and subcommand == "init"):
                self.init(use_backend=True)

            if command == "token":
                register_module('otpme.lib.classes.token')
                #register_module('otpme.lib.classes.role')
                register_module('otpme.lib.token')
                register_module('otpme.lib.cli.token')
            if command == "realm":
                register_module("otpme.lib.classes.realm")
                register_module("otpme.lib.cli.realm")
            if command == "site":
                register_module("otpme.lib.classes.site")
                register_module("otpme.lib.cli.site")
            if command == "unit":
                register_module("otpme.lib.classes.unit")
                register_module("otpme.lib.cli.unit")
            if command == "ca":
                register_module("otpme.lib.classes.ca")
                register_module("otpme.lib.cli.ca")
            if command == "node":
                register_module("otpme.lib.classes.node")
                register_module("otpme.lib.cli.node")
            if command == "host":
                register_module("otpme.lib.classes.host")
                register_module("otpme.lib.cli.host")
            if command == "user":
                register_module("otpme.lib.classes.user")
                register_module("otpme.lib.cli.user")
            if command == "group":
                register_module("otpme.lib.classes.group")
                register_module("otpme.lib.cli.group")
            if command == "client":
                register_module("otpme.lib.classes.client")
                register_module("otpme.lib.cli.client")
            if command == "role":
                register_module("otpme.lib.classes.role")
                register_module("otpme.lib.cli.role")
            if command == "policy":
                from otpme.lib.register import register_modules
                # Register modules.
                register_modules()
                #register_module("otpme.lib.classes.policy")
                #register_module("otpme.lib.cli.policy")
            if command == "accessgroup":
                register_module("otpme.lib.classes.accessgroup")
                register_module("otpme.lib.cli.accessgroup")
            if command == "resolver":
                register_module("otpme.lib.classes.resolver")
                register_module("otpme.lib.cli.resolver")
            if command == "dictionary":
                register_module("otpme.lib.classes.dictionary")
                register_module("otpme.lib.cli.dictionary")
            if command == "share":
                register_module('otpme.lib.classes.share')
                register_module('otpme.lib.cli.share')
            if command == "pool":
                register_module('otpme.lib.classes.pool')
                register_module('otpme.lib.cli.pool')

            if subcommand == "show":
                register_module("otpme.lib.cli")

            if subcommand == "config":
                register_module('otpme.lib.token.fido2.fido2')

            # Handle post object registration stuff.
            config.handle_post_object_registration()
            # Handle post base object registration stuff.
            config.handle_post_base_object_registration()

            # Re-init backend after module registration.
            init_file_dir_perms = False
            if config.realm_init:
                init_file_dir_perms = True
            backend.init(init_file_dir_perms=init_file_dir_perms)

        if self.command == "auth":
            return self.handle_auth_command(command, subcommand, command_line)

        if command == "cluster":
            if subcommand == "status":
                register_module("otpme.lib.daemon.controld")
                return self.handle_cluster_status(command, subcommand)

            if subcommand == "required_votes":
                try:
                    command_syntax = self.get_command_syntax(command, subcommand)
                except:
                    return self.get_help(_("Unknown command: %s") % subcommand)
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
                try:
                    required_votes = command_args['required_votes']
                except KeyError:
                    return self.get_help(_("Missing required votes: %s") % subcommand)
                return self.handle_required_votes(required_votes)

            if subcommand == "master_failover":
                try:
                    command_syntax = self.get_command_syntax(command, subcommand)
                except:
                    return self.get_help(_("Unknown command: %s") % subcommand)
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
                try:
                    random_node = command_args['random_node']
                except KeyError:
                    random_node = False
                try:
                    new_master = command_args['new_master_node']
                except KeyError:
                    new_master = False
                try:
                    wait = command_args['wait']
                except KeyError:
                    wait = False
                return self.handle_master_failover(new_master=new_master,
                                                    random_node=random_node,
                                                    wait=wait)

        # For some commands make sure debug log goes to stderr and not to
        # stdout. (e.g. a signature)
        if command == "tool" or command == "user":
            if subcommand == "sign" \
            or subcommand == "verify" \
            or subcommand == "encrypt" \
            or subcommand == "decrypt":
                self.logger = config.setup_logger(stderr_log=True,
                                        existing_logger=config.logger)

        if command == "script":
            if subcommand == "sign" \
            or subcommand == "verify":
                from otpme.lib.register import register_modules
                register_modules()
                #self.init(use_backend=True)

        if command == "tool":
            return self.handle_tool_command(command, subcommand, command_line)

        if command == "trash":
            return self.handle_trash_command(command, subcommand, command_line)

        if command == "pinentry":
            self.start_pinentry()
            return ""

        if config.cli_object_type != "main":
            object_type = "%s_type" % command
            self.command_args[object_type] = config.cli_object_type

        if command == "user" and subcommand == "dump_key":
            return self.handle_user_dump_key_command(command, subcommand)

        # Resync login token if none is given.
        if command == "token" and subcommand == "resync":
            return self.handle_token_resync_command()

        if command == "token" and subcommand == "deploy":
            return self.handle_token_deploy_command()

        # When changing password of users RSA key we may need to read
        # old and new password from stdin.
        if command == "user" and subcommand == "key_pass":
            return self.handle_user_key_pass_command()

        # When editing a script we need to dump it to a local file first.
        if command == "script" and subcommand == "edit":
            return self.handle_script_edit_command()

        # When running a script we need to dump it to a local file first.
        if command == "script" and subcommand == "run":
            return self.handle_script_run_command(command, subcommand)

        # When generating users RSA keys on server side we may have to read
        # key password from stdin.
        if command == "user" and subcommand == "gen_keys" \
        and "--server" in self.command_line:
            if config.read_stdin_pass:
                msg = (_("--stdin-pass option conflicts with global option."))
                raise OTPmeException(msg)
            if "--stdin-pass" in self.command_line:
                # Get password from stdin if given.
                try:
                    # When a user is configured for key_mode=server the private
                    # key might be encrypted with a passphrase (AES).
                    self.user_aes_pass = stuff.read_pass_from_stdin()
                except:
                    pass

        # When generating users RSA keys on server side we may have to read
        # key password from stdin.
        if command == "user" and subcommand == "import_key":
            if config.read_stdin_pass:
                msg = (_("--stdin-key option conflicts with global --stdin-pass option."))
                raise OTPmeException(msg)
            private_key = None
            if "--stdin-key" in self.command_line:
                # Get private key from stdin if given.
                try:
                    private_key = sys.stdin.read()
                except Exception as e:
                    msg = "Failed to read private key from stdin: %s" % e
                    raise OTPmeException(msg)
                if "--server" in self.command_line:
                    self.command_args = { 'private_key' : private_key }
            if "--server" not in self.command_line:
                return self.handle_user_key_import(command, subcommand, private_key)

        # When signing data and the signing key is on server we may have to read
        # the key password from stdin.
        if command == "user" and subcommand == "sign_data":
            if "--stdin-pass" in self.command_line:
                if "--stdin-data" in self.command_line:
                    msg = (_("--stdin-pass option conflicts with --stdin-data option."))
                    raise OTPmeException(msg)
                if config.read_stdin_pass:
                    msg = (_("--stdin-pass option conflicts with global option."))
                    raise OTPmeException(msg)
                # Get password from stdin if given.
                try:
                    # When a user is configured for key_mode=server the private
                    # key might be encrypted with a passphrase (AES).
                    self.user_aes_pass = stuff.read_pass_from_stdin()
                except:
                    pass
            if "--stdin-data" in self.command_line:
                # Get data to sign from stdin if given.
                try:
                    data = sys.stdin.read()
                except Exception as e:
                    msg = "Failed to read sign data from stdin: %s" % e
                    raise OTPmeException(msg)
                self.command_args = {'data' : data}

        # Generating users certificate needs some local action (e.g.
        # calling key script) which is done below.
        if command == "user" and subcommand == "gen_cert":
            return self.handle_user_gen_cert_command(command, subcommand)

        # When adding a script we need to send the given script base64 encoded.
        if command == "script" and subcommand == "add":
            return self.handle_script_add_command(command, subcommand)

        # When signing data with a server side RSA key we may need to read the
        # key password from stdin.
        if command == "user" \
        and subcommand == "sign" \
        or subcommand == "encrypt" \
        or subcommand == "decrypt":
            if "--stdin-pass" in self.command_line:
                if config.read_stdin_pass:
                    msg = (_("--stdin-pass option conflicts with global option."))
                    raise OTPmeException(msg)
                if "--stdin-data" in self.command_line:
                    msg = (_("--stdin-pass option conflicts with --stdin-data option."))
                    raise OTPmeException(msg)
                # Get password from stdin if given.
                try:
                    # When a user is configured for key_mode=server the private
                    # key might be encrypted with a passphrase (AES).
                    self.user_aes_pass = stuff.read_pass_from_stdin()
                except:
                    pass
            if "--stdin-data" in self.command_line:
                # Get data to sign from stdin if given.
                try:
                    data = sys.stdin.read()
                except Exception as e:
                    msg = "Failed to read data from stdin: %s" % e
                    raise OTPmeException(msg)
                self.command_args = {'data' : data}

        if command == "dictionary" and subcommand == "word_import":
            self.handle_dictionary_word_import_command(command, subcommand)

        if command == "dictionary" and subcommand == "word_learning":
            self.handle_dictionary_word_learning_command(command, subcommand)

        # Rewrite "token add" command to "user add_token". This is a workaround
        # to be backward compatible with OTPme commands before v0.3 handling
        # this in mgmtd would make things much more complicated.
        if command == "token" and (subcommand == "add" or subcommand == "del"):
            return self.handle_token_add_del_command(command, subcommand)

        # Send command.
        try:
            result = self.send_command(daemon="mgmtd",
                                    client_type=client_type)
            status = True
        except OTPmeException as e:
            status = False
            result = str(e)
            config.raise_exception()

        # Do not add newline when exporting data.
        if command == "export" \
        or command == "dump_cert" \
        or command == "dump_key" \
        or command == "dump_ca_chain" \
        or command == "dump_ca_data" \
        or command == "dump_crl":
            if status:
                self.newline = False

        # Make sure no additional newline is printed at end of script dump.
        if command == "script" and subcommand == "dump":
            if status:
                self.newline = False

        if not status:
            config.raise_exception()
            raise OTPmeException(result)

        # Make sure we sync objects after add/del.
        if subcommand == "add" or subcommand == "del":
            # We sync objects on non-node hosts on object add/del.
            #init_otpme()
            self.init()
            if config.host_data['type'] == "host":
                self.start_sync(sync_type="objects")

        return result

    def handle_agent_command(self, subcommand):
        """ Handle agent command. """
        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        if subcommand == "start":
            otpme_agent.start()
            return ""

        if subcommand == "stop":
            if not otpme_agent.stop():
                raise OTPmeException()
            return ""

        if subcommand == "kill":
            if not otpme_agent.kill():
                raise OTPmeException()
            return ""

        if subcommand == "restart":
            otpme_agent.restart()
            return ""

        if subcommand == "reload":
            otpme_agent.reload()
            return ""

        if subcommand == "status":
            if not otpme_agent.status()[0]:
                raise OTPmeException()
            return ""

        return self.get_help(_("Unknown command: %s") % subcommand)

    def handle_daemon_command(self, command_line, command, subcommand):
        """ Handle daemon command. """
        from otpme.lib.daemon.controld import ControlDaemon
        control_daemon = ControlDaemon(config.controld_pidfile)
        ## Init cache.
        #cache.init()
        #cache.enable()

        if subcommand == "start":
            control_daemon.start()
            return ""

        if subcommand == "stop":
            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args=self.command_args)
            try:
                kill = command_args['kill']
            except:
                kill = False

            try:
                timeout = int(command_args['timeout'])
            except:
                timeout = 60

            if not control_daemon.stop(timeout=timeout, kill=kill):
                raise OTPmeException()
            return ""

        if subcommand == "restart":
            control_daemon.restart()
            return ""

        if subcommand == "reload":
            control_daemon.reload()
            return ""

        if subcommand == "status":
            if not control_daemon.status()[0]:
                raise OTPmeException()
            return ""

        return self.get_help(_("Unknown command: %s") % subcommand)

    def do_backup(self, backup_dir):
        from otpme.lib import backup
        from otpme.lib import backend
        from otpme.lib import filetools
        self.init()
        backend.init()
        def get_backup_filename(object_id):
            object_type = object_id.object_type
            backup_attributes = config.get_backup_attributes(object_type)
            backup_filename = []
            for x in backup_attributes:
                x_attr = getattr(object_id, x)
                x_attr = x_attr.replace("/", "+")
                backup_filename.append(x_attr)
            backup_filename = "+".join(backup_filename)
            return backup_filename

        if not os.path.exists(backup_dir):
            os.mkdir(backup_dir)

        backup_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        backup_revision_dir = os.path.join(backup_dir, backup_time)
        if not os.path.exists(backup_revision_dir):
            os.mkdir(backup_revision_dir)

        for object_type in config.object_add_order:
            result = backend.search(object_type=object_type,
                                    attribute="uuid",
                                    value="*",
                                    return_type="oid")
            backup_dir = os.path.join(backup_revision_dir, object_type)
            if not os.path.exists(backup_dir):
                os.mkdir(backup_dir)
            for x_oid in result:
                backup_file_name = get_backup_filename(x_oid)
                backup_file_name = "%s.json" % backup_file_name
                backup_file = os.path.join(backup_dir, backup_file_name)
                msg = "Backing up: %s" % x_oid
                print(msg)
                try:
                    backup_data = backup.backup_object(x_oid)
                except Exception as e:
                    msg = "Failed to backup object: %s: %s" % (x_oid, e)
                    print(msg)
                filetools.create_file(path=backup_file, content=backup_data)

    def full_restore(self, restore_dir):
        from otpme.lib import filetools
        _index = config.get_index_module()
        if not _index.is_available():
            _index.command("init")
        backend.init(init_file_dir_perms=True)
        failed_restores = []
        for object_type in config.object_add_order:
            x_restore_order = {}
            x_restore_dir = os.path.join(restore_dir, object_type)
            for x_filename in sorted(os.listdir(x_restore_dir)):
                x_file = os.path.join(x_restore_dir, x_filename)
                file_content = filetools.read_file(x_file)
                object_data = json.loads(file_content)
                x_oid = object_data['object_id']
                x_oid = oid.get(x_oid)
                x_oc = object_data['object_config']
                x_uuid = object_data['object_uuid']
                x_last_used = object_data['last_used']
                x_path_len = len(x_oid.path.split("/"))
                x_restore_order[x_oid] = {}
                x_restore_order[x_oid]['object_uuid'] = x_uuid
                x_restore_order[x_oid]['object_config'] = x_oc
                x_restore_order[x_oid]['path_len'] = x_path_len
                x_restore_order[x_oid]['last_used'] = x_last_used

            x_sort = lambda x: x_restore_order[x]['path_len']
            x_restore_order_sorted = sorted(x_restore_order, key=x_sort)
            for x_oid in x_restore_order_sorted:
                msg = "Restoring: %s" % x_oid
                print(msg)
                x_oc = x_restore_order[x_oid]['object_config']
                x_uuid = x_restore_order[x_oid]['object_uuid']
                x_last_used = x_restore_order[x_oid]['last_used']
                try:
                    backend.write_config(object_id=x_oid,
                                        object_config=x_oc,
                                        full_index_update=True,
                                        full_data_update=True,
                                        encrypt=False)
                except Exception as e:
                    msg = "Failed to restore object: %s: %s" % (x_oid, e)
                    print(msg)
                    failed_restores.append(msg)
                else:
                    backend.set_last_used(x_oid.object_type, x_uuid, x_last_used)
        msg = "Creating DB indexes..."
        print(msg)
        _index.command("create_db_indices")
        for x in failed_restores:
            print(x)

    def restore_object(self, restore_file):
        from otpme.lib import filetools
        backend.init()
        self.init()
        file_content = filetools.read_file(restore_file)
        object_data = json.loads(file_content)
        command_args = {}
        command_args['object_data'] = object_data
        mgmt_client = self.get_mgmt_client()
        command = "backend"
        command_args['subcommand'] = "restore"
        status, \
        reply = mgmt_client.send_command(command=command,
                                    command_args=command_args,
                                    client_type="CLIENT")
        if status is False:
            raise OTPmeException(reply)
        return reply

    def handle_tool_command(self, command, subcommand, command_line):
        """ Handle tool command. """
        # FIXME: use cli.get_opts() for all -tool commands!
        if subcommand == "join" or subcommand == "leave":
            if config.system_user() != "root":
                msg = ("You must be root for this command.")
                raise OTPmeException(msg)
            # Register modules.
            register_module('otpme.lib.classes.realm')
            register_module('otpme.lib.classes.site')
            register_module('otpme.lib.classes.unit')
            register_module('otpme.lib.classes.ca')
            register_module('otpme.lib.classes.host')
            register_module('otpme.lib.classes.node')
            register_module('otpme.lib.classes.client')
            register_module('otpme.lib.classes.user')
            register_module('otpme.lib.classes.group')
            register_module('otpme.lib.classes.policy')
            register_module('otpme.lib.classes.dictionary')
            register_module('otpme.lib.filetools')
            register_module('otpme.lib.policy')
            # Init cache.
            cache.init()
            cache.enable()

            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            # Parse command line.
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))
            # Set realm join mode.
            config.realm_join = True
            # Disable object locks while doing realm join/leave.
            config.locking_enabled = False

            if subcommand == "join":
                return self.handle_join_command(object_identifier, command_args)

            if subcommand == "leave":
                return self.handle_leave_command(object_identifier, command_args)

        if subcommand == "login":
            return self.handle_login_command(command, subcommand, command_line)

        if subcommand == "logout":
            return self.logout()

        if subcommand == "whoami":
            return self.whoami()

        if subcommand == "get_login_token":
            login_token = self.get_login_token()
            if not login_token:
                raise OTPmeException("Not logged in.")
            return login_token

        if subcommand == "get_login_pass_type":
            login_pass_type = self.get_login_pass_type()
            if not login_pass_type:
                raise OTPmeException("Not logged in.")
            return login_pass_type

        if subcommand == "reload":
            return stuff.update_reload_file()

        if subcommand == "do_sync":
            # Init cache.
            cache.init()
            cache.enable()
            return self.handle_do_sync_command(command, subcommand, command_line)

        if subcommand == "add_signer" \
        or subcommand == "del_signer" \
        or subcommand == "show_signer" \
        or subcommand == "enable_signer" \
        or subcommand == "disable_signer" \
        or subcommand == "update_signer":
            return self.handle_sign_command(command, subcommand, command_line)

        if subcommand == "dump" or subcommand == "sync" or subcommand == "resync":
            if config.use_api:
                raise OTPmeException("Command invalid for API mode.")

            if subcommand == "dump":
                return self.handle_dump_command(command_line)

            if subcommand == "sync" or subcommand == "resync":
                return self.handle_sync_command(command_line, command, subcommand)

        if subcommand == "sync_status":
            try:
                sync_type = sys.argv[1]
            except:
                sync_type = None
            return self.handle_sync_status_command(sync_type)

        if subcommand == "gen_motp":
            return self.handle_gen_motp_command(command_line)

        if subcommand == "gen_mschap":
            return self.handle_gen_mschap_command(command_line)

        if subcommand == "gen_refresh":
            return self.handle_gen_refresh_command(command_line)

        if subcommand == "gen_refresh_mschap":
            return self.handle_refresh_mschap_command(command_line)

        if subcommand == "gen_logout":
            return self.handle_gen_logout_command(command_line)

        if subcommand == "gen_logout_mschap":
            return self.handle_logout_mschap_command(command_line)

        if subcommand == "dump_object":
            return self.handle_dump_object_command(command_line)

        if subcommand == "delete_object":
            return self.handle_delete_object_command(command_line)

        if subcommand == "check_duplicate_ids":
            return self.handle_duplicate_ids_command(command, subcommand)

        if subcommand == "dump_index":
            return self.handle_dump_index_command(command_line)

        if subcommand == "login_benchmark":
            return self.handle_login_benchmark(command, subcommand)

        if subcommand == "mass_object_add":
            return self.handle_mass_object_add(command, subcommand)

        if subcommand == "import":
            return self.handle_import_command(command, subcommand)

        if subcommand == "get_realm":
            return self.handle_get_realm_command()

        if subcommand == "get_site":
            return self.handle_get_site_command()

        if subcommand == "cache":
            return self.handle_cache_command(command_line)

        if subcommand == "index":
            command = command_line[0]
            if command == "backup":
                return self.handle_index_backup()
            elif command == "restore":
                try:
                    restore_file = command_line[1]
                except KeyError:
                    restore_file = None
                if not restore_file:
                    return self.get_help()
                if stuff.controld_status():
                    msg = "Please stop OTPme daemon first."
                    print(msg)
                    return False
                return self.handle_index_restore(restore_file)
            else:
                return self.handle_index_command(command_line)

        if subcommand == "regen_master_key":
            return self.regen_master_key()

        if subcommand == "renew_auth_key":
            return self.renew_auth_key()

        if subcommand == "renew_cert":
            return self.renew_host_cert()

        if subcommand == "show_sessions":
            return self.handle_show_sessions_command(command_line)

        if subcommand == "get_login_session_id":
            return self.get_login_session_id()

        if subcommand == "get_jwt":
            return self.handle_get_jwt_command(command_line)

        if subcommand == "get_sotp":
            return self.get_sotp(command, subcommand)

        if subcommand == "get_srp":
            return self.get_srp()

        if subcommand == "get_tty":
            return self.get_tty()

        if subcommand == "reneg":
            return self.handle_reneg_command()

        if subcommand == "start_ssh_agent":
            self.start_ssh_agent()
            return ""

        if subcommand == "stop_ssh_agent":
            self.stop_ssh_agent()
            return ""

        if subcommand == "restart_ssh_agent":
            self.restart_ssh_agent()
            return ""

        if subcommand == "radius":
            return self.handle_radius_command(command_line)

        if subcommand == "ssh_agent_status":
            return self.ssh_agent_status()

        if subcommand == "search":
            return self.handle_search_command(command_line)

        if subcommand == "backup":
            from otpme.lib.register import register_modules
            register_modules()
            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            # Parse command line.
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))
            try:
                backup_dir = command_args['backup_dir']
            except KeyError:
                return self.get_help()
            return self.do_backup(backup_dir)

        if subcommand == "unpin_offline_token":
            register_module("otpme.lib.offline_token")
            return self.unpin_offline_token()

        if subcommand == "pin_offline_token":
            register_module("otpme.lib.offline_token")
            return self.pin_offline_token()

        if subcommand == "show_offline_token":
            register_module("otpme.lib.offline_token")
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            # Parse command line.
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))
            return self.show_offline_token(token_id=object_identifier)

        if subcommand == "restore":
            from otpme.lib.register import register_modules
            register_modules()
            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            # Parse command line.
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=self.command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))
            try:
                restore_dir = command_args['restore_dir']
            except KeyError:
                restore_dir = None
            try:
                restore_file = command_args['restore_file']
            except KeyError:
                restore_file = None
            if not restore_dir and not restore_file:
                return self.get_help()
            if restore_dir:
                if stuff.controld_status():
                    msg = "Please stop OTPme daemon first."
                    print(msg)
                    return False
                return self.full_restore(restore_dir)
            if restore_file:
                return self.restore_object(restore_file)

        if subcommand == "sign" \
        or subcommand == "verify" \
        or subcommand == "encrypt" \
        or subcommand == "decrypt":
            return self.handle_key_script_command(subcommand)

        # FIXME: implement mass creation of users, tokens, clients groups etc. from file
        if subcommand == "add_user":
            return self.handle_add_user_command()

        if subcommand == "reset_reauth":
            return self.send_command(daemon="mgmtd",
                                    command="reset_reauth",
                                    parse_command_syntax=False)
        if subcommand == "test":
            from otpme.lib import test
            test.test()
            return ""

        return self.get_help()

    def handle_trash_command(self, command, subcommand, command_line):
        """ Handle tool command. """
        if config.use_api:
            #register_module('otpme.lib.host')
            #register_module('otpme.lib.cache')
            register_module('otpme.lib.trash')
            register_module('otpme.lib.multiprocessing')
            # Enable cache.
            cache.init()
            cache.enable()
            self.init(use_backend=True)

        command_args = {}
        # Send command.
        reply = self.send_command(daemon="mgmtd",
                                command=command,
                                command_args=command_args)
        return reply

    def handle_get_realm_command(self):
        """ Handle get realm command. """
        #init_otpme()
        self.init()
        return config.realm

    def handle_get_site_command(self):
        """ Handle get site command. """
        #init_otpme()
        self.init()
        return config.site

    def handle_cache_command(self, command_line):
        """ Handle cache command. """
        from otpme.lib.register import register_modules
        if len(command_line) < 1:
            return self.get_help()
        # Register modules.
        register_modules()
        # Reload config after module registration.
        config.reload()
        command = command_line[0]
        _cache = config.get_cache_module()
        _cache.command(command)

    def handle_index_command(self, command_line):
        """ Handle index command. """
        from otpme.lib.register import register_modules
        if len(command_line) < 1:
            return self.get_help()
        # Register modules.
        register_modules()
        # Reload config after module registration.
        config.reload()
        _index = config.get_index_module()
        command = command_line[0]
        _index.command(command)

    def handle_index_backup(self):
        """ Handle index backup command. """
        from otpme.lib.index import do_index_backup
        from otpme.lib.register import register_modules
        # Register modules.
        register_modules()
        # Reload config after module registration.
        config.reload()
        _index = config.get_index_module()
        self.init()
        backend.init()
        if not _index.status():
            _index.start()
        index_data = do_index_backup()
        index_data = json.dumps(index_data)
        return index_data

    def handle_index_restore(self, restore_file):
        """ Handle index restore command. """
        from otpme.lib import filetools
        from otpme.lib.index import do_index_restore
        from otpme.lib.register import register_modules
        # Register modules.
        register_modules()
        # Reload config after module registration.
        config.reload()
        _index = config.get_index_module()
        backend.init()
        if not _index.status():
            _index.start()
        if not os.path.exists(restore_file):
            msg = "No such file or directory: %s" % restore_file
            raise OTPmeException(msg)
        try:
            file_content = filetools.read_file(restore_file)
        except Exception as e:
            msg = (_("Error reading index dump file: %s") % e)
            raise OTPmeException(msg)
        index_data = json.loads(file_content)
        try:
            do_index_restore(index_data)
        except Exception as e:
            msg = "Failed to do index restore: %s" % e
            raise OTPmeException(msg)
        msg = "Creating DB indexes..."
        print(msg)
        _index.command("create_db_indices")
        return

    def handle_radius_command(self, command_line):
        """ Handle radius command. """
        from otpme.lib.freeradius.utils import stop
        from otpme.lib.freeradius.utils import start
        from otpme.lib.freeradius.utils import status
        from otpme.lib.register import register_modules
        if len(command_line) < 1:
            return self.get_help()
        try:
            command = command_line[0]
        except:
            return self.get_help()
        if command == "start":
            # Register modules.
            register_modules()
            self.init(use_backend=True)
            start()
        elif command == "stop":
            stop()
        elif command == "restart":
            # Register modules.
            register_modules()
            self.init(use_backend=True)
            stop()
            start()
        elif command == "status":
            try:
                status()
                print("Freeradius running.")
            except:
                raise
        elif command == "reload":
            try:
                hostd_conn = connections.get("hostd")
            except Exception as e:
                msg = "Failed to get hostd connection: %s" % e
                self.logger.warning(msg)
                return
            hostd_conn.send(command="reload_radius")

        elif command == "test":
            import pyrad.packet
            from pyrad.client import Client
            from pyrad.dictionary import Dictionary
            from radius_eap_mschapv2 import RADIUS
            mschap = False
            if "--mschap" in command_line:
                mschap = True
                command_line.remove("--mschap")
            usage_help = "Usage: otpme-tool radius test [--mschap] <username> <password> <nas_id> <secret>"
            if "-h" in command_line:
                print(usage_help)
                return

            radius_host = "127.0.0.1"
            radius_nas_ip = "127.0.0.1"
            try:
                username = command_line[1]
                password = command_line[2]
                radius_nas_id = command_line[3]
                radius_secret = command_line[4]
            except IndexError:
                print(usage_help)
                return
            if mschap:
                msg = "Sending MSCHAP radius request."
                print(msg)
                r = RADIUS(radius_host, radius_secret, radius_nas_ip, radius_nas_id, eap=True)
                status = r.is_credential_valid(username, password)
            else:
                msg = "Sending radius request."
                print(msg)
                radius_dict = os.path.join(config.config_dir, "radius", "dictionary")
                radius_secret = radius_secret.encode()
                srv = Client(server=radius_host,
                			secret=radius_secret,
                            dict=Dictionary(radius_dict))
                # Create request.
                req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                						   User_Name=username,
                						   NAS_Identifier=radius_nas_id)
                req["User-Password"] = req.PwCrypt(password)
                # Send request.
                reply = srv.SendPacket(req)
                status = False
                if reply.code == pyrad.packet.AccessAccept:
                    status = True
            if not status:
                msg = "Radius request failed."
                raise OTPmeException(msg)
            msg = "Radius request successful."
            print(msg)
        else:
            msg = "Unknown command: %s" % command
            raise Exception(msg)

    def handle_show_sessions_command(self, command_line):
        """ Handle show sessions command. """
        login_pid = None
        if len(command_line) > 0:
            login_pid = command_line[0]
        return self.show_login_session(login_pid)

    def handle_get_jwt_command(self, command_line):
        """ Handle get JWT command. """
        if len(command_line) < 1:
            return self.get_help()
        #init_otpme()
        self.init()
        challenge = command_line[0]
        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)
        # Try to get username for logged in user from otpme-agent
        username = agent_conn.get_user()
        return self.get_jwt(username, challenge)

    def handle_reneg_command(self):
        """ Handle reneg command. """
        #init_otpme()
        self.init()
        return self.reneg(realm=config.connect_realm,
                            site=config.connect_site)

    def handle_search_command(self, command_line):
        """ Handle search command. """
        if len(command_line) < 1:
            return self.get_help()
        # Init otpme.
        if config.use_api:
            self.init()
        # Get search command.
        search_command = command_line[0:]
        return self.search(command=search_command)

    def handle_join_command(self, object_identifier, command_args):
        """ Handle realm join command. """
        from otpme.lib import filetools
        from otpme.lib.register import register_modules
        from otpme.lib.backends.file.index import INDEX_DIR
        # Register modules.
        register_modules()
        try:
            host_type = command_args['host_type']
        except:
            host_type = "host"
        try:
            jotp = command_args['jotp']
        except:
            jotp = None
        try:
            unit = command_args['unit']
        except:
            unit = None
        try:
            host_key_len = command_args['host_key_len']
        except:
            host_key_len = 4096
        try:
            site_key_len = command_args['site_key_len']
        except:
            site_key_len = 4096
        try:
            trust_site_cert = command_args['trust_site_cert']
        except:
            trust_site_cert = False
        try:
            no_daemon_start = command_args['no_daemon_start']
        except:
            no_daemon_start = False
        try:
            x = command_args['site_cert_fingerprint']
            fingerprint_digest = x.split(":")[0].lower()
            site_cert_fingerprint = x.split(":")[1]
        except:
            fingerprint_digest = "sha256"
            site_cert_fingerprint = None

        # Get index module.
        _index = config.get_index_module()

        # Check host status.
        if config.uuid:
            if not _index.status():
                _index.start()
            self.init()
            my_host = backend.get_object(uuid=config.uuid)
            if my_host:
                msg = ("Host is already a realm member.")
                raise OTPmeException(msg)

        # Make sure index is ready.
        if not _index.is_available():
            if _index.status():
                _index.stop()
            _index.command("drop")
            _index.command("init")
        if not _index.status():
            _index.start()
        # Make sure cache is started.
        _cache = config.get_cache_module()
        if not _cache.status():
            _cache.start()

        create_db_indexes = False
        index_created_file = os.path.join(INDEX_DIR, ".indexes_created")
        if not os.path.exists(index_created_file):
            create_db_indexes = True

        if isinstance(jotp, int) or isinstance(jotp, float):
            jotp = str(jotp)

        # Join realm.
        result = self.join_realm(host_type,
                        domain=object_identifier,
                        jotp=jotp, unit=unit,
                        host_key_len=host_key_len,
                        site_key_len=site_key_len,
                        no_daemon_start=no_daemon_start,
                        trust_site_cert=trust_site_cert,
                        create_db_indexes=create_db_indexes,
                        fingerprint_digest=fingerprint_digest,
                        check_site_cert=site_cert_fingerprint)
        if create_db_indexes:
            filetools.touch(index_created_file)
        return result

    def handle_login_command(self, command, subcommand, command_line):
        """ Handle login command. """
        #register_module("otpme.lib.protocols.client.host1")
        #register_module("otpme.lib.protocols.client.agent1")
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))
        try:
            username = command_args['username']
        except:
            username = None
        try:
            node = command_args['node']
        except:
            node = None

        result = self.login(username=username,
                        password=self.user_password,
                        node=node)

        return result

    def handle_leave_command(self, object_identifier, command_args):
        """ Handle leave command. """
        from otpme.lib import multiprocessing
        from otpme.lib.register import register_modules
        # Register modules.
        register_modules()
        try:
            lotp = command_args['lotp']
        except:
            lotp = None
        try:
            offline = command_args['offline']
        except:
            offline = False
        try:
            keep_host = command_args['keep_host']
        except:
            keep_host = None
        try:
            keep_data = command_args['keep_data']
        except:
            keep_data = False
        try:
            keep_cache = command_args['keep_cache']
        except:
            keep_cache = False
        try:
            keep_cert = command_args['keep_cert']
        except:
            keep_cert = False

        if keep_data:
            keep_cert = True

        if config.use_api:
            offline = True

        if isinstance(lotp, int) or isinstance(lotp, float):
            lotp = str(lotp)

        if not config.uuid:
            msg = "Host is not a realm member."
            raise OTPmeException(msg)

        if config.master_node:
            msg = "Master node cannot leave the realm."
            raise OTPmeException(msg)

        host_type = config.host_data['type']
        if host_type == "node" and stuff.controld_status():
            self.init()
            search_attrs = {
                            'uuid'      : {'value':"*"},
                            'enabled'   : {'value':True},
                        }
            enabled_nodes = backend.search(object_type="node",
                                        attributes=search_attrs,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="name")
            missing_nodes = []
            member_nodes = multiprocessing.get_dict("member_nodes")
            for node_name in enabled_nodes:
                if node_name == config.host_data['name']:
                    continue
                if node_name in member_nodes:
                    continue
                missing_nodes.append(node_name)
            if missing_nodes:
                missing_nodes = " ".join(missing_nodes)
                msg = ("Please wait for nodes to join the cluster: %s"
                            % missing_nodes)
                raise OTPmeException(msg)

        # Stop OTPme daemons.
        try:
            stuff.stop_otpme_daemon(kill=True, timeout=1)
        except Exception as e:
            msg = "Failed to stop OTPme daemons: %s" % e
            logger.critical(msg)

        # Make sure index is running.
        _index = config.get_index_module()
        if _index.need_start:
            if not _index.status():
                _index.start()
        # Make sure cache is running.
        _cache = config.get_cache_module()
        if not _cache.status():
            _cache.start()

        result = self.leave_realm(domain=object_identifier,
                                    lotp=lotp,
                                    offline=offline,
                                    keep_host=keep_host,
                                    keep_data=keep_data,
                                    keep_cache=keep_cache,
                                    keep_cert=keep_cert)
        return result

    def handle_dump_command(self, command_line):
        """ Handle dump command. """
        try:
            dump_type = command_line[0]
        except:
            dump_type = None
        result = self.daemon_dump(dump_type)
        return result

    def handle_login_benchmark(self, command, subcommand):
        """ Handle login benchmark command. """
        import csv
        from otpme.lib import multiprocessing
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=self.command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))
        try:
            node = command_args.pop('node')
        except KeyError:
            node = None
        try:
            procs = command_args.pop('procs')
        except KeyError:
            procs = None
        if procs is None:
            procs = int(os.cpu_count() / 2)
        csv_file = command_args.pop('csv_file')
        with open(csv_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            #header = next(reader)
            #print("Got header from csv file:", header)
            csv_data = list(reader)
        login_procs = {}
        login_counter = 0
        start_time = time.time()
        for line in csv_data:
            username = line[0]
            password = line[1]
            while True:
                for x_user in list(login_procs):
                    child = login_procs[x_user]
                    if child.is_alive():
                        continue
                    child.join()
                    login_procs.pop(x_user)
                    login_counter += 1
                    now = time.time()
                    duration = now - start_time
                    per_login_time = duration / login_counter
                    print("Login finished: %s (%.2f)" % (x_user, per_login_time))
                time.sleep(0.01)
                if len(login_procs) >= procs:
                    continue
                break
            method_kwargs = {}
            method_kwargs['username'] = username
            method_kwargs['password'] = password
            method_kwargs['mount_shares'] = False
            method_kwargs['check_login_status'] = False
            method_kwargs['add_agent_session'] = False
            method_kwargs['add_login_session'] = False
            method_kwargs['start_otpme_agent'] = False
            method_kwargs['node'] = node
            login_child = multiprocessing.start_process(name="login",
                                                target=self.login,
                                                target_kwargs=method_kwargs,
                                                start=False,
                                                daemon=True)
            login_child.start()
            login_procs[username] = login_child
        while True:
            for x_user in list(login_procs):
                child = login_procs[x_user]
                if child.is_alive():
                    continue
                child.join()
                login_procs.pop(x_user)
                login_counter += 1
                now = time.time()
                duration = now - start_time
                per_login_time = duration / login_counter
                print("Login finished: %s (%.2f)" % (x_user, per_login_time))
            time.sleep(0.01)
            if len(login_procs) > 0:
                continue
            break
        now = time.time()
        duration = now - start_time
        logins_per_second = login_counter / duration
        print("Requests/Second: %.2f" % logins_per_second)

    def handle_mass_object_add(self, command, subcommand):
        """ Handle mass object add command. """
        import csv
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=self.command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))
        csv_file = command_args.pop('csv_file')
        with open(csv_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile, delimiter=';')
            #header = next(reader)
            #print("Got header from csv file:", header)
            csv_data = list(reader)
        self.init()
        mgmt_client = self.get_mgmt_client()
        mgmt_cmd = "mass_object_add"
        command_args['csv_data'] = csv_data
        status, \
        reply = mgmt_client.send(command=mgmt_cmd,
                                command_args=command_args,
                                client_type="CLIENT")
        if status == False:
            raise OTPmeException(reply)
        return reply

    def handle_dump_index_command(self, command_line):
        """ Handle dump index command. """
        if len(command_line) < 1:
            return self.get_help()
        object_id = command_line[0]
        return self.dump_index(object_id)

    def handle_delete_object_command(self, command_line):
        """ Handle delete object command. """
        if len(command_line) < 1:
            return self.get_help()
        object_id = command_line[0]
        return self.delete_object(object_id)

    def handle_duplicate_ids_command(self, command, subcommand):
        """ Handle check duplicate IDs command. """
        from otpme.lib.register import register_modules
        # Register modules.
        register_modules()
        if len(self.command_line) < 1:
            return self.get_help()
        self.init()
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=self.command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))
        mgmt_client = self.get_mgmt_client()
        command = "check_duplicate_ids"
        command_args['subcommand'] = command_args['object_type']
        status, \
        reply = mgmt_client.send_command(command=command,
                                    command_args=command_args,
                                    client_type="CLIENT")
        if status is False:
            raise OTPmeException(reply)
        return reply


    def handle_dump_object_command(self, command_line):
        """ Handle dump object command. """
        if len(command_line) < 1:
            return self.get_help()
        object_id = command_line[0]
        return self.dump_object(object_id)

    def handle_logout_mschap_command(self, command_line):
        """ Handle gen logout MSCHAP command. """
        if len(command_line) < 2:
            return self.get_help()

        username = command_line[0]
        password = command_line[1]

        mschap_data = self.gen_logout_mschap(username, password)

        nt_key = mschap_data['nt_key']
        challenge = mschap_data['challenge']
        response = mschap_data['response']

        result = []
        result.append("NT_KEY: %s" % nt_key)
        result.append("MSCHAP_CHALLENGE: %s" % challenge)
        result.append("MSCHAP_RESPONSE: %s" % response)

        return "\n".join(result)

    def handle_gen_logout_command(self, command_line):
        """ Handle gen logout command. """
        if len(command_line) < 2:
            return self.get_help()
        username = command_line[0]
        password = command_line[1]
        return self.gen_logout(username, password)

    def handle_gen_refresh_command(self, command_line):
        """ Handle gen refresh command. """
        if len(command_line) < 2:
            return self.get_help()
        username = command_line[0]
        password = command_line[1]
        srp = self.gen_refresh(username, password)
        return srp

    def handle_refresh_mschap_command(self, command_line):
        """ Handle refresh MSCHAP command. """
        if len(command_line) < 2:
            return self.get_help()

        username = command_line[0]
        password = command_line[1]

        mschap_data = self.gen_refresh_mschap(username, password)

        nt_key = mschap_data['nt_key']
        challenge = mschap_data['challenge']
        response = mschap_data['response']

        result = []
        result.append("NT_KEY: %s" % nt_key)
        result.append("MSCHAP_CHALLENGE: %s" % challenge)
        result.append("MSCHAP_RESPONSE: %s" % response)

        return "\n".join(result)

    def handle_gen_mschap_command(self, command_line):
        """ Handle gen MSCHAP command. """
        if len(command_line) < 2:
            return self.get_help()

        username = command_line[0]
        password = command_line[1]

        mschap_data = self.gen_mschap(username, password)
        if not mschap_data:
            return ""

        nt_key = mschap_data['nt_key']
        challenge = mschap_data['challenge']
        response = mschap_data['response']

        result = []
        result.append("NT_KEY: %s" % nt_key)
        result.append("MSCHAP_CHALLENGE: %s" % challenge)
        result.append("MSCHAP_RESPONSE: %s" % response)

        return "\n".join(result)

    def handle_gen_motp_command(self, command_line):
        """ Handle gen MOTP command. """
        if len(command_line) < 3:
            return self.get_help()

        if len(command_line) >= 4:
            otp_count = int(command_line[3])
        else:
            otp_count = 1

        epoch_time = command_line[0]
        secret = command_line[1]
        pin = command_line[2]

        otps = self.gen_motp(epoch_time=epoch_time,
                            secret=secret, pin=pin,
                            otp_count=otp_count,
                            otp_len=config.motp_len)
        if not otps:
            return ""
        otp_list = "\n".join(otps)

        return otp_list

    def handle_import_command(self, command, subcommand):
        """ Handle import command. """
        from otpme.lib import filetools
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=self.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        try:
            password = local_command_args['password']
        except:
            password = None
        filename = object_identifier

        # xxxxxxxxxxxxxxx
        # FIXME: how to im-/export complete user (e.g. with tokens?)
        try:
            file_content = filetools.read_file(filename)
        except Exception as e:
            msg = (_("Error reading object config: %s") % e)
            raise OTPmeException(msg)

        object_config = json.loads(file_content)
        object_id = object_config.pop('OID')

        return self.import_object(object_config,
                                object_id=object_id,
                                password=password)

    def handle_sync_status_command(self, sync_type=None):
        """ Handle get sync status command. """
        register_module('otpme.lib.host')
        self.init()
        reply = []
        host_type = config.host_data['type']
        sync_status = self.get_sync_status()
        for realm in sorted(sync_status):
            for site in sorted(sync_status[realm]):
                for _sync_type in sorted(sync_status[realm][site]):
                    if sync_type is not None:
                        if _sync_type != sync_type:
                            continue
                    if host_type == "node":
                        if realm == config.realm:
                            if site == config.site:
                                if _sync_type == "objects":
                                    continue
                    try:
                        status = sync_status[realm][site][_sync_type]['status']
                    except:
                        continue
                    try:
                        last_run = sync_status[realm][site][_sync_type]["last_run"]
                    except:
                        last_run = 0
                    try:
                        last_failed = sync_status[realm][site][_sync_type]["last_failed"]
                    except:
                        last_failed = 0
                    try:
                        progress = sync_status[realm][site][_sync_type]["progress"]
                    except:
                        progress = 0

                    if last_run:
                        # Get time since sync started.
                        x = int(time.time() - last_run)
                        # Make it human readable.
                        running_age = str(datetime.timedelta(seconds=x))

                    if last_failed:
                        # Get time since sync started.
                        x = int(time.time() - last_failed)
                        # Make it human readable.
                        failed_age = str(datetime.timedelta(seconds=x))

                    if last_run != 0:
                        # Get time since last run.
                        last_run = datetime.datetime.fromtimestamp(last_run)
                        last_run = last_run.strftime('%H:%M:%S %d.%m.%Y')
                        sync_time = last_run
                    else:
                        sync_time = "Never synced"

                    x = ("/%s/%s: %s: %s" % (realm, site, _sync_type, sync_time))
                    if status == "running":
                        if progress > 0:
                            x = ("%s (%.2f%% running since %s)"
                                % (x, progress, running_age))
                        else:
                            x = ("%s (running since %s)" % (x, running_age))
                    elif status == "disabled":
                        x = ("%s (%s)" % (x, status))
                    elif status == "failed":
                        x = ("%s (last failed: %s)" % (x, failed_age))
                    else:
                        x = ("%s (%s)" % (x, running_age))

                    reply.append(x)

        return "\n".join(reply)

    def handle_sync_command(self, command_line, command, subcommand):
        """ Handle sync command. """
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        # Get sync parameters.
        try:
            sync_type = command_args['sync_type']
        except:
            sync_type = None
        try:
            realm = command_args['realm']
        except:
            realm = None
        try:
            site = command_args['site']
        except:
            site = None

        if subcommand == "resync":
            resync = True
        else:
            resync = False

        result = self.start_sync(sync_type,
                            resync=resync,
                            realm=realm,
                            site=site)
        return result

    def handle_sign_command(self, command, subcommand, command_line):
        # Register required object types.
        register_module('otpme.lib.classes.user')
        register_module('otpme.lib.classes.role')
        # Examples
        # we want users to access this node to be in the role "verwaltung"
        # we trust the user root that she only adds users that are allowed to the role "verwaltung"
        #   - otpme-tool add_signer --type token --tag "role|hboss.intern/koblenz/roles/verwaltung" "user|hboss.intern/koblenz/users/root"
        # we allow only the user test1 to login with a token that was signed for the node bossix-hbslx.
        #   - otpme-tool add_signer --type token --tag "node|hboss.intern/koblenz/nodes/bossix-hbslx" --tag "user|hboss.intern/koblenz/users/test1" "user|hboss.intern/koblenz/users/root"
        # trust any auth_script signed by any member of the manager role.
        #   - otpme-tool add_signer --type auth_script "role|hboss.intern/koblenz/roles/manager"
        # trust scripts signed by the root user for the site koblenz.
        #   - otpme-tool add_signer --type auth_script --tag "site|hboss.intern/koblenz" "user|hboss.intern/koblenz/users/root"
        # trust only key scripts signed by the user itself
        #   - otpme-tool add_signer --type key_script "user|hboss.intern/koblenz/users/test1"

        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        if config.system_user() != "root":
            command_args['private'] = True
            command_args['username'] = config.system_user()

        command_method = getattr(self, subcommand)

        return command_method(**command_args)

    def handle_do_sync_command(self, command, subcommand, command_line):
        """ Handle do sync command. """
        from otpme.lib.register import register_modules
        # Register modules.
        register_modules()
        if config.system_user() != "root":
            msg = ("You must be root for this command.")
            raise OTPmeException(msg)
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args=self.command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        sync_type = object_identifier
        try:
            realm = command_args['realm']
        except:
            realm = config.realm
        try:
            site = command_args['site']
        except:
            site = config.site
        try:
            resync = command_args['resync']
        except:
            resync = False
        try:
            mem_cache = command_args['mem_cache']
        except:
            mem_cache = True
        try:
            offline = command_args['offline']
        except:
            offline = False
        try:
            ignore_changed_objects = command_args['ignore_changed_objects']
        except:
            ignore_changed_objects = False
        try:
            sync_older_objects = command_args['sync_older_objects']
        except:
            sync_older_objects = False

        # Init in API mode because hostd may not be running when
        # doing manual sync.
        config.use_api = True
        # Init otpme.
        #init_otpme(use_backend=True)
        self.init(use_backend=True)

        config.sync_mem_cache = mem_cache

        sync_last_used = False
        host_type = config.host_data['type']
        if host_type == "node":
            sync_last_used = True
        sync_status = self.do_sync(sync_type=sync_type,
                    realm=realm,
                    site=site,
                    resync=resync,
                    offline=offline,
                    sync_last_used=sync_last_used,
                    sync_older_objects=sync_older_objects,
                    ignore_changed_objects=ignore_changed_objects)
        if sync_status is False:
            msg = "Sync failed."
            raise OTPmeException(msg)
        return

    def gen_user_keys(self, username, password=None, key_len=None):
        """ Generate users private/public key pair. """
        # Build key script options.
        script_command = [ "gen_keys" ]
        if key_len is not None:
            script_options = [ "-b", str(key_len) ]

        # Run key script.
        try:
            script_status, \
            script_stdout, \
            script_stderr, \
            script_pid = stuff.run_key_script(username=username,
                                            key_pass=password, call=False,
                                            script_command=script_command,
                                            script_options=script_options)
        except Exception as e:
            config.raise_exception()
            msg = "Failed to run key script: %s" % e
            raise OTPmeException(msg)

        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        if script_status != 0:
            if script_stderr == "":
                output = script_stdout
            else:
                output = script_stderr
            msg = (_("Error running key script: %s") % output)
            raise OTPmeException(msg)

        if not script_stdout:
            raise OTPmeException("Got no keys from script.")

        try:
            user_private_key = script_stdout.split(" ")[0]
        except:
            raise OTPmeException("Unable to get private key from script.")

        try:
            user_public_key = script_stdout.split(" ")[1].replace("\n", "")
        except:
            raise OTPmeException("Unable to get public key from script.")

        return user_private_key, user_public_key

    def deploy_token(self, token_rel_path, token_type, no_token_write=False):
        """ Deploy token. """
        # Enable/disable SERIAL_API_VISIBLE flag.
        if token_type == "yubikey-serial":
            from otpme.lib.smartcard.yubikey.yubikey import Yubikey
            # Try to find yubikey.
            try:
                yk = Yubikey()
            except Exception as e:
                raise OTPmeException(_("Error detecting yubikey: %s") % e)

            try:
                slot = local_command_args['slot']
            except:
                # Set default slot=2 if we got no slot from user.
                slot = 2
                local_command_args['slot'] = slot

            try:
                show_serial = local_command_args['show_serial']
            except:
                show_serial = False

            if show_serial:
                try:
                    message(yk.get_serial())
                except Exception as e:
                    raise OTPmeException(str(e))
            else:
                # Try to set flag to given slot.
                try:
                    yk.set_serial_visible(**local_command_args)
                    message(_("Flag successfully set for slot %s") % slot)
                except Exception as e:
                    raise OTPmeException(str(e))


        # Handle deployment of OpenSSH token (token type ssh in OTPme)
        if token_type == "openssh":
            # Path to SSH private key.
            try:
                ssh_private_key = local_command_args['private_key']
            except:
                ssh_private_key = None
            if ssh_private_key:
                if not os.path.exists(ssh_private_key):
                    msg = (_("No such file or directory: %s") % ssh_private_key)
                    raise OTPmeException(msg)
                try:
                    fd = open(ssh_private_key, "r")
                    ssh_private_key = fd.read()
                except Exception as e:
                    msg = (_("Error reading private key from file: %s") % e)
                    raise OTPmeException(msg)
                finally:
                    fd.close()
            else:
                from otpme.lib import ssh
                ssh_private_key, ssh_public_key = ssh.gen_ssh_key_pair()

            # Hash type used to derive private key encryption key from password.
            if ssh_private_key:
                try:
                    password_hash_type = local_command_args['password_hash_type']
                except:
                    password_hash_type = "PBKDF2"
                deploy_args['password_hash_type'] = password_hash_type

            # Without private key we cannot continue.
            if not ssh_private_key:
                raise OTPmeException("Cannot continue withtout private key.")

            # Get passprhase to protect private key.
            password = cli.get_password(min_len=3)
            deploy_args['password'] = password

            # Add SSH public key to deployment args.
            deploy_args['private_key'] = ssh_private_key

    def add_users(self, user_list):
        """ Mass user adding. """
        from otpme.lib import backend
        from otpme.lib.classes.user import User
        status = True
        register_module("otpme.lib.filetools")

        # Init otpme.
        #init_otpme()
        self.init()

        from otpme.lib import debug
        #config.debug_timings = False

        callback = config.get_callback()

        counter = 0
        user_counter = 0
        user_count = len(user_list)
        for username in user_list:
            counter += 1
            user_counter += 1

            stop_add = False
            #if user_counter > 5:
            #    if add_time > 1.3 and add_time < 1.5:
            #        config.debug_timings = True
            #        stop_add = True

            add_time = 0
            if add_time:
                pass
            #if user_counter == 5:
            #    config.debug_timings = True

            x_oid = oid.get(object_type="user", name=username, realm=config.realm, site=config.site)
            if backend.object_exists(x_oid):
                message(_("Skipping existing user: %s") % username)
                counter = 0
                #user_counter = 0
                #config.debug_timings = False
                stop_add = False
                continue

            #if counter == 1:
            #    backend.begin_transaction("add_user")

            message(_("Adding user: %s (%s/%s)")
                % (username, user_counter, user_count))

            debug.start_timing()
            try:
                user = User(name=username, realm=config.realm, site=config.site)
                user.add(callback=callback, verbose_level=3)
            except Exception as e:
                status = False
                error_message(_("Error adding user: %s") % e)
            add_time = debug.end_timing()

            #if config.debug_timings:
            #    debug.print_timing_result(print_status=True)
            #    config.debug_timings = False

            if counter == 10:
                counter = 0
                #backend.end_transaction()
                callback.write_modified_objects()

            #if user_counter >= 20:
            #    stop_add = True

            if stop_add:
                #backend.end_transaction()
                break

        if not status:
            msg = ("There where errors while creating users.")
            raise OTPmeException(msg)

    def show_offline_token(self, token_id=None):
        from otpme.lib.offline_token import OfflineToken
        username = config.system_user()
        offline_token = OfflineToken()
        try:
            offline_token.set_user(user=username)
        except Exception as e:
            msg = (_("Error initializing offline tokens: %s") % e)
            raise OTPmeException(msg)
        if not offline_token.status():
            msg = "No offline tokens saved."
            raise OTPmeException(msg)
        offline_token.load()
        offline_data = {'offline_tokens_pinned':offline_token.pinned}
        offline_tokens = offline_token.get()
        for key in offline_tokens:
            token = offline_tokens[key]
            if token_id:
                if key != token_id:
                    continue
                offline_data = token.get_offline_data()
                break
            offline_data[key] = token.rel_path
        offline_data = pprint.pformat(offline_data)
        return offline_data

    def pin_offline_token(self):
        from otpme.lib.offline_token import OfflineToken
        username = config.system_user()
        offline_token = OfflineToken()
        try:
            offline_token.set_user(user=username)
        except Exception as e:
            msg = (_("Error initializing offline tokens: %s") % e)
            raise OTPmeException(msg)
        if not offline_token.status():
            msg = "No offline tokens saved."
            raise OTPmeException(msg)
        if offline_token.pinned:
            msg = "Offline tokens already pinned."
            raise OTPmeException(msg)
        offline_token.pin()
        msg = "Offline tokens successfully pinned."
        return msg

    def unpin_offline_token(self):
        from otpme.lib.offline_token import OfflineToken
        username = config.system_user()
        offline_token = OfflineToken()
        try:
            offline_token.set_user(user=username)
        except Exception as e:
            msg = (_("Error initializing offline tokens: %s") % e)
            raise OTPmeException(msg)
        if not offline_token.status():
            msg = "No offline tokens saved."
            raise OTPmeException(msg)
        if not offline_token.pinned:
            msg = "Offline tokens not pinned."
            raise OTPmeException(msg)
        offline_token.unpin()
        msg = "Offline tokens successfully unpinned."
        return msg

    def get_script_uuid(self, script_path, realm=None, site=None):
        """ Get OTPme script UUID. """
        #from otpme.lib.register import register_modules
        ## Register modules.
        #register_modules()
        register_module("otpme.lib.classes.script")
        if realm is None:
            realm = config.realm
        if site is None:
            site = config.site
        # Get script OID.
        script_unit, script_name = script_path.split("/")
        x_oid = oid.get(object_type="script",
                        realm=realm,
                        site=site,
                        unit=script_unit,
                        name=script_name)
        # Get script UUID.
        try:
            script_uuid = self.get_uuid_by_oid(x_oid.full_oid)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting script UUID: %s") % e)
            raise OTPmeException(msg)
        return script_uuid

    def get_user_key_script(self, username, **kwargs):
        """ Get users key script. """
        # Get key script name.
        try:
            script_path, \
            script_opts = self.get_user_key_script_path(username=username, **kwargs)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting user key script path: %s") % e)
            raise OTPmeException(msg)
        if not script_path:
            return None, None, None, None
        self.logger.debug("Reading users key script...")
        # Get key script.
        try:
            script = self.get_script(script_path=script_path, **kwargs)
        except Exception as e:
            msg = (_("Error getting user key script: %s") % e)
            raise OTPmeException(msg)
        # Get key script signatures.
        try:
            script_signs = self.get_script_sign(script_path=script_path, **kwargs)
        except Exception as e:
            msg = (_("Error getting key script signatures: %s") % e)
            raise OTPmeException(msg)
        # Get key script UUID.
        try:
            script_uuid = self.get_script_uuid(script_path=script_path, **kwargs)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting key script UUID: %s") % e)
            raise OTPmeException(msg)
        return script_path, script_opts, script_uuid, script_signs, script

    def get_user_ssh_script(self, username, **kwargs):
        """ Get users SSH script. """
        # Get SSH script name.
        try:
            script_path, \
            script_opts = self.get_user_ssh_script_path(username=username, **kwargs)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting user SSH script path: %s") % e)
            raise OTPmeException(msg)
        if not script_path:
            return None, None, None, None
        self.logger.debug("Reading users SSH script...")
        # Get SSH script.
        try:
            script = self.get_script(script_path=script_path, **kwargs)
        except Exception as e:
            msg = (_("Error getting user SSH script: %s") % e)
            raise OTPmeException(msg)
        # Get SSH script signatures.
        try:
            script_signs = self.get_script_sign(script_path=script_path, **kwargs)
        except Exception as e:
            msg = (_("Error getting SSH script signatures: %s") % e)
            raise OTPmeException(msg)
        # Get SSH script UUID.
        try:
            script_uuid = self.get_script_uuid(script_path=script_path, **kwargs)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting SSH script UUID: %s") % e)
            raise OTPmeException(msg)
        return script_path, script_opts, script_uuid, script_signs, script

    def get_ssh_agent(self):
        """ Get SSH agent instance e.g. to start agent. """
        from otpme.lib.classes.ssh_agent import SSHAgent
        # Get login user.
        login_user = config.login_user
        # Try to get SSH agent script.
        ssh_agent_script_path, \
        ssh_agent_script_opts, \
        ssh_agent_script_uuid, \
        ssh_agent_script_signs, \
        ssh_agent_script = self.get_ssh_agent_script(username=login_user)
        # Get SSH agent instance.
        ssh_agent = SSHAgent(username=login_user,
                    script=ssh_agent_script,
                    script_uuid=ssh_agent_script_uuid,
                    script_path=ssh_agent_script_path,
                    script_opts=ssh_agent_script_opts,
                    script_signs=ssh_agent_script_signs)
        return ssh_agent

    def get_ssh_agent_script(self, username):
        """ Get users SSH agent script. """
        from otpme.lib.offline_token import OfflineToken
        # Get login status.
        login_status = self.get_login_status()

        if login_status:
            # Try to get SSH agent script from server.
            try:
                ssh_agent_script_path, \
                ssh_agent_script_opts, \
                ssh_agent_script_uuid, \
                ssh_agent_script_signs, \
                ssh_agent_script = self.get_user_ssh_script(username=username)
            except Exception as e:
                msg = (_("Error getting user SSH agent script: %s") % e)
                raise OTPmeException(msg)

        elif login_status == None:
            # Try to get SSH agent script from offline tokens.
            try:
                offline_token = OfflineToken()
                offline_token.set_user(user=username)
                offline_token.lock()
                ssh_agent_script_path, \
                ssh_agent_script_opts, \
                ssh_agent_script_uuid, \
                ssh_agent_script_signs, \
                ssh_agent_script = offline_token.get_script(script_id="ssh-agent")
                offline_token.unlock()
            except Exception as e:
                msg = (_("Error loading SSH script from offline tokens: %s")
                        % e)
                raise OTPmeException(msg)
        else:
            raise OTPmeException(_("Unable to get SSH agent script."))

        return (ssh_agent_script_path,
                ssh_agent_script_opts,
                ssh_agent_script_uuid,
                ssh_agent_script_signs,
                ssh_agent_script)

    def start_ssh_agent(self):
        """ Start SSH agent via agent script. """
        #init_otpme()
        self.init()
        ssh_agent = self.get_ssh_agent()
        ssh_agent.start()

    def stop_ssh_agent(self):
        """ Stop SSH agent via agent script. """
        #init_otpme()
        self.init()
        ssh_agent = self.get_ssh_agent()
        ssh_agent.start()

    def restart_ssh_agent(self):
        """ Restart SSH agent via agent script. """
        #init_otpme()
        self.init()
        ssh_agent = self.get_ssh_agent()
        ssh_agent.stop()
        ssh_agent.start()

    def ssh_agent_status(self):
        """ Get SSH agent status via agent script. """
        #init_otpme()
        self.init()
        ssh_agent = self.get_ssh_agent()
        return ssh_agent.status()

    def show_login_session(self, login_pid=None):
        """ Show login sessions. """
        from otpme.lib.humanize import units
        # Get login sessions from agent.
        login_sessions = self.get_login_sessions()

        if login_pid is not None:
            table_headers = [
                        "token",
                        "realm",
                        "site",
                        "login_time",
                        "reneg",
                        "next_reneg",
                        #"slp",
                        #"srp",
                        #"rsp",
                        "timeout",
                        "utimeout",
                        "offline",
                        ]
            table = PrettyTable(table_headers,
                                header_style="title",
                                vrules=NONE,
                                hrules=FRAME)

            table.align = "l"
            table.align["timeout"] = "c"
            table.align["utimeout"] = "c"
            table.padding_width = 0
            table.right_padding_width = 1

            try:
                login_token = login_sessions[login_pid]['login_token']
            except:
                raise OTPmeException("Unknown session PID: %s" % login_pid)

            server_sessions = login_sessions[login_pid]['server_sessions']
            for realm in server_sessions:
                for site in server_sessions[realm]:
                    session = server_sessions[realm][site]
                    current_row = []
                    current_row.append(login_token)
                    current_row.append(realm)
                    current_row.append(site)

                    try:
                        login_time = session['login_time']
                        login_time = datetime.datetime.fromtimestamp(float(login_time))
                        login_time = login_time.strftime('%H:%M:%S %d.%m')
                    except:
                        login_time = ""
                    current_row.append(login_time)

                    try:
                        last_reneg = session['last_reneg']
                    except:
                        last_reneg = None

                    # Set last reneg time.
                    if last_reneg is None:
                        last_reneg = "Never"
                    else:
                        last_reneg = datetime.datetime.fromtimestamp(float(last_reneg))
                        last_reneg = last_reneg.strftime('%H:%M:%S %d.%m')

                    # Calculate next reneg stuff.
                    try:
                        next_retry = session['next_retry']
                    except:
                        next_retry = None

                    try:
                        next_reneg = session['next_reneg']
                    except:
                        next_reneg = None

                    try:
                        last_failed_reneg = session['last_failed_reneg']
                    except:
                        last_failed_reneg = False

                    if next_retry is not None:
                        x_reneg = next_retry
                    elif next_reneg is not None:
                        x_reneg = next_reneg
                    else:
                        x_reneg = None

                    if x_reneg is not None:
                        x_reneg = datetime.datetime.fromtimestamp(float(x_reneg))
                        x_reneg = x_reneg.strftime('%H:%M:%S %d.%m')
                        if last_failed_reneg:
                            x_reneg = "%s (F)" % x_reneg
                    else:
                        x_reneg = ""

                    current_row.append(last_reneg)
                    current_row.append(x_reneg)

                    #try:
                    #    slp = session['slp']
                    #except:
                    #    slp = ""
                    #current_row.append(slp)

                    #try:
                    #    srp = session['srp']
                    #except:
                    #    srp = ""
                    #current_row.append(srp)

                    #try:
                    #    rsp = session['rsp']
                    #except:
                    #    rsp = ""
                    #current_row.append(rsp)

                    try:
                        timeout = session['session_timeout']
                        timeout = units.int2time(timeout, time_unit="m")[0]
                    except:
                        timeout = ""
                    current_row.append(timeout)

                    try:
                        unused_timeout = session['session_unused_timeout']
                        unused_timeout = units.int2time(unused_timeout, time_unit="m")[0]
                    except:
                        unused_timeout = ""
                    current_row.append(unused_timeout)

                    try:
                        offline = session['offline']
                        if offline == True:
                            offline = "Enabled"
                        else:
                            offline = "Disabled"
                    except:
                        offline = ""
                    current_row.append(offline)

                    table.add_row(current_row)

            output = table.get_string(border=True, fields=table_headers)
            # Remove top border.
            output = "\n".join(output.split("\n")[1:-1])

            return output

        table_headers = [
                    #"login_user",
                    #"id",
                    "PID",
                    #"user",
                    "token",
                    "pass_type",
                    "realm",
                    "site",
                    "type",
                    "acls",
                    "logins",
                    ]
        table = PrettyTable(table_headers,
                            header_style="title",
                            vrules=NONE,
                            hrules=FRAME)

        table.align = "l"
        #table.align["pid"] = "m"
        table.padding_width = 0
        table.right_padding_width = 1

        for login_pid in login_sessions:
            login_session = login_sessions[login_pid]

            # Skip empty sessions.
            try:
                login_token = login_session["login_token"]
            except:
                continue

            current_row = []
            #current_row.append(login_session["session_id"])
            current_row.append(login_pid)
            #try:
            #    current_row.append(login_session["system_user"])
            #except:
            #    current_row.append("")
            try:
                current_row.append(login_session["login_token"])
            except:
                current_row.append("")
            try:
                current_row.append(login_session["login_pass_type"])
            except:
                current_row.append("")
            try:
                current_row.append(login_session["realm"])
            except:
                current_row.append("")
            try:
                current_row.append(login_session["site"])
            except:
                current_row.append("")
            try:
                if login_session["session_type"] == "realm_login":
                    session_type = "login"
                elif login_session["session_type"] == "ssh_key_pass":
                    session_type = "ssh_pass"
                current_row.append(session_type)
            except:
                current_row.append("")
            try:
                acls = []
                for user in login_session["acls"]:
                    for acl in login_session["acls"][user]:
                        acls.append("%s:%s" % (user, acl))
                current_row.append("\n".join(acls))
            except:
                current_row.append("")

            logins = []
            try:
                server_sessions = login_session["server_sessions"]
            except:
                server_sessions = []
            for realm in server_sessions:
                for site in server_sessions[realm]:
                    logins.append("%s/%s" % (realm, site))
            current_row.append("\n".join(logins))

            table.add_row(current_row)

        output = table.get_string(border=True, fields=table_headers)
        # Remove top border.
        output = "\n".join(output.split("\n")[1:-1])

        return output

    def do_sync(self, sync_type="objects", resync=False, offline=False,
        sync_older_objects=False, ignore_changed_objects=False, sync_last_used=False,
        skip_object_deletion=False, max_tries=config.hostd_sync_retry_count,
        realm=None, site=None, sync_cache_on_failure=True, socket_uri=None):
        """ Do a manual hostd sync. """
        from otpme.lib import nsscache
        from otpme.lib import protocols
        from otpme.lib.sync_cache import SyncCache
        if config.host_data['type'] == "host":
            if sync_type == "token_counters" or sync_type == "used_otps":
                if not offline:
                    msg = "Hosts can only sync offline token data."
                    raise OTPmeException(msg)
        if realm is None:
            realm = config.realm
        if site is None:
            site = config.site
        if sync_type == "nsscache":
            try:
                nsscache_sync_status = nsscache.update(realm, site,
                                                    resync=resync,
                                                    cache_resync=resync,
                                                    lock=None)
            except Exception as e:
                nsscache_sync_status = False
                msg = "Error updating nsscache: %s" % e
                self.logger.critical(msg)
                config.raise_exception()
            return nsscache_sync_status
        # We must run in non API mode when doing a sync.
        config.use_api = False
        try:
            sync_conn = connections.get(daemon="syncd",
                                    realm=realm, site=site,
                                    socket_uri=socket_uri,
                                    timeout=None,
                                    interactive=False)
            sync_proto = sync_conn.protocol
        except Exception as e:
            sync_conn = None
            sync_cache = SyncCache(config.realm, config.site)
            sync_proto = sync_cache.protocol
            msg = ("Unable to get sync connection: %s/%s: %s"
                    % (realm, site, e))
            self.logger.warning(msg)
            if not sync_cache_on_failure:
                return False
            if sync_proto:
                msg = "Processing sync cache from disk."
                self.logger.info(msg)
            else:
                raise OTPmeException(msg)
        # Get protocol handler.
        proto_class = protocols.client.get_class(sync_proto)
        # Create protocol handler.
        proto_handler = proto_class(connection=sync_conn)
        # Start sync job.
        sync_status = proto_handler.do_sync(sync_type=sync_type,
                                    realm=realm,
                                    site=site,
                                    resync=resync,
                                    offline=offline,
                                    max_tries=max_tries,
                                    sync_last_used=sync_last_used,
                                    sync_older_objects=sync_older_objects,
                                    skip_object_deletion=skip_object_deletion,
                                    ignore_changed_objects=ignore_changed_objects)
        if sync_conn:
            sync_conn.close()
        return sync_status

    def get_login_status(self):
        """ Get user login status. """
        try:
            self.whoami()
        except NotLoggedIn as e:
            return False
        return True

    def get_jwt(self, username, challenge, reason="TESTING", access_group=None):
        """ Request JWT from authd. """
        register_module("otpme.lib.classes.realm")
        from otpme.lib import connections
        if access_group is None:
            access_group = config.realm_access_group
        try:
            authd_conn = connections.get("authd",
                                        realm=config.realm,
                                        site=config.site,
                                        auto_auth=False,
                                        username=username,
                                        interactive=True)
        except Exception as e:
            msg = (_("Unable to get connection to authd: %s") % e)
            raise OTPmeException(msg)
        try:
            authd_conn.authenticate(command="auth")
        except Exception as e:
            authd_conn.close()
            raise
        command_args = {}
        command_args['jwt_reason'] = reason
        command_args['jwt_challenge'] = challenge
        command_args['jwt_accessgroup'] = access_group
        try:
            status, \
            status_code, \
            reply, \
            binary_data = authd_conn.send(command="get_jwt", command_args=command_args)
        except Exception as e:
            msg = "Failed to get JWT: %s" % e
            raise OTPmeException(msg)
        finally:
            authd_conn.close()
        return reply

    def get_login_sessions(self):
        """ Get login sessions from agent. """
        from otpme.lib import json
        from otpme.lib import connections

        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        username = None
        agent_conn = None

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        # Try to get username for logged in user from otpme-agent
        username = agent_conn.get_user()

        if not username:
            raise OTPmeException("Not logged in.")

        # Get session list from agent
        json_string = agent_conn.get_sessions()

        session_list = json.decode(json_string, encoding="base64")

        return session_list

    def get_login_session_id(self):
        """ Get login sessions from agent. """
        from otpme.lib import connections

        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        username = None
        agent_conn = None

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        # Try to get username for logged in user from otpme-agent
        username = agent_conn.get_user()

        if not username:
            raise OTPmeException("Not logged in.")

        # Get session list from agent
        session_id = agent_conn.get_login_session_id()

        return session_id

    def get_tty(self):
        """ Get TTY from agent. """
        from otpme.lib import connections

        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        agent_conn = None

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        username = self.whoami()
        if not username:
            raise OTPmeException("Not logged in.")

        # Get SOTP from agent
        tty = agent_conn.get_tty()

        return tty

    def get_sotp(self, command, subcommand):
        """ Get SOTP from agent. """
        from otpme.lib import connections

        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except Exception as e:
            help_text = self.get_help(_("Unknown command: %s") % subcommand)
            raise OTPmeException(help_text)

        # Parse command line.
        object_cmd, \
        object_required, \
        object_identifier, \
        command_args = cli.get_opts(command_syntax=command_syntax,
                                    command_line=self.command_line,
                                    command_args=self.command_args)

        agent_conn = None

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        username = self.whoami()
        if not username:
            raise OTPmeException("Not logged in.")

        # Get SOTP from agent
        try:
            site = command_args['site']
        except KeyError:
            site = None
        try:
            sotp = agent_conn.get_sotp(site=site)[1]
        finally:
            agent_conn.close()

        return sotp

    def get_srp(self):
        """ Get SRP from agent. """
        from otpme.lib import connections

        # Create otpme-agent instance
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        username = None
        agent_conn = None

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        # Try to get username for logged in user from otpme-agent
        username = agent_conn.get_user()

        if not username:
            raise OTPmeException("Not logged in.")

        # Get SRP from agent
        srp = agent_conn.get_srp()[1]

        return srp

    def reneg(self, realm=None, site=None):
        """ Send renegotiation command to agent. """
        from otpme.lib import connections

        # Create otpme-agent instance.
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()

        username = None
        agent_conn = None

        # Check if otpme-agent is running.
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            msg = "No running otpme-agent found..."
            raise OTPmeException(msg)

        # Try to get agent connection.
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Error getting agent connection: %s") % e)

        # Try to get username for logged in user from otpme-agent.
        username = agent_conn.get_user()

        if not username:
            raise OTPmeException("Not logged in.")

        # Send reneg command to agent.
        try:
            result = agent_conn.reneg_session(realm=realm, site=site)
            if config.verbose_level > 0:
                return result
        except Exception as e:
            raise OTPmeException(str(e))

    def regen_master_key(self):
        """ Regenerate master key. """
        #init_otpme()
        self.init()
        if not os.path.exists(config.master_pass_salt_file):
            msg = (_("Realm config does not have a master pass salt."))
            raise OTPmeException(msg)

        if config.system_user() != "root":
            raise OTPmeException("You must be root for this command.")

        try:
            fd = open(config.master_pass_salt_file, "r")
            master_pass_salt = fd.read()
            fd.close()
        except Exception as e:
            msg = (_("Error reading master pass salt from file: %s") % e)
            raise OTPmeException(msg)
        # Re-gen master key.
        config.gen_master_key(master_pass_salt=master_pass_salt)

    def renew_auth_key(self):
        """ Regenerate host auth key. """
        config.daemon_mode = True
        #init_otpme()
        self.init()
        config.daemon_mode = False
        from otpme.lib import host
        from otpme.lib import backend

        if config.system_user() != "root":
            raise OTPmeException("You must be root for this command.")

        if config.master_node:
            config.use_api = True

        for x in ['node', 'host']:
            myhost = backend.get_object(object_type=x, uuid=config.uuid)
            if myhost:
                break
        host_private_key = myhost.gen_auth_key()

        command_args = {}
        command_args['public_key'] = myhost.public_key
        try:
            self.send_command(command=myhost.type,
                            subcommand="public_key",
                            command_line=[myhost.name],
                            command_args=command_args)
        except Exception as e:
            msg = (_("Failed to send auth key to server: %s") % e)
            raise OTPmeException(msg)

        # Save public key of host object.
        lock_caller = "renew_auth_key"
        myhost.acquire_lock(lock_caller=lock_caller)
        myhost._write()
        myhost.release_lock(lock_caller=lock_caller)
        # Update private auth key file.
        host.update_data(host_auth_key=host_private_key)

        # We need to reload daemon and agent after renewing key.
        self.handle_command(command="controld", command_line=["reload"])
        self.handle_command(command="agent", command_line=["reload"])

    def renew_host_cert(self, key_len=None):
        """ Regenerate host auth key. """
        config.daemon_mode = True
        #init_otpme()
        self.init()
        config.daemon_mode = False
        from otpme.lib import host
        from otpme.lib import backend
        from otpme.lib.pki import utils

        if config.system_user() != "root":
            raise OTPmeException("You must be root for this command.")

        for x in ['node', 'host']:
            myhost = backend.get_object(object_type=x, uuid=config.uuid)
            if myhost:
                break

        # Get host key.
        host_key = config.host_data['key']

        # Generate CSR.
        _my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
        _my_site_ca = backend.get_object(object_type="ca", uuid=_my_site.ca)
        host_cert_req, host_key = utils.create_csr(myhost.fqdn,
                                                country=_my_site_ca.country,
                                                state=_my_site_ca.state,
                                                locality=_my_site_ca.locality,
                                                organization=_my_site_ca.organization,
                                                ou=_my_site_ca.ou,
                                                email=_my_site_ca.email,
                                                key=host_key)
        command_args = {}
        command_args['cert_req'] = host_cert_req
        try:
            self.send_command(command=myhost.type,
                            subcommand="renew_cert",
                            command_line=[myhost.name],
                            command_args=command_args)
        except Exception as e:
            msg = (_("Failed to send renew cert command to server: %s") % e)
            raise OTPmeException(msg)

        command_args = {}
        try:
            host_cert = self.send_command(command=myhost.type,
                                        subcommand="dump_cert",
                                        command_line=[myhost.name],
                                        command_args=command_args,
                                        client_type="RAPI")
        except Exception as e:
            msg = (_("Failed to send dump cert command to server: %s") % e)
            raise OTPmeException(msg)

        # Update host cert in files.
        host.update_data(host_cert=host_cert)

        # We need to reload daemon and agent after renewing key.
        self.handle_command(command="controld", command_line=["reload"])
        self.handle_command(command="agent", command_line=["reload"])

    def dump_object(self, object_id):
        """ Dump object config. """
        #init_otpme()
        self.init()
        mgmt_client = self.get_mgmt_client()
        mgmt_cmd = "dump_object"
        command_args = {'object_id':object_id}
        status, \
        reply = mgmt_client.send(command=mgmt_cmd, command_args=command_args)
        if status == False:
            raise OTPmeException(reply)
        return reply

    def delete_object(self, object_id):
        """ Dump object config. """
        #init_otpme()
        self.init()
        register_module("otpme.lib.multiprocessing")
        mgmt_client = self.get_mgmt_client()
        command = "delete_object"
        command_args = {'object_id':object_id}
        status, \
        reply = mgmt_client.send(command=command,
                                command_args=command_args,
                                client_type="CLIENT")
        if status == False:
            raise OTPmeException(reply)

    def dump_index(self, object_id):
        """ Dump object index. """
        #init_otpme()
        self.init()
        mgmt_client = self.get_mgmt_client()
        mgmt_cmd = "dump_index"
        command_args = {'object_id':object_id}
        status, \
        reply = mgmt_client.send(command=mgmt_cmd, command_args=command_args)
        if status == False:
            raise OTPmeException(reply)
        return reply

    def import_object(self, object_config, object_id, password=None):
        """ Import object. """
        from otpme.lib import json
        self.init()
        # Encode object config.
        object_config = json.encode(object_config, encoding="base64")
        command_args = {}
        command_args['password'] = password
        command_args['object_id'] = object_id
        command_args['object_config'] = object_config

        mgmt_client = self.get_mgmt_client()
        command = "backend"
        command_args['subcommand'] = "import"
        status, \
        reply = mgmt_client.send_command(command=command,
                                    command_args=command_args)
        if status is False:
            raise OTPmeException(reply)

    def gen_motp(self, **kwargs):
        """ Generate MOTP. """
        from otpme.lib.otp.motp import motp
        otps = motp.generate(**kwargs)
        return otps

    def gen_refresh(self, username, password):
        """ Generate SRP. """
        from otpme.lib import srp
        password_hash  = otpme_pass.gen_one_iter_hash(username=username,
                                                password=password)
        return srp.gen(password_hash)

    def gen_logout(self, username, password):
        """ Generate SLP. """
        from otpme.lib import slp
        password_hash  = otpme_pass.gen_one_iter_hash(username=username,
                                                password=password)
        logout_pass = slp.gen(password_hash)
        return logout_pass

    def gen_mschap(self, username, password):
        """ Generate MSCHAP stuff. """
        from otpme.lib import mschap_util
        password_hash  = stuff.gen_nt_hash(password)

        nt_key, \
        challenge, \
        response = mschap_util.generate(username, password_hash)

        mschap_data = {
                    'nt_key'    : nt_key,
                    'challenge' : challenge,
                    'response'  : response,
                    }

        return mschap_data

    def gen_refresh_mschap(self, username, password):
        """ Generate MSCHAP SRP. """
        from otpme.lib import srp
        from otpme.lib import mschap_util
        password_hash  = stuff.gen_nt_hash(password)
        refresh_pass = srp.gen(password_hash)
        refresh_pass_hash = stuff.gen_nt_hash(refresh_pass)

        nt_key, \
        challenge, \
        response = mschap_util.generate(username, refresh_pass_hash)

        mschap_data = {
                    'nt_key'    : nt_key,
                    'challenge' : challenge,
                    'response'  : response,
                    }

        return mschap_data

    def gen_logout_mschap(self, username, password):
        """ Generate MSCHAP SLP. """
        from otpme.lib import slp
        from otpme.lib import mschap_util
        password_hash  = stuff.gen_nt_hash(password)

        logout_pass = slp.gen(password_hash)
        logout_pass_hash = stuff.gen_nt_hash(logout_pass)

        nt_key, \
        challenge, \
        response = mschap_util.generate(username, logout_pass_hash)

        mschap_data = {
                    'nt_key'    : nt_key,
                    'challenge' : challenge,
                    'response'  : response,
                    }

        return mschap_data

    def get_login_pass_type(self):
        """ Get login token from otpme-agent. """
        from otpme.lib import connections
        agent_conn = None
        login_pass_type = None

        # Try to get agent connection.
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Unable to get agent connection: %s") % e)

        # Try to get login token.
        try:
            login_pass_type = agent_conn.get_login_pass_type()
        except Exception as e:
            msg = (_("Error getting login pass type from agent: %s") % e)
            raise OTPmeException(msg)

        return login_pass_type

    def get_login_token(self):
        """ Get login token from otpme-agent. """
        from otpme.lib import connections
        agent_conn = None
        login_token = None

        # Try to get agent connection.
        try:
            agent_conn = connections.get("agent")
        except Exception as e:
            raise OTPmeException(_("Unable to get agent connection: %s") % e)

        # Try to get login token.
        try:
            login_token = agent_conn.get_login_token()
        except Exception as e:
            msg = (_("Error getting login user from agent: %s") % e)
            raise OTPmeException(msg)

        return login_token

    def start_sync(self, sync_type, resync=False, realm=None, site=None):
        """ Tell daemon to start sync. """
        if resync:
            if sync_type == "nsscache":
                cmd = "resync_nsscache"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            elif not sync_type or sync_type == "objects":
                # First start a sync of all sites.
                cmd = "sync_sites"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
                # Then start resync of all objects.
                cmd = "resync_objects"
                if site:
                    if not realm:
                        realm = config.realm
                if realm:
                    cmd = "%s %s" % (cmd, realm)
                if site:
                    cmd = "%s %s" % (cmd, site)
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            else:
                return self.get_help()
        else:
            if sync_type == "sites":
                cmd = "sync_sites"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            elif sync_type == "objects":
                cmd = "sync_objects"
                if site:
                    if not realm:
                        realm = config.realm
                command_args = {}
                if realm:
                    command_args['realm'] = realm
                if site:
                    command_args['site'] = site
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                command_args=command_args,
                                                interactive=False)
            elif sync_type == "token_data":
                cmd = "sync_token_data"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            elif sync_type == "ssh_authorized_keys":
                cmd = "sync_ssh_authorized_keys"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            elif sync_type == "nsscache":
                cmd = "sync_nsscache"
                sync_message = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
            elif sync_type is None:
                sync_message = []
                cmd = "sync_objects"
                result = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
                sync_message.append(result)
                cmd = "sync_token_data"
                result = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
                sync_message.append(result)
                cmd = "sync_ssh_authorized_keys"
                result = self.send_command(daemon="hostd",
                                                command=cmd,
                                                interactive=False)
                sync_message.append(result)
                sync_message = "\n".join(sync_message)
            else:
                return self.get_help()
        return sync_message

    def get_sync_status(self):
        """ Get sync status from hostd. """
        from otpme.lib import json
        cmd = "get_sync_status"
        reply = self.send_command(daemon="hostd", command=cmd)
        sync_status = json.decode(reply)
        return sync_status

    def daemon_dump(self, dump_type):
        """ Dump daemon caches. """
        try:
            object_id = self.command_line[1]

        except:
            object_id = None

        if dump_type == "instance_cache":
            command_args = {}
            cmd = "dump_instance_cache"
            if object_id:
                command_args['parameter'] = object_id
            dump_result = self.send_command(daemon="hostd", command=cmd,
                                            command_args=command_args)

        elif dump_type == "acl_cache":
            command_args = {}
            cmd = "dump_acl_cache"
            if object_id:
                command_args['parameter'] = object_id
            dump_result = self.send_command(daemon="hostd", command=cmd,
                                            command_args=command_args)

        elif dump_type == "sync_map":
            cmd = "dump_sync_map"
            dump_result = self.send_command(daemon="hostd", command=cmd)

        else:
            return self.get_help()

        return dump_result

    def add_signer(self, signer_type, object_oid,
        private=False, pin=True, tags=None, **kwargs):
        """ Add signer. """
        from otpme.lib.classes.signing import OTPmeSigner
        from otpme.lib.classes.signing import resolve_tags
        #init_otpme()
        self.init()

        # FIXME: docu!!!
        # - signatures without key pinning only protect against some attack vectors/configration issues
        # 	- e.g. if a attacker gets access to a role (e.g. by a wrong ACL) he should not have access to. any node that
        # 		requires a valid signature from your siging key is safe, even if the role would allow
        # 		the attacker to access the node. But if the attacker gets access to your user object he can change your
        # 		signing keys which get synced to each host/node and create a new valid signature.
        # - key pinning involves some manual action on each host/node
        # 	- this is a design decision!!!!!
        # 		- only a user with root access should be able to change the valid signers of a host/node!??
        # 			- only token and agent/key script signer are an exception because the are user specific
        # 			- but if the root user defines a global key script signer(s) this has precedence
        #	- possible --tag variants
        #		--tag oid
        #		--tag type:name (e.g. user:heiko.baumann)
        #		--tag sometag
        #		--tag sometag=withvalue
        #
        if signer_type not in OTPmeSigner.supported_signer_types:
            msg = ("Invalid signer type: %s" % signer_type)
            raise OTPmeException(msg)

        # FIXME: do we want to allow this command to run as user?
        #       - allow non-root user to configure global singers?
        #       - send command to hostd that executes commands?
        if signer_type not in config.valid_private_signer_types:
            if config.system_user() != "root":
                msg = ("You need to be root to add signers of type: %s"
                        % signer_type)
                raise OTPmeException(msg)
            if private:
                msg = ("signer type only allowed as global signer: %s"
                        % signer_type)
                raise OTPmeException(msg)

        # Resolve tags.
        resolved_tags = []
        if tags:
            resolved_tags = resolve_tags(tags=tags, from_uuid=False)

        # Get signer UUID.
        try:
            object_oid = oid.get(object_oid)
        except InvalidOID:
            msg = "Invaild signer OID: %s" % object_oid
            raise OTPmeException(msg)
        object_uuid = stuff.resolve_oid(object_oid)

        # Create signer object.
        signer = OTPmeSigner(object_uuid=object_uuid,
                            signer_type=signer_type,
                            pinned=pin,
                            tags=resolved_tags)
        signer.load()

        # Save signer to file.
        self.save_signer(signer=signer,
                        private=private)

    def save_signer(self, signer, private):
        """ Save signer to signers directory. """
        from otpme.lib import filetools
        signers = self.get_signers(private=private)
        for x in signers:
            if signer == x:
                msg = "Signer already exists: %s: %s" % (x.uuid, x.object_oid)
                raise OTPmeException(msg)

        file_owner = config.user
        signers_dir = config.signers_dir
        if private:
            file_owner=config.system_user()
            signers_dir = config.user_signers_dir

        signers_dir = os.path.join(signers_dir, signer.signer_type)
        if not os.path.exists(signers_dir):
            try:
                filetools.create_dir(signers_dir,
                                    user=file_owner,
                                    mode=0o770)
            except Exception as e:
                msg = ("Failed to create signers dir: %s: %s"
                    % (signers_dir, e))
                raise OTPmeException(msg)

        file_content = signer.dumps()
        signers_file = os.path.join(signers_dir, signer.uuid)
        try:
            filetools.create_file(path=signers_file,
                                content=file_content,
                                user=file_owner,
                                mode=0o700)
        except Exception as e:
            msg = ("Failed to write signers file: %s: %s"
                % (signers_file, e))
            raise OTPmeException(msg)

    def del_signer(self, signer_uuid, username=None, private=False, **kwargs):
        """ Delete signer. """
        from otpme.lib import filetools
        signers_dir = config.signers_dir
        if private:
            signers_dir = config.user_signers_dir
            if username:
                signers_dir = config.get_user_signers_dir(username)

        signer = self.get_signers(signer_uuid=signer_uuid,
                                    username=username,
                                    private=private)
        if not signer:
            msg = "Signer does not exist."
            raise OTPmeException(msg)

        signers_dir = os.path.join(signers_dir, signer.signer_type)
        signers_file = os.path.join(signers_dir, signer.uuid)
        if not os.path.exists(signers_file):
            msg = ("Signer file does not exists: %s: %s"
                % (signer_uuid, signers_file))
            raise OTPmeException(msg)

        try:
            filetools.delete(signers_file)
        except Exception as e:
            msg = ("Failed to delete signers file: %s: %s"
                % (signers_file, e))
            raise OTPmeException(msg)

    def update_signer(self, signer_uuid, private=False, **kwargs):
        """ Update signer. """
        signer = self.get_signers(signer_uuid=signer_uuid,
                                    private=private)
        signer.load()
        self.del_signer(signer.uuid, private=private)
        self.save_signer(signer=signer, private=private)

    def enable_signer(self, signer_uuid=None, private=False,
        signer_type=None, **kwargs):
        """ Enaable signer. """
        if not signer_uuid and not signer_type:
            msg = "Need <signer_uuid> or <signer_type>."
            raise OTPmeException(msg)

        result = self.get_signers(signer_uuid=signer_uuid,
                                    signer_type=signer_type,
                                    private=private)
        if not result:
            if signer_uuid:
                msg = "Unknown signer: %s" % signer_uuid
                raise OTPmeException(msg)
            msg = "No signers of type found: %s" % signer_type
            raise OTPmeException(msg)

        signers = result
        if signer_uuid:
            signers = [result]

        for signer in signers:
            signer.enable()
            self.del_signer(signer.uuid, private=private)
            self.save_signer(signer=signer, private=private)

    def disable_signer(self, signer_uuid=None, private=False,
        signer_type=None, **kwargs):
        """ Disable signer. """
        if not signer_uuid and not signer_type:
            msg = "Need <signer_uuid> or <signer_type>."
            raise OTPmeException(msg)

        result = self.get_signers(signer_uuid=signer_uuid,
                                    signer_type=signer_type,
                                    private=private)
        if not result:
            if signer_uuid:
                msg = "Unknown signer: %s" % signer_uuid
                raise OTPmeException(msg)
            msg = "No signers of type found: %s" % signer_type
            raise OTPmeException(msg)

        signers = result
        if signer_uuid:
            signers = [result]

        for signer in signers:
            signer.disable()
            self.del_signer(signer.uuid, private=private)
            self.save_signer(signer=signer, private=private)

    def get_signers(self, signer_type=None, signer_uuid=None,
        private=False, username=None, pinned=None):
        """ Load signers from files. """
        from otpme.lib.classes.signing import OTPmeSigner

        if private and signer_type:
            if signer_type not in config.valid_private_signer_types:
                msg = "Invalid private signer type: %s" % signer_type
                raise OTPmeException(msg)

        signers_dir = config.signers_dir
        if private:
            signers_dir = config.user_signers_dir
            if username:
                signers_dir = config.get_user_signers_dir(username)

        signers = []
        signer_dirs = glob.glob("%s/*" % signers_dir)
        for x in signer_dirs:
            x_signer_type = x.split("/")[-1]
            type_dir = os.path.join(signers_dir, x_signer_type)

            signers_files = glob.glob("%s/*" % type_dir)
            for signers_file in signers_files:
                x_uuid = signers_file.split("/")[-1]
                if signer_uuid and x_uuid != signer_uuid:
                    continue
                if signer_type  and x_signer_type != signer_type:
                    continue
                try:
                    fd = open(signers_file, "r")
                    file_content = fd.read()
                    fd.close()
                except Exception as e:
                    msg = ("Failed to read signers file: %s: %s"
                        % (signers_file, e))
                    raise OTPmeException(msg)

                x_signer = OTPmeSigner()
                x_signer.loads(file_content)

                if pinned is not None:
                    if x_signer.pinned != pinned:
                        continue
                signers.append(x_signer)
        if signer_uuid:
            if signers:
                return signers[0]
            return None
        signers = sorted(signers)
        return signers

    def show_signer(self, signer_uuid=None, private=False, **kwargs):
        """ Show signers. """
        from otpme.lib.classes.signing import resolve_tags
        #init_otpme()
        self.init()
        table_headers = [
                    "uuid (*pinned)",
                    "status",
                    "type",
                    "user/role",
                    "signers",
                    #"realm",
                    #"site",
                    #"pinned",
                    "tags",
                    ]
        #type_header = "type"
        #if private:
        #    type_header = "%s (private)" % type_header
        #table_headers.insert(2, type_header)
        table = PrettyTable(table_headers,
                            header_style="title",
                            vrules=NONE,
                            hrules=FRAME)

        table.align = "l"
        #table.align["timeout"] = "c"
        table.padding_width = 0
        table.right_padding_width = 1

        signers = self.get_signers(signer_uuid=signer_uuid,
                                    private=private)
        for x_signer in signers:
            current_row = []

            uuid_str = x_signer.uuid
            if x_signer.pinned:
                uuid_str = "%s*" % uuid_str
            current_row.append(uuid_str)

            signer_status = "Disabled"
            if x_signer.enabled:
                signer_status = "Enabled"
            current_row.append(signer_status)

            current_row.append(x_signer.signer_type)

            # Get user/signer OID.
            signer_uuid = x_signer.object_uuid
            try:
                signer_oid = stuff.resolve_uuid(signer_uuid)
            except Exception as e:
                msg = str(e)
                print(msg)
                continue

            if not signer_oid:
                current_row.append("Unknown")
                current_row.append("N/A")
                current_row.append("N/A")
                table.add_row(current_row)
                continue

            # FIXME: check if signer role/user does not exist anymore!!!!
            # Check if signer itself is outdated.
            signer_info = signer_oid
            signer_outdated = x_signer.check_outdated()
            if signer_outdated:
                signer_info = "%s (Outdated)" % signer_oid
            current_row.append(signer_info)

            # Check if signer keys are outdated.
            signers = []
            for x in x_signer.signers:
                key_status = None
                object_oid = x_signer.signers[x]['oid']
                key_status = x_signer.check_outdated(uuid=x)
                if key_status:
                    signer_info = "%s (%s)" % (object_oid, key_status)
                else:
                    signer_info = object_oid
                signers.append(signer_info)
            signers = "\n".join(signers)
            current_row.append(signers)

            #current_row.append(x_signer.realm)
            #current_row.append(x_signer.site)

            #current_row.append(x_signer.pinned)

            tags = resolve_tags(x_signer.tags)
            tags = "\n".join(tags)
            current_row.append(tags)

            table.add_row(current_row)

        output = table.get_string(border=True, fields=table_headers)
        # Remove top border.
        output = "\n".join(output.split("\n")[1:-1])

        # Add info on private sigeners.
        if private:
            system_user = config.system_user()
            output = (_("%s\n\n***Private singers of user '%s'***")
                    % (output, system_user))

        return output

    def join_realm(self, host_type, realm=None, site=None,
        domain=None, jotp=None, unit=None, host_key_len=None,
        site_key_len=None, trust_site_cert=False, no_daemon_start=False,
        check_site_cert=None, fingerprint_digest=None, create_db_indexes=False):
        """ Join host/node to realm. """
        from otpme.lib.join import JoinHandler
        # Disable interactive policies (e.g. reauth).
        disabled_interactive_policies = False
        if "interactive" not in config.ignore_policy_tags:
            disabled_interactive_policies = True
            config.ignore_policy_tags.append("interactive")

        # Try to join realm.
        join_handler = JoinHandler()
        try:
            result = join_handler.join_realm(domain=domain,
                                            realm=realm,
                                            site=site,
                                            host_type=host_type,
                                            host_key_len=host_key_len,
                                            site_key_len=site_key_len,
                                            jotp=jotp,
                                            unit=unit,
                                            force=config.force,
                                            no_daemon_start=no_daemon_start,
                                            trust_site_cert=trust_site_cert,
                                            check_site_cert=check_site_cert,
                                            create_db_indexes=create_db_indexes,
                                            fingerprint_digest=fingerprint_digest)
        finally:
            if disabled_interactive_policies:
                if "interactive" in config.ignore_policy_tags:
                    config.ignore_policy_tags.remove("interactive")
        return result

    def leave_realm(self, domain=None, lotp=None, offline=None,
        keep_host=None, keep_data=False, keep_cache=False, keep_cert=False):
        """ Leave realm. """
        from otpme.lib.join import JoinHandler
        # Disable interactive policies (e.g. reauth).
        disabled_interactive_policies = False
        if "interactive" not in config.ignore_policy_tags:
            disabled_interactive_policies = True
            config.ignore_policy_tags.append("interactive")

        host_type = None
        if not offline:
            self.init()
            if not config.uuid:
                msg = "Host is not a realm member."
                raise OTPmeException(msg)
            host_type = config.host_data['type']

        if host_type == "node":
            if keep_host is None:
                keep_host = False
        if host_type == "host":
            if keep_host is None:
                keep_host = True

        # Try to leave realm.
        join_handler = JoinHandler()
        try:
            result = join_handler.leave_realm(domain=domain,
                                        host_type=host_type,
                                        offline=offline,
                                        keep_host=keep_host,
                                        keep_data=keep_data,
                                        keep_cache=keep_cache,
                                        keep_cert=keep_cert,
                                        lotp=lotp)
        finally:
            if disabled_interactive_policies:
                if "interactive" in config.ignore_policy_tags:
                    config.ignore_policy_tags.remove("interactive")
        return result

    def login(self, username=None, password=None, node=None,
        start_otpme_agent=True, **kwargs):
        """ Do realm login. """
        from otpme.lib.classes.login_handler import LoginHandler
        #init_otpme(use_backend=False)
        self.init(use_backend=False)
        if start_otpme_agent:
            try:
                stuff.start_otpme_agent(user=config.system_user(),
                                        wait_for_socket=False,
                                        quiet=False)
            except Exception as e:
                config.raise_exception()
                raise OTPmeException(_("Unable to start otpme-agent: %s") % e)
        if password is None:
            if config.stdin_pass:
                password = config.stdin_pass
        login_use_dns = config.login_use_dns
        if node:
            login_use_dns = False
        try:
            login_session_id = os.environ['OTPME_LOGIN_SESSION']
        except KeyError:
            login_session_id = None
        login_handler = LoginHandler()
        try:
            login_handler.login(username=username,
                                password=password,
                                node=node,
                                interactive=True,
                                use_dns=config.use_dns,
                                #cache_login_tokens=True,
                                start_otpme_agent=False,
                                login_session_id=login_session_id,
                                login_use_dns=login_use_dns,
                                use_ssh_agent=config.use_ssh_agent,
                                use_smartcard=config.use_smartcard,
                                **kwargs)
        except Exception as e:
            raise OTPmeException(str(e))
        login_message = login_handler.login_reply['login_message']
        return login_message

    def logout(self):
        """ Do realm logout. """
        from otpme.lib.classes.login_handler import LoginHandler
        #init_otpme(use_backend=False)
        self.init(use_backend=False)
        login_handler = LoginHandler()
        try:
            result = login_handler.logout()
        except Exception as e:
            raise OTPmeException(str(e))
        return result

    def whoami(self):
        """ Get login status. """
        from otpme.lib.classes.login_handler import LoginHandler
        #init_otpme(use_backend=False)
        self.init(use_backend=False)
        login_handler = LoginHandler()
        return login_handler.whoami(verify_server_session=False)

    def get_ssh_key_pass(self):
        """ Get SSH key passphrase from running otpme-agent. """
        from otpme.lib import connections
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        ssh_key_pass = None
        # Create otpme-agent instance
        system_user = config.system_user()
        otpme_agent = OTPmeAgent(user=system_user)

        # Check if otpme-agent is running
        agent_status, pid = otpme_agent.status(quiet=True)
        if not agent_status:
            return

        # Try to get agent connection
        try:
            agent_conn = connections.get("agent", user=system_user)
        except Exception as e:
            return

        ssh_key_pass = agent_conn.get_ssh_key_pass()[1]

        return ssh_key_pass

    def start_pinentry(self, title="pinentry-otpme", wrap_pinentry=None,
        pinentry_bin=None, pinentry_opts=None):
        """ Start GPG pinentry wrapper. """
        #from otpme.lib.pinentry import pinentry
        from otpme.lib.pinentry.wrapper import pinentry_wrapper

        # Check if we have to wrap an existing pinentry.
        if pinentry_bin is None:
            pinentry_bin = config.pinentry
            if pinentry_bin == "otpme-pinentry":
                if wrap_pinentry is None:
                    wrap_pinentry = False
            else:
                if wrap_pinentry is None:
                    wrap_pinentry = True

        # Get login session ID.
        try:
            login_session_id = os.environ['OTPME_LOGIN_SESSION']
        except:
            login_session_id = None

        # Make sure we do not auth to agent with users login session.
        try:
            del (os.environ['OTPME_LOGIN_SESSION'])
        except:
            pass

        # FIXME: the autoconfirm_file should be in session_dir but for this we would
        #        need to create a login session id in pam_otpme because there is no
        #        login session when we need the autoconfirmation.
        # Check if we have to autoconfirm key usage. This file is created by
        # pam_otpme while the user is logging in and thus otpme-pinentry cannot
        # ask for confirmation of key usage.
        username = config.system_user()
        autoconfirm_file = config.get_pinentry_autoconfirm_file(username)

        # Try to get users DISPLAY from file
        if login_session_id:
            env_dir = config.get_user_env_dir()
            session_dir = "%s/%s" % (env_dir, login_session_id)
            display_file = "%s/.display" % session_dir
            if os.path.exists(display_file):
                fd = open(display_file, "r")
                display = fd.readline()
                fd.close()
                if display.startswith(":"):
                    os.environ['DISPLAY'] = display

        # Set path to users Xauthority file
        user_home = os.path.expanduser("~")
        os.environ['XAUTHORITY'] = "%s/.Xauthority" % user_home

        if wrap_pinentry:
            # Get original pinentry opts
            if pinentry_opts is None:
                pinentry_opts = self.command_line
        # Start pinentry/wrapper.
        #pinentry.run(title=title,
        #            pinentry_bin=pinentry_bin,
        #            pinentry_opts=pinentry_opts,
        #            wrapper=wrap_pinentry,
        #            debug_file=debug_file,
        #            autoconfirm_file=autoconfirm_file,
        #            pin_function=self.get_ssh_key_pass)

        pinentry_wrapper(pin=None,
                     pin_function=self.get_ssh_key_pass,
                     autoconfirm_file=autoconfirm_file,
                     fallback=True,
                     #debug_file="/tmp/pinentry.log",
                     pinentry_bin=pinentry_bin)

    def get_authorized_keys(self, username):
        """ Get authorized keys for the given user. """
        # Limit server requests to 1/30 seconds.
        now = time.time()
        try:
            last_update = os.path.getmtime(config.authorized_keys_dir)
        except FileNotFoundError:
            last_update = time.time()
        authorized_keys_age = now - last_update
        if authorized_keys_age > 30:
            try:
                hostd_conn = connections.get("hostd")
            except Exception as e:
                hostd_conn = None

            if hostd_conn:
                # Sync SSH keys assigned to this host.
                hostd_conn.send("sync_ssh_authorized_keys")
                # Wait a maximum of 5 seconds for hostd to update
                # authorized_keys file.
                wait_counter = 0
                current_timestamp = last_update
                while current_timestamp == last_update:
                    try:
                        current_timestamp = os.path.getmtime(config.authorized_keys_dir)
                    except FileNotFoundError:
                        current_timestamp = time.time()
                    wait_counter += 1
                    time.sleep(0.1)
                    if wait_counter == 50:
                        break

        authorized_keys_dir = "%s/%s" % (config.authorized_keys_dir, username)
        authorized_keys_file = "%s/authorized_keys" % authorized_keys_dir

        if not os.path.exists(authorized_keys_file):
            return ""

        try:
            fd = open(authorized_keys_file, "r")
            authorized_keys = fd.read()
            fd.close()
        except Exception as e:
            msg = (_("Unable to read current authorized_keys file: %s") % e)
            raise OTPmeException(msg)

        return authorized_keys

    def handle_token_add_del_command(self, command, subcommand):
        """ Handle token add/del command. """
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except Exception as e:
            help_text = self.get_help(_("Unknown command: %s") % subcommand)
            raise OTPmeException(help_text)

        # Parse command line.
        object_cmd, \
        object_required, \
        object_identifier, \
        command_args = cli.get_opts(command_syntax=command_syntax,
                                    command_line=self.command_line,
                                    command_args=self.command_args)

        command = "user"
        if subcommand == "add":
            subcommand = "add_token"
        else:
            subcommand = "del_token"

        token_path = object_identifier
        token_user = token_path.split("/")[0]
        token_name = token_path.split("/")[1]

        object_list = [token_user]
        command_args['token_name'] = token_name

        result = self.send_command(daemon="mgmtd",
                                command="user",
                                subcommand=subcommand,
                                command_args=command_args,
                                object_list=object_list,
                                parse_command_syntax=False,
                                interactive=True)
        return result

    def handle_dictionary_word_learning_command(self, command, subcommand):
        """ Handle dictionary word learning command. """
        from otpme.lib.spsc import SPSC
        from otpme.lib.spsc import split_password
        from itertools import permutations
        # Show help if needed
        if len(self.command_line) < 2:
            return self.get_help()

        # Get command syntax
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=self.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        all_combinations = []
        for subset in permutations(alphabet, 3):
            comb = "".join(subset)
            all_combinations.append(comb)

        # Get path to dictionary file.
        dict_file = local_command_args['dict_file']

        if not os.path.exists(dict_file):
            msg = (_("No such file or directory: %s") % dict_file)
            raise OTPmeException(msg)

        title = "Reading: %s " % os.path.basename(dict_file)

        try:
            file_size = get_uncompressed_size(dict_file)
        except UnsupportedCompressionType:
            file_size = os.path.getsize(dict_file)

        pbar = stuff.get_progressbar(maxval=file_size, title=title)

        spsc = SPSC()
        spsc.import_from_file(filename=dict_file,
                                dict_name=object_identifier,
                                dict_type="guessing",
                                min_word_len=4,
                                progressbar=pbar)
        all_dict = {}
        counter = 0
        dictionary = spsc.dictionaries[object_identifier]['dict']
        dict_size = len(dictionary)
        title = "Processing matches: %s " % object_identifier
        pbar = stuff.get_progressbar(maxval=dict_size, title=title)
        for word in dictionary:
            counter += 1
            pbar.update(counter)
            all_slices = []
            start = "%s:" % word[0:3]
            end = ":%s" % word[-3:]
            all_slices.append(start)
            middle = word[3:-3]
            if len(middle) > 2:
                middle_slices = split_password(middle, slice_len=3)
                for s in middle_slices:
                    middle_slice = ":%s:" % middle_slices[s]['slice']
                    all_slices.append(middle_slice)
            all_slices.append(end)
            for x in all_slices:
                if not x in all_dict:
                    comb = x.replace(":", "")
                    all_dict[x] = 0
                all_dict[x] += 1
        pbar.finish()

        title = "Processing non-matches: %s " % object_identifier
        dict_size = len(all_dict)
        pbar = stuff.get_progressbar(maxval=dict_size, title=title)

        counter = 0
        sorted_dict = {}
        for x in all_dict:
            counter += 1
            pbar.update(counter)
            number = int(all_dict[x])
            try:
                comb = str(x.replace(":", ""))
                all_combinations.remove(comb)
            except:
                pass

            if number < 3:
                continue
            if not number in sorted_dict:
                sorted_dict[number] = []
            if not x in sorted_dict[number]:
                sorted_dict[number].append(x)
        pbar.finish()

        word_list = []
        for x in sorted(sorted_dict, reverse=True):
            for word in sorted_dict[x]:
                word_list.append(word)

        for x in all_combinations:
            comb = "-%s-" % x
            word_list.append(comb)

        self.subcommand = "word_import"
        self.command_line = [ object_identifier ]
        self.command_args = { 'word_list' : word_list }

    def handle_dictionary_word_import_command(self, command, subcommand):
        """ Handle dictionary word import command. """
        from otpme.lib.spsc import SPSC
        # Show help if needed.
        if len(self.command_line) < 2:
            return self.get_help()

        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=self.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        # Get path to dictionary file.
        dict_file = local_command_args['dict_file']

        if not os.path.exists(dict_file):
            msg = (_("No such file or directory: %s") % dict_file)
            raise OTPmeException(msg)

        title = "Processing file: %s " % os.path.basename(dict_file)

        try:
            file_size = get_uncompressed_size(dict_file)
        except UnsupportedCompressionType:
            file_size = os.path.getsize(dict_file)

        pbar = stuff.get_progressbar(maxval=file_size, title=title)

        spsc = SPSC()
        spsc.import_from_file(filename=dict_file,
                                dict_name=object_identifier,
                                dict_type="words",
                                min_word_len=3,
                                progressbar=pbar)

        word_list = spsc.dump(object_identifier)
        self.command_line = [ object_identifier ]
        self.command_args = { 'word_list' : word_list }

    def handle_script_run_command(self, command, subcommand):
        """ Handle script run command. """
        from otpme.lib import script
        # Init otpme.
        #init_otpme()
        self.init()

        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Remember original command line to get script options.
        org_cmdline = list(self.command_line)

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=self.command_line,
                                            command_args=local_command_args,
                                            ignore_unknown_opts=True)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        script_type = local_command_args['script_type']

        # Get script options from command line
        script_opts = []
        script_opts_start = False
        for x in org_cmdline:
            if x == object_identifier:
                script_opts_start = True
                continue
            if script_opts_start:
                script_opts.append(x)
        script_options = script_opts

        # Run the script
        script_status, \
        script_stdout, \
        script_stderr, \
        script_pid = script.run(script_path=object_identifier,
                                options=script_options,
                                script_type=script_type)
                                #**command_args)
        # Make sure script output is string.
        script_stdout = script_stdout.decode()
        script_stderr = script_stderr.decode()
        if script_stdout:
            message("Script stdout:")
            message(script_stdout, newline=False)
        if script_stderr:
            message("Script stderr:")
            message(script_stderr, newline=False)

        if script_status != 0:
            raise OTPmeException()

        return ""

    def handle_script_add_command(self, command, subcommand):
        """ Handle script add command. """
        register_module("otpme.lib.multiprocessing")
        # Init otpme.
        #init_otpme()
        self.init()

        # Show help if needed.
        if len(self.command_line) < 1:
            return self.get_help()

        if "--stdin-pass" in self.command_line:
            if config.read_stdin_pass:
                msg = (_("--stdin-pass option conflicts with global option."))
                raise OTPmeException(msg)
            # Get password from stdin if given.
            try:
                # When a user is configured for key_mode=server the private
                # key might be encrypted with a passphrase (AES).
                self.user_aes_pass = stuff.read_pass_from_stdin()
            except:
                pass

        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        object_cmd, \
        object_required, \
        object_identifier, \
        command_args = cli.get_opts(command_syntax=command_syntax,
                                    command_line=self.command_line,
                                    command_args=self.command_args)

        script_path = command_args['script']

        # Read file content.
        fd = open(script_path, "r")
        file_content = fd.read()
        fd.close()

        script_base64 = encode(file_content, "base64")

        # Build final command to OTPme script.
        command_line = [ object_identifier, script_base64 ]

        # Add script.
        try:
            self.send_command(command="script",
                            subcommand="add",
                            command_line=command_line)
        except Exception as e:
            msg = "Error adding script: %s\n" % e
            raise OTPmeException(msg)

    def handle_user_gen_cert_command(self, command, subcommand):
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=self.command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        # Get stdin pass option.
        try:
            stdin_pass = local_command_args['stdin_pass']
        except:
            stdin_pass = False

        # Check if we got "--stdin-pass" (and not the global one)
        if stdin_pass:
            if config.read_stdin_pass:
                msg = (_("--stdin-pass option conflicts with global option."))
                raise OTPmeException(msg)
            # Get key passphrase from stdin.
            self.user_key_pass = sys.stdin.readline().replace("\n", "")

        # Init otpme.
        #init_otpme()
        self.init()
        script_command = [ "gen_csr" ]

        # Run key script to generate a CSR with users private key.
        script_status, \
        script_stdout, \
        script_stderr, \
        script_pid = stuff.run_key_script(username=object_identifier,
                                        script_command=script_command,
                                        key_pass=self.user_key_pass,
                                        call=False)

        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        if script_status != 0:
            self.newline = False
            if script_stderr == "":
                output = script_stdout
            else:
                output = script_stderr
            msg = (_("Error running key script: %s") % output)
            raise OTPmeException(msg)
        if not script_stdout:
            msg = (_("Key script returned no CSR."))
            raise OTPmeException(msg)

        # FIXME: not implemented yet.
        ## Get CSR from key script output
        #cert_req = script_stdout

        #common_name = object_identifier
        #valid=3650

        #country = "DE"
        #state = "RLP"
        #locality = "Koeln"
        #organization = "OTPme"
        #email = "root@otpme.org"

        self.newline = False
        return script_stdout

    def handle_script_edit_command(self):
        """ Handle script edit command. """
        register_module("otpme.lib.multiprocessing")
        from otpme.lib import filetools
        from subprocess import call
        # Init otpme.
        #init_otpme()
        self.init()

        # Show help if needed.
        if len(self.command_line) < 1:
            return self.get_help()

        # Try to get users preferred editor.
        try:
            editor = os.environ['EDITOR']
        except:
            editor = "vim"

        # Get script.
        script_path = self.command_line[0]
        script_content = self.send_command(command="script",
                                        subcommand="dump",
                                        client_type="RAPI")

        # We always use the same filename/path for the temp file to allow
        # vim features like "jump to the last cursor position".
        tmp_file = "%s/%s.tmp" % (config.tmp_dir,
                                stuff.gen_md5(script_path))
        # Generate script md5sum before editing.
        old_script_sum = stuff.gen_md5(script_content)
        # Write script to temp file.
        filetools.create_file(path=tmp_file,
                            content=script_content,
                            user=config.system_user(),
                            mode=0o700)
        # Start editor.
        call([editor, tmp_file])
        # Read file content.
        fd = open(tmp_file, "r")
        file_content = fd.read()
        fd.close()
        # Generate md5sum from edited script.
        new_script_sum = stuff.gen_md5(file_content)
        # Check if file has changed.
        if new_script_sum == old_script_sum:
            os.remove(tmp_file)
            msg = "Nothing changed."
            return msg

        script_base64 = encode(file_content, "base64")

        # Build final command to replace OTPme script with new one.
        command_line = [ '-r', script_path, script_base64 ]

        # Add edited script.
        try:
            self.send_command(command="script",
                            subcommand="add",
                            command_line=command_line)
        except Exception as e:
            msg = "Error updating script: %s\n" % e
            msg = "%sScript saved to temporary file: %s" % (msg, tmp_file)
            raise OTPmeException(msg)

        # Remove temp file
        os.remove(tmp_file)

        # Nothing more to do for edit command
        return ""

    def handle_user_key_pass_command(self):
        """ Handle user key pass command. """
        # Init otpme.
        #init_otpme()
        self.init()
        # Will hold current and new passwords.
        password = None
        new_password = None
        # Get login user.
        login_user = config.login_user

        # Get key mode of users private key (server or client).
        try:
            key_mode = self.get_user_key_mode(username=login_user)
        except Exception as e:
            raise OTPmeException(_("Error getting key mode: %s") % e)

        # Check if we got "--stdin-pass" (and not the global one).
        if "--stdin-pass" in self.command_line:
            if config.read_stdin_pass:
                msg = (_("--stdin-pass option conflicts with global option."))
                raise OTPmeException(msg)
            stdin = sys.stdin.readline().replace("\n", "")
            try:
                password = stdin.split("\0")[0]
                new_password = stdin.split("\0")[1]
            except:
                msg =(_("Input format for --stdin-pass is: "
                        "old_pass\0new_pass"))
                raise OTPmeException(msg)

            if key_mode == "server":
                # Add current and new password to command args.
                self.command_args['password'] = password
                self.command_args['new_password'] = new_password

        if key_mode == "client":
            script_command = [ "change_key_pass" ]
            script_options = []

            # Run key script.
            script_status, \
            script_stdout, \
            script_stderr, \
            script_pid = stuff.run_key_script(username=login_user,
                                            key_pass=password, call=False,
                                            key_pass_new=new_password,
                                            script_command=script_command,
                                            script_options=script_options)

            # Make sure script output is string.
            if isinstance(script_stdout, bytes):
                script_stdout = script_stdout.decode()
            if isinstance(script_stderr, bytes):
                script_stderr = script_stderr.decode()

            if script_status != 0:
                self.newline = False
                if script_stderr == "":
                    msg =(_("Error running key script: %s") % script_stdout)
                    raise OTPmeException(msg)
                else:
                    msg = (_("Error running key script: %s") % script_stderr)
                    raise OTPmeException(msg)

            if not script_stdout:
                msg = (_("Got no private key from key script."))
                raise OTPmeException(msg)

            user_private_key = script_stdout

            # Send private key to server.
            try:
                self.set_user_key(username=login_user,
                                key=user_private_key,
                                private=True,
                                force=True)
            except Exception as e:
                msg = (_("Error sending private key to server: %s") % e)
                raise OTPmeException(msg)

        return ""

    def handle_user_key_import(self, command, subcommand, private_key):
        """ Handle user key import command. """
        # Init otpme.
        #self.init()
        # Get login user.

        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        object_cmd, \
        object_required, \
        object_identifier, \
        command_args = cli.get_opts(command_syntax=command_syntax,
                                    command_line=self.command_line,
                                    command_args=self.command_args)
        try:
            encrypt_key = command_args['encrypt_key']
        except:
            encrypt_key = True

        if not encrypt_key:
            msg = "Cannot import unencrypted key in key mode client"
            raise OTPmeException(msg)

        if not private_key:
            try:
                private_key = command_args['private_key']
            except:
                private_key = None

        if not private_key:
            msg = "No private key received."
            raise OTPmeException(msg)

        # Make sure private key is bytes.
        if isinstance(private_key, str):
            private_key = private_key.encode()

        script_command = [ "encrypt_key" ]
        proc = stuff.run_key_script(username=object_identifier,
                                    call=False,
                                    return_proc=True,
                                    script_command=script_command,
                                    disable_ctrl_c=False)
        proc.stdin.write(private_key)
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait()
        script_stdout = proc.stdout.read()
        script_stderr = proc.stderr.read()
        returncode = proc.returncode
        if returncode != 0:
            self.newline = False
            if script_stderr == "":
                msg =(_("Error running key script: %s") % script_stdout)
                raise OTPmeException(msg)
            else:
                msg = (_("Error running key script: %s") % script_stderr)
                raise OTPmeException(msg)

        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        if not script_stdout:
            msg = (_("Got no key from key script."))
            raise OTPmeException(msg)

        enc_private_key, public_key = script_stdout.split(" ")

        # Send private key to server.
        try:
            self.set_user_key(username=object_identifier,
                            key=enc_private_key,
                            private=True,
                            force=True)
        except Exception as e:
            msg = (_("Error sending private key to server: %s") % e)
            raise OTPmeException(msg)

        # Send private key to server.
        try:
            self.set_user_key(username=object_identifier,
                            key=public_key,
                            private=False,
                            force=True)
        except Exception as e:
            msg = (_("Error sending public key to server: %s") % e)
            raise OTPmeException(msg)

        return ""

    def handle_mount(self, command, subcommand):
        import argparse
        from otpme.lib import cli
        from otpme.lib import multiprocessing
        from otpme.lib.fuse import mount_share
        parser = argparse.ArgumentParser()
        parser.add_argument("--foreground", dest="foreground", action="store_true", help="Run in foreground")
        parser.add_argument("--list", dest="list_shares", action="store_true", help="List shares")
        parser.add_argument('--nodes', dest='nodes')
        parser.add_argument("--encrypted", dest="encrypted", action="store_true", help="Share is encrypted")
        parser.add_argument("--add-share-key", dest="add_share_key", action="store_true", help="Add share key to share")
        parser.add_argument("--master-password-mount", dest="master_password_mount", action="store_true", help="Use master password to mount encrypted share.")
        parser.add_argument('share', nargs='?')
        parser.add_argument('mount', nargs='?')
        args = parser.parse_args(sys.argv)

        if args.add_share_key:
            if not args.master_password_mount:
                msg = "Need --master-password-mount with --add-share-key"
                raise OTPmeException(msg)
            if config.login_user != "root":
                msg = "You must be root for --add-share-key."
                raise OTPmeException(msg)
        self.init(use_backend=False)
        nodes = None
        encrypted = None
        if args.nodes:
            nodes = args.nodes.split(",")
        if args.encrypted:
            encrypted = True
        master_password_mount = args.master_password_mount
        try:
            login_session_id = self.get_login_session_id()
        except Exception as e:
            msg = "Unable to get login session ID: %s" % e
            raise OTPmeException(msg)
        if args.list_shares:
            reply = self.send_command(daemon="mgmtd",
                                    command="get_shares",
                                    parse_command_syntax=False,
                                    client_type="RAPI")
            return reply
        share_id = args.share
        try:
            share_site = share_id.split("/")[0]
            share_name = share_id.split("/")[1]
        except:
            msg = "Invalid share: %s" % share_id
            raise OTPmeException(msg)
        mount_point = args.mount
        if nodes is None or mount_point is None:
            command_args = {'share_id':share_id}
            reply = self.send_command(daemon="mgmtd",
                                    command="get_share",
                                    command_args=command_args,
                                    parse_command_syntax=False,
                                    client_type="RAPI")
            if nodes is None:
                nodes = reply[share_id]['nodes']
            if encrypted is None:
                encrypted = reply[share_id]['encrypted']
            if mount_point is None:
                shares = reply
                try:
                    agent_conn = connections.get("agent")
                except Exception as e:
                    raise OTPmeException(_("Error getting agent connection: %s") % e)
                mount_reply = agent_conn.mount_shares(shares=shares)
                return mount_reply
        if not mount_point:
            msg = "Missing mountpoint."
            raise OTPmeException(msg)
        master_password = None
        if master_password_mount:
            try:
                master_password = cli.read_pass("Master password: ")
            except Exception as e:
                msg = (_("Error reading master password from stdin: %s") % e)
                raise OTPmeException(msg)
        os.environ['OTPME_LOGIN_SESSION'] = login_session_id
        if args.foreground:
            mount_share(share_name,
                        share_site,
                        mount_point,
                        nodes,
                        encrypted,
                        master_password=master_password,
                        add_share_key=args.add_share_key,
                        foreground=args.foreground)
        else:
            mount_proc = multiprocessing.start_process(name="mount",
                                                    target=mount_share,
                                                    target_args=(share_name, share_site, mount_point, nodes, encrypted),
                                                    target_kwargs={
                                                                    'master_password'   : master_password,
                                                                    'add_share_key'     : args.add_share_key,
                                                                    'foreground'        : False,
                                                                },
                                                    daemon=False)
            mount_proc.join()
            if mount_proc.exitcode != 0:
                msg = "Failed to mount share: %s" % share_id
                raise OTPmeException(msg)
            os.system(f"sudo -n setreadahead {mount_point}")
        return

    def handle_smartcard_detection(self, command, subcommand):
        from otpme.lib.smartcard.utils import detect_smartcard
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        local_command_args = {}
        command_line = list(self.command_line)
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))
        try:
            sc_types = local_command_args['smartcard_types']
        except KeyError:
            sc_types = []
        supported_smartcards = config.get_supported_smartcards()
        for sc_type in sc_types:
            if sc_type in supported_smartcards:
                continue
            msg = "Unsupported smartcard type: %s" % sc_type
            raise OTPmeException(msg)
        detect_smartcard(sc_types, detect_only=True, print_devices=True)

    def handle_token_deploy_command(self):
        """ Handle token deploy command. """
        from otpme.lib import json
        from otpme.lib.help import command_map
        # FIXME: make this a config.register_token_deploy(token_type)!!!  
        supported_token_types = config.get_supported_smartcards()

        # Handle --list-token-types option.
        if "--list-token-types" in self.command_line:
            return "\n".join(sorted(supported_token_types))

        # Try to get token type from command line.
        try:
            command_syntax = self.get_command_syntax(command="token", subcommand="deploy")
        except:
            return self.get_help(_("Unknown command: %s") % "deploy")

        # Parse command line.
        show_token_help = True
        local_command_args = {}
        command_line = list(self.command_line)
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                            command_line=command_line,
                                            command_args=local_command_args)
        except Exception as e:
            if config.cli_object_type != "main":
                show_token_help = True
            else:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))

        smartcard_type = config.cli_object_type

        # Indicates if we have to configure the hardware token
        # or just re-configure the OTPme token for the connected
        # hardware token.
        try:
            no_token_write = local_command_args['no_token_write']
        except:
            no_token_write = False

        try:
            replace = local_command_args['replace']
        except:
            replace = False

        try:
            smartcard_client_handler = config.get_smartcard_handler(smartcard_type)[0]
        except NotRegistered:
            raise

        if show_token_help:
            # Set token command help.
            # Get command syntax.
            try:
                command_syntax = command_map['token'][smartcard_type]['deploy']['cmd']
            except:
                msg = (_("Unknown token type: %s") % smartcard_type)
                raise OTPmeException(msg)

            # Parse command line.
            local_command_args = {}
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                local_command_args = cli.get_opts(command_syntax=command_syntax,
                                                command_line=list(self.command_line),
                                                command_args=local_command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    msg = str(e)
                    return self.get_help(message=msg)

        try:
            smartcard_client_handler = smartcard_client_handler(sc_type=smartcard_type,
                                                        token_rel_path=object_identifier)
        except ShowHelp as e:
            return str(e)

        # Init otpme.
        self.init()

        self.command_args['pre_deploy'] = True
        # Build command line for "user deploy_token" command
        user_name = object_identifier.split("/")[0]
        token_name = object_identifier.split("/")[1]
        # Get token type to deploy on server side.
        token_type = smartcard_client_handler.token_type

        self.command_args['replace'] = replace
        self.command_args['smartcard_type'] = smartcard_type
        command_line = [ user_name, token_name, token_type ]
        try:
            pre_deploy_result = self.send_command(daemon="mgmtd",
                                        command="user",
                                        subcommand="deploy_token",
                                        command_line=command_line,
                                        command_args=self.command_args,
                                        client_type="RAPI")
        except Exception as e:
            config.raise_exception()
            raise OTPmeException(_("Unable to deploy token: %s") % e)

        if pre_deploy_result is None:
            return

        deploy_args = smartcard_client_handler.handle_deploy(command_handler=self,
                                                    no_token_write=no_token_write,
                                                    pre_deploy_result=pre_deploy_result)

        # Encode token deploy data (e.g. token keys)
        deploy_data = json.encode(deploy_args, encoding="hex")
        self.command_args['deploy_data'] = deploy_data
        self.command_args['pre_deploy'] = False
        self.command_args['replace'] = False
        self.command_args['force'] = True
        command_line = [ user_name, token_name, token_type ]
        deploy_message = self.send_command(daemon="mgmtd",
                                        command="user",
                                        subcommand="deploy_token",
                                        command_line=command_line,
                                        command_args=self.command_args)
        return deploy_message

    def handle_token_resync_command(self):
        """ Handle token resync command. """
        def get_login_token():
            try:
                reply = self.get_login_token()
                status = True
            except Exception as e:
                reply = str(e)
                status = False
            if status:
                message(_("Unsing login token: %s") % reply)
                return reply

        # Set function to get default object.
        self.get_default_object = get_login_token
        # Try to resync token.
        self.send_command(daemon="mgmtd")
        # Trigger resync of token data (e.g. token counter) after resync of token.
        self.send_command(daemon="hostd", command="sync_token_data")
        return

    def handle_user_dump_key_command(self, command, subcommand):
        """ Handle user dump key command. """
        # Init otpme.
        #init_otpme()
        self.init()
        # Get login user.
        login_user = config.login_user

        # Get key mode of users private key (server or client).
        try:
            key_mode = self.get_user_key_mode(username=login_user)
        except Exception as e:
            config.raise_exception()
            raise OTPmeException(_("Error getting key mode: %s") % e)

        if not key_mode:
            msg = (_("Unable to get users key mode. Private key missing?"))
            raise OTPmeException(msg)

        # Read key pass from stdin if needed.
        if "--stdin-pass" in self.command_line:
            if config.read_stdin_pass:
                msg = (_("--stdin-pass option conflicts with global option."))
                raise OTPmeException(msg)
            try:
                password = sys.stdin.readline().replace("\n", "")
                if key_mode == "server":
                    self.command_args['password'] = password
            except:
                pass

        if key_mode == "server":
            # Get private key.
            user_key = self.send_command(daemon="mgmtd", client_type="RAPI")
            self.newline = True

        if key_mode == "client":
            # Get command syntax.
            try:
                command_syntax = self.get_command_syntax(command, subcommand)
            except:
                return self.get_help(_("Unknown command: %s") % subcommand)

            # Parse command line.
            local_command_args = {}
            command_line = list(self.command_line)
            try:
                object_cmd, \
                object_required, \
                object_identifier, \
                local_command_args = cli.get_opts(command_syntax=command_syntax,
                                                command_line=command_line,
                                                command_args=local_command_args)
            except Exception as e:
                if str(e) == "help":
                    return self.get_help()
                elif str(e) != "":
                    return self.get_help(str(e))

            # When dumping an key that is located on the client side we need to call
            # users key script.
            try:
                unencrypted = local_command_args['decrypt']
            except:
                unencrypted = False
            try:
                private = local_command_args['private']
            except:
                private = False

            if private and unencrypted:
                # Run key script
                script_command = [ 'export_key' ]
                script_status, \
                script_stdout, \
                script_stderr, \
                script_pid = stuff.run_key_script(username=login_user,
                                                key_pass=self.user_key_pass,
                                                script_command=script_command)
                if script_status != 0:
                    raise OTPmeException(script_stderr)

                # Get private key from script stdout.
                user_key = script_stdout
            else:
                # Get private or public key.
                user_key = self.send_command(daemon="mgmtd", client_type="RAPI")
                self.newline = True

        return user_key

    def handle_cluster_status(self, command, subcommand):
        """ Handle auth command. """
        from termcolor import colored
        from otpme.lib import multiprocessing
        from otpme.lib.daemon.controld import ControlDaemon
        register_module("otpme.lib.classes.realm")

        # Init otpme.
        self.init()

        if config.host_data['type'] == "host":
            msg = "This is not a cluster node."
            raise OTPmeException(msg)
        if config.system_user() != "root":
            msg = ("You must be root for this command.")
            raise OTPmeException(msg)

        control_daemon = ControlDaemon(config.controld_pidfile)
        if not control_daemon.status(quiet=True)[0]:
            msg = "OTPme daemon not running."
            raise OTPmeException(msg)

        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        command_line = list(self.command_line)
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            command_args = cli.get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args={})
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                return self.get_help(str(e))

        try:
            diff_data = command_args['diff_data']
        except KeyError:
            diff_data = False

        try:
            full_data_diff = command_args['full_data_diff']
        except KeyError:
            full_data_diff = False

        try:
            full_index_diff = command_args['full_index_diff']
        except KeyError:
            full_index_diff = False

        def get_node_data(node, data_dict, full=False, full_index=False):
            msg = "Reading cluster data from node: %s" % node.name
            print(msg)
            master_node = None
            node_status = data_dict['node_status']
            node_checksums = data_dict['node_checksums']
            socket_uri = stuff.get_daemon_socket("clusterd", node.name)
            try:
                clusterd_conn = connections.get(daemon="clusterd",
                                                socket_uri=socket_uri,
                                                interactive=False,
                                                timeout=600)
            except Exception as e:
                config.raise_exception()
                msg = ("Failed to get cluster connection: %s: %s"
                        % (node.name, e))
                self.logger.warning(msg)
                try:
                    node_status[node.name]['status'] = "Offline"
                except:
                    node_status[node.name] = {'status':"Offline"}
                return
            try:
                # Get master node.
                x_master_node = clusterd_conn.get_master_node()
                try:
                    node_status[node.name]['master'] = x_master_node
                except:
                    node_status[node.name] = {'master':x_master_node}
            except Exception as e:
                x_master_node = None
            if not master_node:
                master_node = x_master_node
            if node.name == master_node:
                data_dict['master_node'] = master_node
                data_dict['cluster_status'] = clusterd_conn.get_cluster_status()
            try:
                # Get cluster quorum.
                quorum = clusterd_conn.get_cluster_quorum()
                try:
                    node_status[node.name]['quorum'] = quorum
                except:
                    node_status[node.name] = {'quorum':quorum}
            except Exception as e:
                try:
                    node_status[node.name]['status'] = "Offline"
                except:
                    node_status[node.name] = {'status':"Offline"}
                return
            try:
                # Get cluster checksums.
                if full:
                    node_checksums[node.name] = clusterd_conn.get_full_checksums()
                elif full_index:
                    node_checksums[node.name] = clusterd_conn.get_index_checksums()
                else:
                    node_checksums[node.name] = clusterd_conn.get_checksums()
            except Exception as e:
                msg = "Checksum request failed: %s" % e
                self.logger.warning(msg)
                node_checksums[node.name] = {}
                node_checksums[node.name]['objects_checksum'] = "Request failed: %s" % e
                node_checksums[node.name]['data_checksum'] = "Request failed: %s" % e
                node_checksums[node.name]['sessions_checksum'] = "Request failed: %s" % e
                try:
                    node_status[node.name]['status'] = "Error"
                except:
                    node_status[node.name] = {'status':"Error"}
                return
            finally:
                clusterd_conn.close()
            try:
                node_status[node.name]['status'] = "Online"
            except:
                node_status[node.name] = {'status':"Online"}

        result = backend.search(object_type="node",
                                attribute="uuid",
                                value="*",
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        data_dict = {
                    'node_status'   : {},
                    'node_checksums': {},
                    'master_node'   : None,
                    'cluster_status': False,
                    }
        node_threads = {}
        for node in result:
            if not node.enabled:
                data_dict['node_status'][node.name] = {}
                data_dict['node_status'][node.name]['status'] = False
                continue
            full = False
            if full_data_diff:
                full = True
            full_index = False
            if full_index_diff:
                full_index = True
            node_data_thread = multiprocessing.start_thread(name=node.name,
                                                        target=get_node_data,
                                                        target_args=(node, data_dict),
                                                        target_kwargs={
                                                                    'full'      : full,
                                                                    'full_index': full_index,
                                                                    },
                                                        daemon=True)
            node_threads[node.name] = node_data_thread

        for node_name in node_threads:
            node_thread = node_threads[node_name]
            node_thread.join()

        node_status = data_dict['node_status']
        node_checksums = data_dict['node_checksums']
        master_node = data_dict['master_node']
        cluster_status = data_dict['cluster_status']

        do_diff_data = False
        do_diff_objects = False
        do_diff_sessions = False
        cluster_in_sync = True
        nodes_in_sync = list(node_checksums.keys())
        if master_node:
            try:
                master_data_checksum = node_checksums[master_node]['data_checksum']
                master_objects_checksum = node_checksums[master_node]['objects_checksum']
                master_sessions_checksum = node_checksums[master_node]['sessions_checksum']
            except KeyError:
                master_data_checksum = None
                master_objects_checksum = None
                master_sessions_checksum = None
            if master_data_checksum:
                for node_name in list(nodes_in_sync):
                    if node_name == master_node:
                        continue
                    # Check objects checksum.
                    if master_objects_checksum != node_checksums[node_name]['objects_checksum']:
                        do_diff_objects = True
                        cluster_in_sync = False
                        try:
                            nodes_in_sync.remove(node_name)
                        except ValueError:
                            pass
                    # Check data checksum.
                    if master_data_checksum != node_checksums[node_name]['data_checksum']:
                        do_diff_data = True
                        cluster_in_sync = False
                        try:
                            nodes_in_sync.remove(node_name)
                        except ValueError:
                            pass
                    # Check sessions checksum.
                    if master_sessions_checksum != node_checksums[node_name]['sessions_checksum']:
                        do_diff_sessions = True
                        cluster_in_sync = False
                        try:
                            nodes_in_sync.remove(node_name)
                        except ValueError:
                            pass

        if cluster_status:
            cstring = "Cluster status: Online"
            cstring = colored(cstring, "green")
        else:
            cstring = "Cluster status: Offline"
            cstring = colored(cstring, "red")

        own_site = backend.get_object(uuid=config.site_uuid)
        if own_site.required_votes:
            wstring = ("(Warning: required votes set to %s)"
                        % own_site.required_votes)
            wstring = colored(wstring, "yellow")
            cstring = "%s %s" % (cstring, wstring)

        cluster_status_str = [cstring]

        diff_objects = []
        missing_objects = []
        for x_node in sorted(node_status):
            try:
                x_node_status = node_status[x_node]['status']
            except KeyError:
                x_node_status = "Unknown"
            if not x_node_status:
                x_status_line = "%s Disabled" % x_node
                x_status_line = colored(x_status_line, 'light_grey')
                cluster_status_str.append(x_status_line)
                continue
            try:
                x_node_master = node_status[x_node]['master']
            except KeyError:
                x_node_master = "Unknown"
            try:
                x_node_quorum = node_status[x_node]['quorum']
            except KeyError:
                x_node_quorum = "Unknown"
            if x_node_status == "Offline":
                x_status_line = "%s (Offline)" % x_node
                x_status_line = colored(x_status_line, "red")
            elif x_node_status == "Error":
                x_status_line = "%s (Error)" % x_node
                x_status_line = colored(x_status_line, "red")
            else:
                try:
                    data_checksum = node_checksums[x_node]['data_checksum']
                except KeyError:
                    data_checksum = None
                try:
                    objects_checksum = node_checksums[x_node]['objects_checksum']
                except KeyError:
                    objects_checksum = None
                try:
                    sessions_checksum = node_checksums[x_node]['sessions_checksum']
                except KeyError:
                    sessions_checksum = None
                x_status_line = ("%s (Quorum: %s) (Master: %s) (Objects: %s) (Data: %s) (Sessions: %s)"
                                % (x_node, x_node_quorum, x_node_master, objects_checksum, data_checksum, sessions_checksum))
                if x_node_master == "Unknown":
                    x_status_line = colored(x_status_line, 'red')
                else:
                    if x_node_quorum:
                        if x_node in nodes_in_sync:
                            x_status_line = colored(x_status_line, 'green')
                        else:
                            x_status_line = colored(x_status_line, 'yellow')
                    else:
                            x_status_line = colored(x_status_line, 'yellow')
            cluster_status_str.append(x_status_line)

            if cluster_in_sync:
                continue

            if x_node_status == "Offline":
                continue

            if x_node == master_node:
                continue

            if diff_data:
                already_missed_datas= {}
                already_missed_objects = {}
                already_missed_sesssions = {}
                already_diffed_datas = {}
                already_diffed_objects = {}
                already_diffed_sessions = {}
                try:
                    m_data_checksums = node_checksums[master_node]['data_checksums']
                except KeyError:
                    m_data_checksums = {}
                try:
                    m_object_checksums = node_checksums[master_node]['object_checksums']
                except KeyError:
                    m_object_checksums = {}
                try:
                    m_session_checksums = node_checksums[master_node]['session_checksums']
                except KeyError:
                    m_session_checksums = {}

                try:
                    n_data_checksums = node_checksums[x_node]['data_checksums']
                except KeyError:
                    n_data_checksums = {}
                try:
                    n_object_checksums = node_checksums[x_node]['object_checksums']
                except KeyError:
                    n_object_checksums = {}
                try:
                    n_session_checksums = node_checksums[x_node]['session_checksums']
                except KeyError:
                    n_session_checksums = {}

                # Diff objects.
                if do_diff_objects:
                    for m_object in m_object_checksums:
                        m_checksum = m_object_checksums[m_object]
                        try:
                            n_checksum = n_object_checksums[m_object]
                        except:
                            try:
                                n_missing_objects = already_missed_objects[x_node]
                            except KeyError:
                                n_missing_objects = []
                            if m_object in n_missing_objects:
                                continue
                            n_missing_objects.append(m_object)
                            already_missed_objects[x_node] = n_missing_objects
                            msg = "Object %s missing on node %s." % (m_object, x_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue
                        if n_checksum == m_checksum:
                            continue
                        try:
                            n_diffed_objects = already_diffed_objects[x_node]
                        except KeyError:
                            n_diffed_objects = []
                        if m_object in n_diffed_objects:
                            continue
                        n_diffed_objects.append(m_object)
                        already_diffed_objects[x_node] = n_diffed_objects
                        msg = ("Object %s differs on node %s: %s <> %s" %
                                (m_object, x_node, m_checksum, n_checksum))
                        msg = colored(msg, 'yellow')
                        diff_objects.append(msg)

                    for n_object in n_object_checksums:
                        try:
                            m_object_checksums[n_object]
                        except KeyError:
                            try:
                                m_missing_objects = already_missed_objects[master_node]
                            except KeyError:
                                m_missing_objects = []
                            if n_object in m_missing_objects:
                                continue
                            m_missing_objects.append(n_object)
                            already_missed_objects[master_node] = m_missing_objects
                            msg = "Object %s missing on node %s." % (n_object, master_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue

                # Diff data objects.
                if do_diff_data:
                    for m_data in m_data_checksums:
                        m_checksum = m_data_checksums[m_data]
                        try:
                            n_checksum = n_data_checksums[m_data]
                        except:
                            try:
                                n_missing_datas = already_missed_datas[x_node]
                            except KeyError:
                                n_missing_datas = []
                            if m_data in n_missing_datas:
                                continue
                            n_missing_datas.append(m_data)
                            already_missed_datas[x_node] = n_missing_datas
                            msg = "Data object %s missing on node %s." % (m_data, x_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue
                        if n_checksum == m_checksum:
                            continue
                        try:
                            n_diffed_datas = already_diffed_datas[x_node]
                        except KeyError:
                            n_diffed_datas = []
                        if m_data in n_diffed_datas:
                            continue
                        n_diffed_datas.append(m_data)
                        already_diffed_datas[x_node] = n_diffed_datas
                        msg = ("Object %s differs on node %s: %s <> %s"
                                % (m_data, x_node, m_checksum, n_checksum))
                        msg = colored(msg, 'yellow')
                        diff_objects.append(msg)

                    for n_data in n_data_checksums:
                        try:
                            m_data_checksums[n_data]
                        except KeyError:
                            try:
                                m_missing_datas = already_missed_datas[master_node]
                            except KeyError:
                                m_missing_datas = []
                            if n_data in m_missing_datas:
                                continue
                            m_missing_datas.append(n_data)
                            already_missed_datas[master_node] = m_missing_datas
                            msg = "Data object %s missing on node %s." % (n_data, master_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue

                # Diff session objects.
                if do_diff_sessions:
                    for m_session in m_session_checksums:
                        m_checksum = m_session_checksums[m_session]
                        try:
                            n_checksum = n_session_checksums[m_session]
                        except KeyError:
                            try:
                                n_missing_sessions = already_missed_sesssions[x_node]
                            except KeyError:
                                n_missing_sessions = []
                            if m_session in n_missing_sessions:
                                continue
                            n_missing_sessions.append(m_session)
                            already_missed_sesssions[x_node] = n_missing_sessions
                            msg = "Session %s missing on node %s." % (m_session, x_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue
                        if n_checksum == m_checksum:
                            continue
                        try:
                            n_diffed_sessions = already_diffed_sessions[x_node]
                        except KeyError:
                            n_diffed_sessions = []
                        if m_session in n_diffed_sessions:
                            continue
                        n_diffed_sessions.append(m_session)
                        already_diffed_sessions[x_node] = n_diffed_sessions
                        msg = ("Session %s differs on node %s: %s <> %s"
                                % (m_session, x_node, m_checksum, n_checksum))
                        msg = colored(msg, 'yellow')
                        diff_objects.append(msg)

                    for n_session in n_session_checksums:
                        n_checksum = n_session_checksums[n_session]
                        try:
                            m_session_checksums[n_session]
                        except:
                            try:
                                m_missing_sessions = already_missed_sesssions[master_node]
                            except KeyError:
                                m_missing_sessions = []
                            if n_session in m_missing_sessions:
                                continue
                            m_missing_sessions.append(n_session)
                            already_missed_sesssions[master_node] = m_missing_sessions
                            msg = "Session %s missing on node %s." % (n_session, master_node)
                            msg = colored(msg, 'red')
                            missing_objects.append(msg)
                            continue

        diff_details = diff_objects + missing_objects
        if diff_details:
            msg = "Misses: %s" % len(missing_objects)
            diff_details.append(msg)
            msg = "Diffs: %s" % len(diff_objects)
            diff_details.append(msg)
            diff_details.append("")
            cluster_status_str = diff_details + cluster_status_str

        cluster_status_str = "\n".join(cluster_status_str)
        return cluster_status_str

    def check_node_vote_status(self, node_name):
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = "Failed to get hostd connection: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", node_name)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            msg = ("Failed to get node connection: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            node_vote = clusterd_conn.get_node_vote()
        except Exception as e:
            msg = ("Node vote check failed: %s: %s" % (node_name, e))
            raise OTPmeException(msg)
        if node_vote == 0:
            msg = "Node not ready."
            raise OTPmeException(msg)

    def check_node_sync_status(self, node_name):
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = "Failed to get hostd connection: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", node_name)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            msg = ("Failed to get node connection: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            master_sync_status = clusterd_conn.get_master_sync_status()
        except Exception as e:
            msg = ("Master sync check failed: %s: %s" % (node_name, e))
            raise OTPmeException(msg)
        if not master_sync_status:
            msg = "Node master sync not finished."
            raise OTPmeException(msg)
        try:
            node_sync_status = clusterd_conn.get_node_sync_status()
        except Exception as e:
            msg = ("Node sync check failed: %s: %s" % (node_name, e))
            raise OTPmeException(msg)
        if not node_sync_status:
            msg = "Node not in sync."
            raise OTPmeException(msg)

    def start_master_failover(self, node_name):
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = "Failed to get hostd connection: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", node_name)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            raise OTPmeException(msg)
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            msg = ("Failed to get master node connection: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise OTPmeException(msg)

        try:
            clusterd_conn.start_master_failover()
        except Exception as e:
            msg = ("Failed to start master failover: %s: %s"
                    % (node_name, e))
            raise OTPmeException(msg)
        finally:
            clusterd_conn.close()

    def handle_required_votes(self, required_votes):
        """ Handle required quorum command. """
        register_module("otpme.lib.classes.realm")
        register_module("otpme.lib.daemon.clusterd")
        if config.system_user() != "root":
            msg = ("You must be root for this command.")
            raise OTPmeException(msg)
        # Init otpme.
        self.init()
        # Get our node.
        this_node_name = config.host_data['name']
        result = backend.search(object_type="node",
                                attribute="name",
                                value=this_node_name,
                                return_type="instance")
        if not result:
            msg = "Unknown node: %s" % this_node_name
            msg = colored(msg, 'red')
            raise OTPmeException(msg)

        this_node = result[0]
        if not this_node.enabled:
            msg = "Node disabled."
            msg = colored(msg, 'red')
            raise OTPmeException(msg)

        # Get socket uri.
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = "Failed to get hostd connection: %s" % e
            self.logger.warning(msg)
            return
        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", this_node.name)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            return msg
        # Get connection to node.
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            config.raise_exception()
            msg = ("Failed to get cluster connection: %s: %s"
                    % (this_node.name, e))
            self.logger.warning(msg)
            return msg
        # Set required votes.
        try:
            result = clusterd_conn.set_required_votes(required_votes)
        except Exception as e:
            msg = str(e)
            self.logger.warning(msg)
            config.raise_exception()
            return msg

        return result

    def handle_master_failover(self, new_master=None,
        random_node=False, wait=False):
        """ Handle master failover command. """
        import random
        from termcolor import colored
        register_module("otpme.lib.classes.realm")
        register_module("otpme.lib.daemon.clusterd")
        if config.system_user() != "root":
            msg = ("You must be root for this command.")
            raise OTPmeException(msg)
        # Init otpme.
        #init_otpme()
        self.init()
        # Get this node.
        this_node_name = config.host_data['name']
        result = backend.search(object_type="node",
                                attribute="name",
                                value=this_node_name,
                                return_type="instance")
        if not result:
            msg = "Unknown node: %s" % this_node_name
            msg = colored(msg, 'red')
            raise OTPmeException(msg)

        this_node = result[0]
        if not this_node.enabled:
            msg = "Node disabled."
            msg = colored(msg, 'red')
            raise OTPmeException(msg)

        master_node = config.get_master_node()
        if random_node:
            if this_node.name != master_node:
                msg = "Node not the master node."
                msg = colored(msg, 'red')
                return msg
        elif new_master:
            result = backend.search(object_type="node",
                                    attribute="name",
                                    value=new_master,
                                    realm=config.realm,
                                    site=config.site)
            if not result:
                msg = "Unknown node: %s" % new_master
                msg = colored(msg, 'red')
                return msg
        else:
            if not config.force:
                if this_node.name == master_node:
                    msg = "Node already master node."
                    msg = colored(msg, 'red')
                    return msg

        msg = "Checking for cluster quorum..."
        msg = colored(msg, 'green')
        print(msg)
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = "Failed to get hostd connection: %s" % e
            self.logger.warning(msg)
            return

        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", this_node.name)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            return msg
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            config.raise_exception()
            msg = ("Failed to get cluster connection: %s: %s"
                    % (this_node.name, e))
            self.logger.warning(msg)
            return msg

        try:
            this_node_quorum = clusterd_conn.get_cluster_quorum()
        except Exception as e:
            msg = ("Failed to get cluster quorum: %s: %s"
                    % (this_node.name, e))
            self.logger.warning(msg)
            config.raise_exception()
            return msg
        if not this_node_quorum:
            msg = "No cluster quorum."
            msg = colored(msg, 'red')
            return msg
        if random_node:
            msg = "Trying to find a node to switch to..."
            msg = colored(msg, 'green')
            print(msg)
            # Get all member nodes
            try:
                member_nodes = clusterd_conn.get_member_nodes()
            except Exception as e:
                msg = ("Failed to get cluster nodes: %s: %s"
                        % (this_node.name, e))
                self.logger.warning(msg)
                return msg
            try:
                member_nodes.remove(this_node.name)
            except ValueError:
                pass
            # Try to find new master node.
            while True:
                if len(member_nodes) == 0:
                    msg = "Master failover failed: Unable to find node to switch to."
                    msg = colored(msg, 'red')
                    return msg
                new_master_node = random.choice(member_nodes)
                if not wait:
                    member_nodes.remove(new_master_node)
                try:
                    self.check_node_sync_status(new_master_node)
                except Exception as e:
                    msg = ("Will not switch to unsync node: %s: %s"
                            % (new_master_node, e))
                    self.logger.debug(msg)
                    continue
                try:
                    self.check_node_vote_status(new_master_node)
                except Exception as e:
                    msg = ("Will not switch to unsync node: %s: %s"
                            % (new_master_node, e))
                    self.logger.debug(msg)
                    continue
                break

            msg = ("Will switch to node: %s" % new_master_node)
            msg = colored(msg, 'green')
            print(msg)

            if master_node:
                msg = ("Setting master failover status on current master node: %s"
                        % master_node)
                msg = colored(msg, 'green')
                print(msg)
                while True:
                    try:
                        self.start_master_failover(master_node)
                        msg = "Master node ready..."
                        msg = colored(msg, 'green')
                        print(msg)
                        break
                    except Exception as e:
                        msg = str(e)
                        if wait:
                            msg = colored(msg, 'red')
                            print(msg)
                            continue
                        else:
                            return msg
            msg = "Trying to switch to new master node: %s" % new_master_node
            msg = colored(msg, 'green')
            print(msg)
            try:
                socket_uri = hostd_conn.get_daemon_socket("clusterd", new_master_node)
            except Exception as e:
                msg = "Failed to get daemon socket from hostd: %s" % e
                self.logger.warning(msg)
                return msg
            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=30,
                                                socket_uri=socket_uri)
            except Exception as e:
                config.raise_exception()
                msg = ("Failed to get cluster connection: %s: %s"
                        % (new_master_node, e))
                self.logger.warning(msg)
                return msg
            try:
                # Do master failover.
                failover_status = clusterd_conn.do_master_failover()
                failover_status = colored(failover_status, 'green')
            except Exception as e:
                failover_status = "Master failover failed: %s" % e
                failover_status = colored(failover_status, 'red')
            return failover_status

        new_master_node = this_node.name
        if new_master:
            new_master_node = new_master

        if new_master_node == master_node:
            msg = "Node already the master node: %s" % new_master_node
            msg = colored(msg, 'red')
            return msg

        msg = ("Checking node sync status: %s" % new_master_node)
        msg = colored(msg, 'green')
        print(msg)
        while True:
            try:
                self.check_node_vote_status(new_master_node)
                break
            except Exception as e:
                msg = ("Will not switch to not ready node: %s: %s"
                        % (new_master_node, e))
                self.logger.debug(msg)
                msg = colored(msg, 'red')
                if wait:
                    print(msg)
                    time.sleep(1)
                else:
                    return msg
            try:
                self.check_node_sync_status(new_master_node)
                break
            except Exception as e:
                msg = ("Will not switch to unsync node: %s: %s"
                        % (new_master_node, e))
                self.logger.debug(msg)
                msg = colored(msg, 'red')
                if wait:
                    print(msg)
                    time.sleep(1)
                else:
                    return msg
        try:
            socket_uri = hostd_conn.get_daemon_socket("clusterd", new_master_node)
        except Exception as e:
            msg = "Failed to get daemon socket from hostd: %s" % e
            self.logger.warning(msg)
            return msg
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=30,
                                            socket_uri=socket_uri)
        except Exception as e:
            config.raise_exception()
            msg = ("Failed to get cluster connection: %s: %s"
                    % (new_master_node, e))
            self.logger.warning(msg)
            return msg
        if master_node:
            msg = ("Setting master failover status on current master node: %s"
                    % master_node)
            msg = colored(msg, 'green')
            print(msg)
            while True:
                try:
                    self.start_master_failover(master_node)
                    msg = "Master node ready..."
                    msg = colored(msg, 'green')
                    print(msg)
                    break
                except Exception as e:
                    msg = str(e)
                    if wait:
                        msg = colored(msg, 'red')
                        print(msg)
                        continue
                    else:
                        return msg
        msg = "Trying to switch to new master node: %s" % new_master_node
        msg = colored(msg, 'green')
        print(msg)
        try:
            # Do master failover.
            failover_status = clusterd_conn.do_master_failover()
            failover_status = colored(failover_status, 'green')
        except Exception as e:
            failover_status = "Master failover failed: %s" % e
            failover_status = colored(failover_status, 'red')

        return failover_status

    def handle_auth_command(self, command, subcommand, command_line):
        """ Handle auth command. """
        register_module("otpme.lib.classes.realm")
        self.init(use_backend=False)
        cache.init()
        cache.enable()
        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command, subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)
        object_cmd, \
        object_required, \
        object_list, \
        command_args = cli.get_opts(command_syntax=command_syntax,
                                    command_line=command_line,
                                    command_args=self.command_args)

        try:
            use_socket = command_args.pop('use_socket')
        except:
            use_socket = False

        socket_uri = None
        if use_socket:
            socket_uri = config.authd_socket_path

        result = self.send_command(daemon="authd",
                                command=subcommand,
                                command_line=command_line,
                                command_args=command_args,
                                parse_command_syntax=False,
                                socket_uri=socket_uri,
                                timeout=120,
                                interactive=False)
        return result

    def handle_add_user_command(self):
        """ Handle add user command. """
        if len(self.command_line) < 1:
            return self.get_help()

        filename = self.command_line[0]
        try:
            fd = open(filename,'r')
        except (OSError, IOError) as e:
            raise OTPmeException(_("Error reading users file: %s") % e)

        user_list = []
        for line in fd:
            if not line.startswith("#"):
                username = line.replace("\n", "")
                user_list.append(username)

        fd.close()
        return self.add_users(user_list)

    def handle_key_script_command(self, subcommand):
        """ Handle key script commands. """
        # Init otpme.
        if config.use_api:
            #init_otpme()
            self.init()
        # Will hold private key passphrase.
        key_pass = None
        # Will hold AES key passphrase.
        aes_pass = None

        # Get login user.
        login_user = config.login_user

        # Get command syntax.
        try:
            command_syntax = self.get_command_syntax(command=self.command,
                                                    subcommand=subcommand)
        except:
            return self.get_help(_("Unknown command: %s") % subcommand)

        # Parse command line.
        local_command_args = {}
        try:
            object_cmd, \
            object_required, \
            object_identifier, \
            local_command_args = cli.get_opts(command_syntax=command_syntax,
                                                command_line=self.command_line,
                                                command_args=local_command_args)
        except Exception as e:
            if str(e) == "help":
                return self.get_help()
            elif str(e) != "":
                raise OTPmeException(str(e))

        # Get filenames.
        file1 = local_command_args['file1']
        file2 = local_command_args['file2']

        # Command line we have to pass to key script.
        script_command = subcommand.split(" ")

        # Get key mode of users private key (server or client).
        try:
            key_mode = self.get_user_key_mode(username=login_user)
        except Exception as e:
            raise OTPmeException(_("Error getting key mode: %s") % e)

        if key_mode == "server":
            script_command.append("--server-key")

        # Get script options:
        # -u: Username which public key to use for encrpytion.
        # --rsa: Use plain RSA encrpytion.
        # --no-rsa: Disable use of RSA public keys for encryption of AES keys.
        #        to secure AES key).
        # --pass: Password to use for de/encrpytion (AES only)
        # --stdin-pass: Read RSA/AES key passphrase from stdin.
        try:
            username = local_command_args['username']
            script_command.append("-u")
            script_command.append(username)
        except:
            pass
        try:
            if local_command_args['use_rsa']:
                script_command.append("--rsa")
        except:
            pass
        try:
            if local_command_args['no_rsa']:
                script_command.append("--no-rsa")
        except:
            pass
        try:
            if local_command_args['password']:
                if 'no_rsa' in local_command_args:
                    aes_pass = local_command_args['password']
        except:
            pass
        try:
            if local_command_args['force_pass']:
                script_command.append("--force-pass")
        except:
            pass

        try:
            if local_command_args['stdin_pass']:
                try:
                    password = sys.stdin.readline().replace("\n", "")
                except:
                    password = None
                if 'no_rsa' in local_command_args:
                    aes_pass = password
                else:
                    key_pass = password
        except:
            pass

        script_options = [ file1, file2 ]

        script_status, \
        script_stdout, \
        script_stderr, \
        script_pid = stuff.run_key_script(username=login_user,
                                        key_pass=key_pass,
                                        aes_pass=aes_pass,
                                        script_command=script_command,
                                        script_options=script_options)

        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        self.newline = False
        if script_status != 0:
            script_output = ""
            if script_stdout:
                script_output = script_stdout
            if script_stderr:
                script_output = "%s\n%s" % (script_output, script_stderr)
            raise OTPmeException(script_output)

        return script_stdout
