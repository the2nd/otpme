# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib import cache
from otpme.lib import stuff
from otpme.lib import config
#from otpme.lib import locking
from otpme.lib import backend
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.daemon.clusterd import cluster_radius_reload

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-host-1.0"

#valid_agent_lock_types = [
#                        'agent.connection',
#                        ]

def register():
    config.register_otpme_protocol("hostd", PROTOCOL_VERSION, server=True)

class OTPmeHostP1(OTPmeServer1):
    """ Class that implements OTPme-host-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "hostd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Indicates parent class that we need no authentication.
        self.require_auth = None
        self.require_preauth = False
        # FIXME: Currently hostd only uses unix sockets so there is no
        #        encryption involved.
        self.require_client_cert = False
        # Communication with hostd is only done via unix sockets.
        self.encrypt_session = False
        self.require_master_node = False
        self.require_cluster_status = False
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def get_password_score(self, password, policy_name=None):
        """ Get password strength score via policy. """
        # Try to get policy object.
        if policy_name:
            result = backend.search(object_type="policy",
                                    attribute="name",
                                    value=policy_name,
                                    return_type="instance")
            if not result:
                raise Exception("Unknown policy.")
            policy = result[0]
        else:
            # Without policy try to get password policy of host.
            my_host = backend.get_object(object_type=self.host_type,
                                            uuid=config.uuid)
            policy = None
            for uuid in my_host.get_policies():
                p = backend.get_object(object_type="policy", uuid=uuid)
                if p.policy_type == "password":
                    policy = p
                    break
            if not policy:
                raise Exception("No password policy configured for host.")

        # Check password via policy.
        score = policy.check_password(password, score_only=True)
        return score

    def authorize_token(self, token_uuid, login_interface=None):
        """ Check if given token is allowed to login. """
        # Check host status.
        myhost = backend.get_object(object_type=self.host_type,
                                        uuid=config.uuid)
        if not myhost.enabled:
            message = "Host disabled"
            raise PolicyException(message)

        # Check host policies.
        myhost.run_policies("authenticate")

        # Check token status.
        token = backend.get_object(object_type="token", uuid=token_uuid)
        if not token:
            message = "Unknown token."
            raise PolicyException(message)
        if not token.enabled:
            message = "Token disabled."
            raise PolicyException(message)

        # Check token policies.
        token.run_policies("authenticate")

        # Check user status.
        user = backend.get_object(object_type="user", uuid=token.owner_uuid)
        if not user:
            message = "Unknown user."
            raise PolicyException(message)
        if not user.enabled:
            message = "User disabled."
            raise PolicyException(message)

        # Check user policies.
        user.run_policies("authenticate")

        # Check token role/group policies.
        myhost.authorize_token(token, login_interface=login_interface)

    def _process(self, command, command_args):
        """ Handle commands received from host_handler. """
        # all valid commands
        valid_commands = [
                            "get_realm",
                            "get_realm_uuid",
                            "get_site",
                            "get_site_uuid",
                            "get_site_address",
                            "get_site_auth_fqdn",
                            "get_site_mgmt_fqdn",
                            "get_realm_master_uuid",
                            "get_realm_master_name",
                            "get_realm_master_address",
                            "get_site_cert",
                            "get_site_trust_status",
                            "get_user_uuid",
                            "get_user_name",
                            "get_user_site",
                            "get_host_status",
                            "get_pass_strength",
                            "authorize_token",
                            "dump_instance_cache",
                            "dump_acl_cache",
                            "dump_sync_map",
                            "dump_object_counter",
                            "sync_sites",
                            "sync_objects",
                            "sync_nsscache",
                            "sync_token_data",
                            "resync_objects",
                            "resync_nsscache",
                            "sync_ssh_authorized_keys",
                            "get_sync_status",
                            "get_daemon_socket",
                            "acquire_lock",
                            "release_lock",
                            "reload_radius",
                        ]

        if command in valid_commands:
            if config.debug_level() > 3:
                msg = ("Received command %s from client: %s"
                        % (command, self.client))
                logger.debug(msg)
        else:
            msg = ("Received unknown command %s from client: %s"
                    % (command, self.client))
            logger.warning(msg)

        # check if we got a valid command
        if not command in valid_commands:
            message = "Unknown command: %s" % command
            status = False

        elif command == "get_realm":
            message = config.realm
            status = True

        elif command == "get_realm_uuid":
            message = config.realm_uuid
            status = True

        elif command == "get_site":
            message = config.site
            status = True

        elif command == "get_site_uuid":
            message = config.site_uuid
            status = True

        elif command == "get_realm_master_uuid":
            message = config.realm_master_uuid
            status = True

        elif command == "get_realm_master_name":
            realm_master = backend.get_object(object_type="node",
                                    uuid=config.realm_master_uuid)
            status = False
            message = "Unknown node: %s" % config.realm_master_uuid
            if realm_master:
                message = realm_master.name
                status = True

        elif command == "get_realm_master_address":
            realm_master = backend.get_object(object_type="node",
                                    uuid=config.realm_master_uuid)
            status = False
            message = "Unknown node: %s" % config.realm_master_uuid
            if realm_master:
                message = realm_master.address
                status = True

        elif command == "get_site_address":
            status = True
            try:
                realm = command_args['realm']
            except:
                realm = None
            try:
                site = command_args['site']
            except:
                site = None

            if realm and site:
                try:
                    site_address = stuff.get_site_address(realm, site)
                except Exception as e:
                    status = False
                    message = "Failed to get site address: %s" % e
            else:
                site_address = config.site_address

            if status:
                message = site_address


        elif command == "get_site_auth_fqdn":
            status = True
            try:
                realm = command_args['realm']
            except:
                realm = None
            try:
                site = command_args['site']
            except:
                site = None

            if realm and site:
                try:
                    auth_fqdn = stuff.get_site_fqdn(realm, site)
                except Exception as e:
                    status = False
                    message = "Failed to get site address: %s" % e
            else:
                auth_fqdn = config.site_auth_fqdn

            if status:
                message = auth_fqdn

        elif command == "get_site_mgmt_fqdn":
            status = True
            try:
                realm = command_args['realm']
            except:
                realm = None
            try:
                site = command_args['site']
            except:
                site = None

            if realm and site:
                try:
                    mgmt_fqdn = stuff.get_site_fqdn(realm,
                                                    site,
                                                    mgmt=True)
                except Exception as e:
                    status = False
                    message = "Failed to get site address: %s" % e
            else:
                mgmt_fqdn = config.site_mgmt_fqdn

            if status:
                message = mgmt_fqdn

        elif command == "get_site_trust_status":
            status = True
            try:
                realm_name = command_args['realm']
            except:
                realm_name = None
                message = "INCOMPLETE_COMMAND"
                status = False
            try:
                site_name = command_args['site']
            except:
                site_name = None
                message = "INCOMPLETE_COMMAND"
                status = False

            if status:
                try:
                    stuff.get_site_trust_status(realm_name, site_name)
                    message = "trusted"
                except SiteNotTrusted as e:
                    message = str(e)
                except Exception as e:
                    status = False
                    message = "Failed to get site trust status: %s" % e

        elif command == "get_site_cert":
            status = True
            try:
                realm_name = command_args['realm']
            except:
                realm_name = None
                message = "INCOMPLETE_COMMAND"
                status = False
            try:
                site_name = command_args['site']
            except:
                site_name = None
                message = "INCOMPLETE_COMMAND"
                status = False

            if realm_name and site_name:
                # Load certificate of given site.
                result = backend.search(object_type="site",
                                        attribute="name",
                                        value=site_name,
                                        realm=realm_name,
                                        return_type="instance")
                status = False
                if result:
                    site = result[0]
                    if site.cert:
                        status = True
                        message = site.cert
                    else:
                        message = "Site does not have a certificate."
                else:
                    message = "Unknown site: %s" % site_name


        elif command == "get_user_site":
            try:
                username = command_args['username']
            except:
                username = None
                message = "%s INCOMPLETE_COMMAND" % status_codes.ERR
                status = False

            if username:
                if "@" in username:
                    user_name = username.split("@")[0]
                    user_realm = username.split("@")[1]
                else:
                    user_name = username
                    user_realm = config.realm
                u = backend.get_object(object_type="user",
                                        realm=user_realm,
                                        name=user_name)
                if u.exists():
                    message = u.site
                    status = True
                else:
                    message = "Unknown user"
                    status = False


        elif command == "get_user_uuid":
            try:
                username = command_args['username']
            except:
                username = None
                message = "%s INCOMPLETE_COMMAND" % status_codes.ERR
                status = False

            if username:
                u = backend.get_object(object_type="user",
                                    realm=config.realm,
                                    name=username)
                if u:
                    message = u.uuid
                    status = True
                else:
                    message = "Unknown user"
                    status = False

        elif command == "get_user_name":
            try:
                user_uuid = command_args['user_uuid']
            except:
                user_uuid = None
                message = "INCOMPLETE_COMMAND"
                status = False

            if user_uuid:
                u = backend.get_object(object_type="user", uuid=user_uuid)
                if u:
                    message = u.name
                    status = True
                else:
                    message = "Unknown user."
                    status = False

        elif command == "get_host_status":
            myhost = backend.get_object(object_type=self.host_type,
                                            uuid=config.uuid)
            if myhost.enabled:
                message = "Host enabled"
                status = True
            else:
                message = "Host disabled"
                status = False

        elif command == "authorize_token":
            try:
                token_uuid = command_args['token_uuid']
            except:
                token_uuid = None
                message = "INCOMPLETE_COMMAND"
                status = False

            try:
                login_interface = command_args['login_interface']
            except:
                login_interface = None

            if token_uuid:
                try:
                    self.authorize_token(token_uuid=token_uuid,
                                login_interface=login_interface)
                    message = "Token authorized to login."
                    status = True
                except LoginsLimited as e:
                    message = str(e)
                    status = False
                except PolicyException as e:
                    message = str(e)
                    status = False
                except Exception as e:
                    msg = "Internal server error: %s" % e
                    logger.critical(msg)

        elif command == "get_pass_strength":
            # Get password to check.
            try:
                password = command_args['password']
            except:
                password = None
                message = "INCOMPLETE_COMMAND"
                status = False

           # Try to get policy name.
            try:
                policy_name = command_args['policy']
            except:
                policy_name = None

            try:
                message = self.get_password_score(password=password,
                                            policy_name=policy_name)
                status = True
            except Exception as e:
                message = str(e)
                status = False
                logger.warning(message)

        elif command == "dump_instance_cache":
            try:
                parameter = command_args['parameter']
            except:
                parameter = None

            if parameter:
                if '*' in parameter:
                    object_id = None
                    search_regex = parameter
                else:
                    object_id = parameter
                    search_regex = None
            else:
                object_id = None
                search_regex = None

            if self.client_user == "root":
                try:
                    message = cache.dump_instance_cache(object_id=object_id,
                                                    search_regex=search_regex)
                except Exception as e:
                    message = str(e)
                status = True
            else:
                message = "Permission denied."
                status = False

        elif command == "dump_acl_cache":
            try:
                parameter = command_args['parameter']
            except:
                parameter = None

            if parameter:
                if '*' in parameter:
                    object_id = None
                    search_regex = parameter
                else:
                    object_id = parameter
                    search_regex = None
            else:
                object_id = None
                search_regex = None

            if self.client_user == "root":
                try:
                    message = cache.dump_acl_cache(object_id=object_id,
                                                search_regex=search_regex)
                except Exception as e:
                    message = str(e)
                status = True
            else:
                message = "Permission denied."
                status = False

        elif command == "dump_sync_map":
            if self.client_user == "root":
                try:
                    message = backend.dump_sync_map()
                except Exception as e:
                    message = str(e)
                status = True
            else:
                message = "Permission denied."
                status = False

        elif command == "sync_sites":
            try:
                self._send_daemon_msg(self.name, "sync_sites")
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "sync_token_data":
            try:
                self._send_daemon_msg(self.name, "sync_token_data")
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "sync_objects":
            # Build sync command.
            try:
                realm = command_args['realm']
            except:
                realm = None
            try:
                site = command_args['site']
            except:
                site = None
            sync_attrs = {
                            'realm' : realm,
                            'site' : site,
                            }
            # Send sync command.
            try:
                self._send_daemon_msg(self.name, "sync_objects", data=sync_attrs)
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "resync_objects":
            # Build resync command.
            try:
                realm = command_args['realm']
            except:
                realm = None
            try:
                site = command_args['site']
            except:
                site = None
            sync_attrs = {
                            'realm' : realm,
                            'site' : site,
                        }
            # Send resync command.
            try:
                self._send_daemon_msg(self.name, "resync_objects", data=sync_attrs)
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "sync_nsscache":
            try:
                self._send_daemon_msg(self.name, "sync_nsscache")
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "resync_nsscache":
            try:
                self._send_daemon_msg(self.name, "resync_nsscache")
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "sync_ssh_authorized_keys":
            try:
                self._send_daemon_msg(self.name, "sync_ssh_authorized_keys")
                message = "Command queued: %s" % command
                status = True
            except Exception as e:
                config.raise_exception()
                message = "Failed to send command: %s" % e
                status = False

        elif command == "get_sync_status":
            message = json.encode(config.sync_status.copy())
            status = True

        elif command == "reload_radius":
            try:
                cluster_radius_reload()
                status = True
                message = "Radius reloaded successful."
            except Exception as e:
                status = False
                message = "Failed to reload radius: %s" % e

        elif command == "get_daemon_socket":
            try:
                daemon = command_args['daemon']
            except:
                daemon = None
            try:
                node_name = command_args['node_name']
            except:
                node_name = None
            try:
                message = stuff.get_daemon_socket(daemon, node_name)
                status = True
            except UnknownObject as e:
                message = e
                status = False

        # NOTE: Currently not in use. Was intended to be used with otpme-agent but
        #       we now use ~/.otpme/locks as lock dir. May be used in the future for
        #       other stuff.
        #elif command == "acquire_lock":
        #    status = True
        #    try:
        #        lock_id = command_args['lock_id']
        #    except:
        #        message = "INCOMPLETE_COMMAND"
        #        status = False
        #    try:
        #        lock_type = command_args['lock_type']
        #    except:
        #        message = "INCOMPLETE_COMMAND"
        #        status = False
        #    try:
        #        write = command_args['write']
        #    except:
        #        write = False

        #    if lock_type not in valid_agent_lock_types:
        #        status = False
        #        message = "INVALID_LOCK_TYPE"
        #        msg = ("Failed to acquire lock: Permission denied: %s: %s"
        #                % (lock_type, lock_id))
        #        logger.warning(msg)

        #    if status:
        #        _lock_id = "proc_lock:%s:%s" % lock_id
        #        try:
        #            _lock = locking.acquire_lock(lock_type=lock_type,
        #                                        lock_id=_lock_id,
        #                                        write=write)
        #            status = True
        #            message = "Acquired lock: %s" % lock_id
        #        except Exception as e:
        #            message = "Failed to acquire lock: %s: %s" % (lock_id, e)
        #            status = False

        #elif command == "release_lock":
        #    status = True
        #    try:
        #        lock_id = command_args['lock_id']
        #    except:
        #        message = "INCOMPLETE_COMMAND"
        #        status = False
        #    try:
        #        lock_type = command_args['lock_type']
        #    except:
        #        message = "INCOMPLETE_COMMAND"
        #        status = False
        #    try:
        #        force = command_args['force']
        #    except:
        #        force = False

        #    if lock_type not in valid_agent_lock_types:
        #        status = False
        #        message = "INVALID_LOCK_TYPE"
        #        msg = ("Failed to release lock: Permission denied: %s: %s"
        #                % (lock_type, lock_id))
        #        logger.warning(msg)

        #    if status:
        #        try:
        #            _lock_id = "proc_lock:%s" % lock_id
        #            _lock = locking.get_lock(lock_type, _lock_id)
        #            _lock.release_lock(force=force)
        #            status = True
        #            message = "Released lock: %s" % lock_id
        #        except Exception as e:
        #            status = False
        #            message = "Failed to release lock: %s: %s" % (lock_id, e)

        elif not self.authenticated or not self.peer:
            message = "Please auth first."
            status = status_codes.NEED_HOST_AUTH

        response = self.build_response(status, message, encrypt=False)
        return response

    def _close(self):
        pass
