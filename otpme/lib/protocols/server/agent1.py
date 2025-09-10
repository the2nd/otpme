# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import psutil
import signal

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import srp
from otpme.lib import sotp
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import otpme_pass
from otpme.lib import multiprocessing
from otpme.lib.fuse import get_mount_point
from otpme.lib.fuse import mount_share_proc
#from otpme.lib.encoding.base import encode
#from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.protocols import status_codes
from otpme.lib.fuse import prepare_mount_point
from otpme.lib.protocols.request import decode_request
from otpme.lib.protocols.response import build_response

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-agent-1.0"

SESSION_LOCK_TYPE = "agent.session"

def register():
    locking.register_lock_type(SESSION_LOCK_TYPE, module=__file__)
    config.register_otpme_protocol("agent", PROTOCOL_VERSION, server=True)

class OTPmeAgentP1(object):
    """ Class that implements OTPme-agent-1.0 """
    def __init__(self, client, peer_cert=None, **handler_args):
        # Our name.
        self.name = "agent"
        # The protocol we support
        self.protocol = PROTOCOL_VERSION
        # Our peer.
        self.client = client
        # Indicates if connected client is authenticated.
        self.authorized = False

        # Will hold session of the requesting client (PID).
        self.session = {}
        self.ssh_agent_pid = None

        # Get communication handler to talk to agent main process.
        socket_comm_handler = handler_args['comm_handler']
        self.comm_handler = socket_comm_handler.get_child()

        # Add shared dict for session ID to PID mappings. A session ID is used
        # to "authorize" a user/PID to access a login session (e.g. get a SOTP)
        # and thus it should be kept (more or less) secret. When logged in via
        # the OTPme PAM module the session ID is added to the users environment
        # as a variable called "$OTPME_LOGIN_SESSION". This session ID is NOT
        # the same session ID used on the server side!
        self.session_ids = handler_args['session_ids']

        # Shared dict for sessions we hold.
        self.login_sessions = handler_args['login_sessions']

        # Daemons the agent can proxy commands to.
        self.supported_daemons = [ 'mgmtd', 'authd', 'fsd' ]

        # Init some variables.
        self.session_id = None
        self.session_type = None
        self.login_user = None
        self.login_token = None
        self.login_pass_type = None
        self.offline_allowed = False
        self.realm = None
        self.site = None
        self.rsp = None
        self.srp = None
        self.slp = None
        self.tty = None

    def init(self):
        """ Init protocol handler (e.g. load client infos). """
        # Get process infos from unix socket client.
        self.client_proc = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\1',
                                self.client)
        self.client_pid = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\2',
                                self.client)
        self.client_user = re.sub('^socket://([^:]*):([^:]*):([^:]*):([^:]*)$', r'\3',
                                self.client)

        # Set PID of users process that will be used as key to set/get
        # credentials.
        if self.client_proc == "otpme-tool":
            # If client process is otpme-tool we have to use the parent
            # PID (e.g. the users shell).
            self.login_pid = str(stuff.get_pid_parent(self.client_pid))
        else:
            # If client process is not otpme-tool this is probably a login
            # via PAM and we use the login process (e.g. login(1))
            self.login_pid = str(self.client_pid)
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        multiprocessing.cleanup()
        os._exit(0)

    @property
    def ssh_key_pass(self):
        if not self.ssh_agent_pid:
            return
        try:
            agent_session = self.login_sessions[self.ssh_agent_pid]
        except KeyError:
            return
        try:
            ssh_key_pass = agent_session['ssh_key_pass']
        except KeyError:
            return
        return ssh_key_pass

    def acquire_session_lock(self, login_pid):
        session_lock = locking.acquire_lock(lock_type=SESSION_LOCK_TYPE,
                                            lock_id=login_pid)
        return session_lock

    def send_command(self, command, request, timeout=None):
        """ Send request to agent parent process. """
        # Send request to parent process.
        self.comm_handler.send(recipient="conn_proxy",
                                command=command,
                                data=request,
                                timeout=timeout)
        # Receive reply.
        sender, command, reply = self.comm_handler.recv(timeout=timeout)
        message = reply['message']
        status_code = reply['status_code']
        status = None
        if status_code == status_codes.OK:
            status = True
        if status_code == status_codes.ERR:
            status = False
        return status, message

    def check_ssh_agent_pid(self, pid, ssh_agent_pid):
        """ Check if PID is a child of agent PID. """
        try:
            proc = psutil.Process(int(pid))
            # Walk through all parent processes of PID and check
            # if one has a session.
            while True:
                # Stop if we found a session for the connecting PID.
                if str(proc.pid) == str(ssh_agent_pid):
                    return str(proc.pid)
                # Get next parent.
                # WORKAROUND: proc.parent changed from str to method
                #             between psutil versions.
                try:
                   proc = proc.parent()
                except:
                   proc = proc.parent
                # Stop loop if we reached process tree's top.
                if proc is None:
                    break
        except:
            pass

    def get_login_pid(self, pid):
        """ Check if a session exists for the given PID and return login PID. """
        try:
            proc = psutil.Process(int(pid))
            # Walk through all parent processes of PID and check
            # if one has a session.
            while True:
                # Stop if we found a session for the connecting PID.
                if str(proc.pid) in self.login_sessions:
                    return str(proc.pid)
                # Get next parent.
                # WORKAROUND: proc.parent changed from str to method
                #             between psutil versions.
                try:
                   proc = proc.parent()
                except:
                   proc = proc.parent
                # Stop loop if we reached process tree's top.
                if proc is None:
                    break
        except:
            pass

    def authorize_user(self, session, username, pid, command=None):
        """ Check if given username/PID is authorized to access session. """
        authorized = False
        # If the given PID runs as the same user as the PID that created the
        # session we grant access because there is no way to protect the RSP
        # from beeing stolen if the user has e.g. access to /proc/$PID/environ.
        if session['system_user'] == username:
            logger.debug("PID %s authorized." % pid)
            return True

        # Check session ACLs for the user of the connecting PID.
        try:
            user_acls = session['acls'][username]
        except:
            user_acls = []

        if 'all' in user_acls:
            authorized = True

        if command is not None:
            if command in user_acls:
                authorized = True

        if authorized:
            logger.debug("User %s (%s) authorized by ACL."
                        % (username, pid))
            return True

        return False

    def process(self, data):
        """ Handle agent commands. """
        # All valid commands.
        valid_commands = [
                            "get_proto",
                            "auth",
                            "status",
                            "add_session",
                            "del_session",
                            "get_sessions",
                            "get_session_id",
                            "add_ssh_key_pass",
                            "check_ssh_key_pass",
                            "get_ssh_key_pass",
                            "del_ssh_key_pass",
                            "add_rsp",
                            "add_acl",
                            "del_acl",
                            "set_login_token",
                            "proxy_command",
                            "mount_shares",
                            "umount_shares",
                            "get_offline",
                            "get_realm",
                            "get_site",
                            "get_user",
                            "get_sotp",
                            "get_srp",
                            "get_slp",
                            "get_tty",
                            "reneg",
                            "ping",
                            #"debug_session",
                            "quit" ]
        # All valid acls.
        valid_acls = [
                        "all",
                        "add_acl",
                        "del_acl",
                        "del_session",
                        "get_sessions",
                        "get_session_id",
                        "add_ssh_key_pass",
                        "check_ssh_key_pass",
                        "get_ssh_key_pass",
                        "del_ssh_key_pass",
                        "add_rsp",
                        "set_login_token",
                        "proxy_command",
                        "mount_shares",
                        "umount_shares",
                        "get_offline",
                        "get_sotp",
                        "get_srp",
                        "get_slp",
                        "get_tty",
                        "reneg",
                        ]

        command, command_args, binary_data = self.decode_request(data)

        # Get DNS option.
        try:
            use_dns = command_args['use_dns']
        except:
            use_dns = config.use_dns

        # Check if we got a valid command.
        if command not in valid_commands:
            message = "Unknown command: %s\n" % command
            status = False
            return self.build_response(status, message)

        # Return protocol we support.
        if command == "get_proto":
            message = "Using protocol: %s" % self.protocol
            status = True
            return self.build_response(status, message)

        #logger.debug("PID %s called command: %s" % (self.client_pid, command))

        # Check if the requesting process is allowed to access one of the
        # sessions we hold.
        if not self.authorized:
            # If we got the "auth" command check if the given session ID exists.
            if command == "auth":
                try:
                    session_id = command_args['login_session_id']
                except:
                    message = "AGENT_INCOMPLETE_COMMAND"
                    status = False
                    return self.build_response(status, message)
                try:
                    self.login_pid = self.session_ids[session_id]
                except:
                    message = "Unknown session"
                    status = status_codes.UNKNOWN_LOGIN_SESSION
                    return self.build_response(status, message)
            else:
                # Without session ID from auth command we have to check if there
                # is a login session from one of the clients parent processes.
                x = self.get_login_pid(self.client_pid)
                if x:
                    self.login_pid = x

            # Try to get session for login PID.
            try:
                session = self.login_sessions[self.login_pid]
            except KeyError:
                session = None
            # If we found a session check if user is authorized to access it.
            if session:
                self.authorized = self.authorize_user(session=session,
                                                    command=command,
                                                    username=self.client_user,
                                                    pid=self.client_pid)

        # If access to SSH key pass is requested try to authorize by agent PID.
        if command == "get_ssh_key_pass":
            for login_pid in self.login_sessions.keys():
                session = self.login_sessions[login_pid]
                try:
                    ssh_agent_pid = session['ssh_agent_pid']
                except:
                    continue
                if not self.check_ssh_agent_pid(self.client_pid, ssh_agent_pid):
                    continue
                self.authorized = True
                self.login_pid = login_pid
                logger.debug("Granted access to SSH key passphrase by PID: %s"
                            % self.client_pid)
                break

        # Set session.
        try:
            self.session = self.login_sessions[self.login_pid]
        except KeyError:
            pass

        # If client is authorized try to get session data.
        if self.authorized and self.session:
            try:
                self.session_id = self.session['session_id']
            except:
                pass
            try:
                self.session_type = self.session['session_type']
            except:
                pass
            try:
                self.login_user = self.session['login_user']
            except:
                pass
            try:
                self.login_token = self.session['login_token']
            except:
                pass
            try:
                self.login_pass_type = self.session['login_pass_type']
            except:
                pass
            try:
                self.ssh_agent_pid = self.session['ssh_agent_pid']
            except:
                pass
            try:
                self.realm = self.session['realm']
            except:
                pass
            try:
                self.site = self.session['site']
            except:
                pass
            try:
                self.tty = self.session['tty']
            except:
                pass
            try:
                self.rsp = self.session['server_sessions'][self.realm][self.site]['rsp']
            except:
                pass
            try:
                self.srp = self.session['server_sessions'][self.realm][self.site]['srp']
            except:
                pass
            try:
                self.slp = self.session['server_sessions'][self.realm][self.site]['slp']
            except:
                pass
            try:
                self.offline_allowed = self.session['server_sessions'][self.realm][self.site]['offline']
            except:
                pass

        if command == "add_session":
            if self.rsp:
                message = "Already logged in as user: %s" % self.login_user
                status = False
            elif self.session_id and self.login_user:
                message = ("Session for this PID already exists: %s"
                            % self.login_user)
                status = False
            else:
                try:
                    self.login_user = command_args['username']
                except:
                    message = "AGENT_INCOMPLETE_COMMAND"
                    status = False

                try:
                    self.session_id = command_args['session_id']
                except:
                    pass

                try:
                    self.tty = command_args['tty']
                except:
                    self.tty = None

                if self.login_user:
                    logger.info("Adding session for user '%s' (PID: %s)."
                                % (self.login_user, self.login_pid))
                    # If we got a session ID get login PID from it.
                    if self.session_id:
                        login_pid = self.session_id.split(":")[0]
                        if stuff.check_pid(login_pid):
                            self.login_pid = login_pid
                        else:
                            logger.warning("Login PID from given session ID "
                                            "does not exist: %s" % login_pid)
                    else:
                        self.session_id = "%s:%s" % (self.login_pid,
                                                stuff.gen_secret())
                    # Lock the session.
                    session_lock = self.acquire_session_lock(self.session_id)
                    try:
                        self.session_ids[self.session_id] = self.login_pid
                        self.session = {}
                        self.session['session_type'] = "realm_login"
                        self.session['system_user'] = self.client_user
                        self.session['login_user'] = self.login_user
                        self.session['session_id'] = self.session_id
                        self.session['tty'] = self.tty
                        self.login_sessions[self.login_pid] = self.session
                    finally:
                        session_lock.release_lock()
                    # Send command to agent parent process.
                    add_request = {
                                'login_pid' : self.login_pid,
                                'realm'     : self.realm,
                                'site'      : self.site,
                                'daemon'    : 'agent',
                                }
                    try:
                        self.send_command(command="add_session",
                                        request=add_request)
                        message = "Added session: %s" % self.session_id
                        status = True
                    except Exception as e:
                        message = str(e)
                        status = False

        elif command == "mount_shares":
            status = True
            login_user = self.login_sessions[self.login_pid]['login_user']
            try:
                shares = command_args['shares']
            except KeyError:
                message = "Missing shares"
                status = False
            if status:
                messages = []
                new_mounts = {}
                for share_id in shares:
                    share_name = shares[share_id]['name']
                    share_site = shares[share_id]['site']
                    share_nodes = shares[share_id]['nodes']
                    share_encrypted = shares[share_id]['encrypted']
                    try:
                        mount_point = prepare_mount_point(login_user, share_site, share_name)
                    except Exception as e:
                        msg = "Failed to prepare mountpoint: %s" % e
                        logger.warning(msg)
                        continue
                    if os.path.ismount(mount_point):
                        status = False
                        msg = "Share already mounted: %s: %s" % (share_id, mount_point)
                        logger.info(msg)
                        messages.append(msg)
                    else:
                        os.environ['OTPME_LOGIN_SESSION'] = self.session_id
                        mount_proc = multiprocessing.start_process(name="mount",
                                                                target=mount_share_proc,
                                                                target_args=(share_name,
                                                                            share_site,
                                                                            mount_point,
                                                                            share_nodes,
                                                                            share_encrypted),
                                                                target_kwargs={
                                                                                'logger'    :logger,
                                                                                'foreground':False,
                                                                            },
                                                                daemon=False)
                        mount_proc.join()
                        if mount_proc.exitcode != 0:
                            msg = "Failed to mount share: %s" % share_id
                            logger.info(msg)
                            messages.append(msg)
                            continue
                        new_mounts[share_id] = shares[share_id]
                        try:
                            os.system(f"sudo -n setreadahead {mount_point}")
                        except Exception as e:
                            status = False
                            msg = "Failed to run setreadahead: %s: %s" % (mount_point, e)
                            messages.append(msg)
                            logger.info(msg)
                try:
                    mounted_shares = self.session['mounted_shares']
                except KeyError:
                    mounted_shares = {}
                for share_id in new_mounts:
                    mounted_shares[share_id] = new_mounts[share_id]
                self.session['mounted_shares'] = mounted_shares
                self.login_sessions[self.login_pid] = self.session
                msg = "Shares mounted: %s" % new_mounts
                messages.append(msg)
                message = "\n".join(messages)

        elif command == "umount_shares":
            status = True
            login_user = self.login_sessions[self.login_pid]['login_user']
            try:
                shares = self.session['mounted_shares']
            except KeyError:
                shares = {}
            if not shares:
                message = "No shares mounted."
            if shares:
                messages = []
                umounted_shares = []
                for share_id in shares:
                    share_site = shares[share_id]['site']
                    share_name = shares[share_id]['name']
                    mount_point = get_mount_point(login_user, share_site, share_name)
                    try:
                        os.system(f"fusermount -u {mount_point}")
                    except Exception as e:
                        try:
                            os.system(f"fusermount -z -u {mount_point}")
                        except Exception as e:
                            msg = "Failed to unmount share: %s: %s" % (mount_point, e)
                            messages.append(msg)
                            logger.warning(msg)
                    try:
                        os.rmdir(mount_point)
                    except Exception as e:
                        msg = "Failed to rmdir mountpoint: %s: %s" % (mount_point, e)
                        logger.warning(msg)
                    umounted_shares.append(share_id)
                msg = "Shares unmounted: %s" % umounted_shares
                messages.append(msg)
                message = "\n".join(messages)
                print(message)

        elif command == "debug_session":
            try:
                debug_session = command_args['debug_session']
            except:
                debug_session = None

            if debug_session:
                try:
                    self.login_pid = debug_session
                    self.session = self.login_sessions[self.login_pid]
                    self.authorized = True
                    message = str(self.session)
                    status = True
                except:
                    message = "Unknown session"
                    status = False
            else:
                message = " ".join(list(dict(self.login_sessions)))
                status = True


        elif command == "auth":
            if self.authorized:
                message = ("Authorized to access login session: %s"
                            % self.login_user)
                status = True
            else:
                message = "Access denied."
                status = False

        elif command == "get_tty":
            if self.tty:
                message = self.tty
                status = True
            else:
                message = "no TTY set"
                status = False

        elif command == "quit":
            message = "Bye bye..."
            raise ClientQuit(message)

        elif command == "ping":
            message = "pong"
            status = True

        elif command == "check_ssh_key_pass":
            if self.ssh_key_pass:
                message = "SSH key passphrase is set"
                status = True
            else:
                message = "No SSH key passphrase set"
                status = False

        elif command == "status":
            if self.rsp:
                if self.login_token:
                    message = ("Logged in with token: %s type: %s"
                            % (self.login_token, self.login_pass_type))
                    status = True
                else:
                    message = "Logged in as user: %s" % self.login_user
                    status = True
            else:
                if self.login_token:
                    message = ("Logged in (offline) with token: %s type: %s"
                                % (self.login_token, self.login_pass_type))
                    status = True
                else:
                    message = "Not logged in"
                    status = status_codes.NOT_FOUND


        elif not self.authorized:
            message = "Not logged in"
            status = status_codes.NOT_FOUND
            if command != "get_user" and command != "del_session":
                logger.warning("Command '%s' denied: process=%s(%s) user=%s"
                                % (command,
                                self.client_proc,
                                self.client_pid,
                                self.client_user))

        elif command == "get_session_id":
            message = self.session_id
            status = True

        elif command == "get_sessions":
            login_sessions = {}
            for login_pid in dict(self.login_sessions):
                login_session = dict(self.login_sessions[login_pid])

                authorized = self.authorize_user(session=login_session,
                                                username=self.client_user,
                                                pid=self.client_pid)
                if not authorized:
                    continue

                try:
                    server_sessions = login_session['server_sessions']
                except:
                    server_sessions = []

                # Remove session attributes based on access permissions.
                for realm in server_sessions:
                    for site in server_sessions[realm]:
                        session = server_sessions[realm][site]
                        for x in dict(session):
                            if x == "rsp":
                                try:
                                    session.pop(x)
                                except:
                                    pass
                                continue
                            if x == "srp":
                                check_cmd = "get_srp"
                            elif x == "slp":
                                check_cmd = "get_slp"
                            else:
                                continue

                            authorized = self.authorize_user(session=login_session,
                                                            command=check_cmd,
                                                            username=self.client_user,
                                                            pid=self.client_pid)
                            if authorized:
                                continue
                            # Remove attribute access was denied to.
                            try:
                                session.pop(x)
                            except:
                                pass

                # Update server sessions.
                login_session['server_sessions'] = server_sessions
                # Add login session.
                login_sessions[login_pid] = login_session

            # Encode session list.
            message = json.encode(login_sessions, encoding="base64")
            status = True


        elif command == "get_realm":
            message = self.realm
            status = True


        elif command == "get_site":
            message = self.site
            status = True


        elif command == "get_user":
            message = self.login_user
            status = True


        elif command == "set_login_token":
            try:
                self.login_token = command_args['login_token']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False

            try:
                self.login_pass_type = command_args['login_pass_type']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False

            if self.login_token:
                msg = ("Setting login token for user '%s' (PID: %s)."
                        % (self.login_user, self.login_pid))
                logger.info(msg)
                session_lock = self.acquire_session_lock(self.session_id)
                try:
                    self.session['login_token'] = self.login_token
                    self.session['login_pass_type'] = self.login_pass_type
                    self.login_sessions[self.login_pid] = self.session
                finally:
                    session_lock.release_lock()
                message = "login token successfully set"
                status = True


        elif command == "add_ssh_key_pass":
            if self.ssh_key_pass:
                message = "SSH key passphrase already set"
                status = False
            else:
                try:
                    self.ssh_agent_pid = command_args['ssh_agent_pid']
                    ssh_key_pass = command_args['ssh_key_pass']
                except:
                    message = "AGENT_INCOMPLETE_COMMAND"
                    status = False

                if self.ssh_agent_pid and ssh_key_pass:
                    try:
                        ssh_agent_proc = psutil.Process(int(self.ssh_agent_pid))
                    except:
                        ssh_agent_proc = None

                    if ssh_agent_proc:
                        msg = ("Adding SSH key passphrase for user '%s' "
                            "(PID: %s)." % (self.login_user, self.ssh_agent_pid))
                        logger.info(msg)
                        # Add new session for the given ssh-agent PID.
                        session_lock = self.acquire_session_lock(self.session_id)
                        try:
                            system_user = ssh_agent_proc.username()
                            agent_session = {}
                            agent_session['session_type'] = "ssh_key_pass"
                            agent_session['system_user'] = system_user
                            agent_session['login_user'] = self.login_user
                            agent_session['ssh_key_pass'] = ssh_key_pass
                            self.login_sessions[self.ssh_agent_pid] = agent_session
                            # Add ssh_agent_pid to this session.
                            self.session['ssh_agent_pid'] = self.ssh_agent_pid
                            self.login_sessions[self.login_pid] = self.session
                        finally:
                            session_lock.release_lock()
                        message = "Added SSH key passphrase"
                        status = True
                    else:
                        message = "PID %s not running" % self.ssh_agent_pid
                        status = False


        elif command == "get_ssh_key_pass":
            if self.ssh_key_pass:
                message = ("username: %s ssh_key_pass: %s"
                        % (self.login_user, self.ssh_key_pass))
                status = True
            else:
                message = "No SSH key passphrase set"
                status = False
                logger.debug(message)


        elif command == "del_ssh_key_pass":
            message = "No SSH key passphrase set"
            status = False
            if self.ssh_agent_pid:
                msg = ("Removing SSH key passphrase for user '%s' "
                    "(PID: %s)." % (self.login_user, self.ssh_agent_pid))
                logger.info(msg)
                session_lock = self.acquire_session_lock(self.session_id)
                try:
                    self.login_sessions.pop(self.ssh_agent_pid)
                    message = "SSH key passphrase removed"
                    status = True
                except:
                    pass
                finally:
                    session_lock.release_lock()

        elif command == "add_rsp":
            status = True
            try:
                realm = command_args['realm']
            except:
                realm = None
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                site = command_args['site']
            except:
                site = None
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                rsp = command_args['rsp']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                slp = command_args['slp']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                login_time = float(command_args['login_time'])
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                session_timeout = int(command_args['timeout'])
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                session_unused_timeout = int(command_args['unused_timeout'])
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False
            try:
                offline = command_args['offline']
            except:
                offline = False
            try:
                session_key = command_args['session_key']
            except:
                session_key = None
            try:
                rsp_signature = command_args['rsp_signature']
            except:
                rsp_signature = None

            if status:
                if realm == self.realm and site == self.site:
                    if self.rsp:
                        message = "RSP already set"
                        status = False

            # Make sure we get a valid session key.
            if status and session_key:
                try:
                    key = RSAKey(key=session_key)
                except Exception as e:
                    message = "Failed to load session key: %s" % e
                    status = False
                    logger.critical(message)
                if status:
                    verify_status = key.verify(rsp_signature,
                                                message=rsp,
                                                encoding="hex")
                    if not verify_status:
                        message = "RSP signature verification failed"
                        status = False

            if status:
                logger.info("Adding RSP for user '%s@%s/%s' (PID: %s)."
                            % (self.login_user, realm, site, self.login_pid))

                # Make sure server session exists in dict.
                if 'server_sessions' not in self.session:
                    self.session['server_sessions'] = {}
                server_sessions = self.session['server_sessions']
                if realm not in server_sessions:
                    server_sessions[realm] = {}
                if site not in server_sessions[realm]:
                    server_sessions[realm][site] = {}

                # Get server session.
                session = server_sessions[realm][site]

                # Add RSP.
                session['rsp'] = rsp
                # Gen SRP.
                rsp_hash = otpme_pass.gen_one_iter_hash(self.login_user, rsp)
                _srp = srp.gen(rsp_hash)
                session['srp'] = _srp
                # Gen SLP.
                session['slp'] = slp
                # Add session public key.
                session['session_key'] = session_key
                # Add login time.
                session['login_time'] = login_time
                # For sessions with offline flag set no logout command
                # will be sent to the server on agent shutdown etc. to
                # allow re-use of the session after a reboot.
                session['offline'] = offline
                # Set reneg stuff.
                session['reneg'] = False
                session['next_reneg'] = None
                session['next_retry'] = None
                session['last_reneg'] = time.time()
                session['last_failed_reneg'] = None
                # Set server session timeout stuff.
                session['session_timeout'] = session_timeout
                session['session_unused_timeout'] = session_unused_timeout
                # Add realm/site.
                self.session['realm'] = realm
                self.session['site'] = site
                # Update login session.
                session_lock = self.acquire_session_lock(self.session_id)
                try:
                    self.login_sessions[self.login_pid] = self.session
                except:
                    pass
                finally:
                    session_lock.release_lock()
                # Send command to agent parent process.
                add_request = {
                            'login_pid' : self.login_pid,
                            'realm'     : self.realm,
                            'site'      : self.site,
                            'daemon'    : 'agent',
                            }
                try:
                    self.send_command(command="add_rsp", request=add_request)
                    message = "Added RSP"
                    status = True
                except Exception as e:
                    message = str(e)
                    status = False
                    msg = "Failed to add RSP: %s" % e
                    logger.warning(msg)

        elif command == "add_acl":
            try:
                username = command_args['username']
                acl = command_args['acl']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False

            if acl in valid_acls:
                try:
                    self.session['acls']
                except:
                    self.session['acls'] = {}

                try:
                    self.session['acls'][username]
                except:
                    self.session['acls'][username] = []

                user_acls = self.session['acls'][username]

                if acl in user_acls:
                    message = "ACL exists"
                    status = False
                else:
                    logger.info("Adding ACL for user session '%s' (PID: %s)."
                                % (self.login_user, self.login_pid))
                    user_acls.append(acl)
                    self.session['acls'][username] = user_acls
                    session_lock = self.acquire_session_lock(self.session_id)
                    try:
                        self.login_sessions[self.login_pid] = self.session
                    except:
                        pass
                    finally:
                        session_lock.release_lock()
                    message = "Added ACL"
                    status = True
            else:
                message = "Invalid ACL"
                status = False


        elif command == "del_acl":
            try:
                username = command_args['username']
                acl = command_args['acl']
            except:
                message = "AGENT_INCOMPLETE_COMMAND"
                status = False

            if acl in valid_acls:
                try:
                    self.session['acls']
                except:
                    self.session['acls'] = {}

                try:
                    self.session['acls'][username]
                except:
                    self.session['acls'][username] = []

                user_acls = self.session['acls'][username]

                if acl in user_acls:
                    msg = ("Removing ACL for user session '%s' (PID: %s)."
                                % (self.login_user, self.login_pid))
                    logger.info(msg)
                    try:
                        user_acls.remove(acl)
                    except:
                        pass
                    self.session['acls'][username] = user_acls
                    session_lock = self.acquire_session_lock(self.session_id)
                    try:
                        self.login_sessions[self.login_pid] = self.session
                    except:
                        pass
                    finally:
                        session_lock.release_lock()
                    message = "Deleted ACL"
                    status = True
                else:
                    message = "ACL does not exist"
                    status = False
            else:
                message = "Invalid ACL"
                status = False


        elif command == "del_session":
            if self.rsp:
                logger.info("Received request to delete user session for '%s'."
                            % self.login_user)
                del_request = {
                            'login_pid' : self.login_pid,
                            'realm'     : self.realm,
                            'site'      : self.site,
                            'daemon'    : 'agent',
                            }
                # Send command to agent parent process.
                try:
                    status, message = self.send_command(command="del_session",
                                                        request=del_request)
                except Exception as e:
                    message = str(e)
                    status = False
            else:
                logger.info("Removing empty session (%s) for user '%s'."
                            % (self.login_pid, self.login_user))
                try:
                    self.session_ids.pop(self.session_id)
                except:
                    pass
                session_lock = self.acquire_session_lock(self.session_id)
                try:
                    self.login_sessions.pop(self.login_pid)
                except:
                    pass
                finally:
                    session_lock.release_lock()
                message = "Empty session removed."
                status = True

            # Reset variables for this connection.
            self.session = {}
            self.session_id = None
            self.session_type = None
            self.login_user = None
            self.login_token = None
            self.login_pass_type = None
            self.offline_allowed = False
            self.realm = None
            self.site = None
            self.rsp = None
            self.srp = None
            self.slp = None
            self.tty = None


        elif not self.rsp:
            message = "No RSP set"
            status = False

        elif command == "proxy_command":
            status = True
            try:
                realm = command_args['realm']
                site = command_args['site']
                daemon = command_args['daemon']
                proxy_request = command_args['proxy_request']
            except:
                daemon = None
                message = "Invalid syntax"
                status = False

            if not daemon in self.supported_daemons:
                message = "Unknown daemon: %s" % daemon
                status = False
                daemon = None

            if status:
                agent_request = {
                            #'command'           : 'proxy_command',
                            'login_pid'         : self.login_pid,
                            'realm'             : realm,
                            'site'              : site,
                            'use_dns'           : use_dns,
                            'daemon'            : daemon,
                            'proxy_request'     : proxy_request,
                            }
                # Send command to agent parent process.
                try:
                    status, message = self.send_command(command="proxy_command",
                                                        request=agent_request)
                except Exception as e:
                    message = str(e)
                    status = False

        #elif command == "get_rsp":
        #    if self.rsp:
        #       message = "username: %s rsp: %s" % (self.login_user, self.rsp)
        #       status = True
        #    else:
        #       message = "no RSP set"
        #       status = False

        elif command == "get_srp":
            if self.srp:
                message = "username: %s srp: %s" % (self.login_user, self.srp)
                status = True
            else:
                message = "no RSP set"
                status = False


        elif command == "get_sotp":
            try:
                site = command_args['site']
            except KeyError:
                site = None
            if site:
                try:
                    rsp = self.session['server_sessions'][self.realm][site]['rsp']
                except:
                    # If no RSP exists for this site, try login to the site.
                    login_request = {
                                'login_pid' : self.login_pid,
                                'realm'     : self.realm,
                                'site'      : site,
                                'daemon'    : 'agent',
                                }
                    try:
                        self.send_command(command="login_user",
                                        request=login_request)
                    except Exception as e:
                        message = str(e)
                        status = False
                    # Re-load session.
                    try:
                        self.session = self.login_sessions[self.login_pid]
                    except KeyError:
                        pass
                    # Try to get RSP.
                    try:
                        rsp = self.session['server_sessions'][self.realm][site]['rsp']
                    except:
                        rsp = None
            else:
                rsp = self.rsp
            if rsp:
                rsp_hash = otpme_pass.gen_one_iter_hash(self.login_user, rsp)
                otp = sotp.gen(password_hash=rsp_hash)
                message = {'username':self.login_user, 'sotp':otp}
                status = True
            else:
                message = "No server session."
                status = False

        elif command == "get_slp":
            if self.slp:
                message = "username: %s slp: %s" % (self.login_user, self.slp)
                status = True
            else:
                message = "no RSP set"
                status = False

        elif command == "get_offline":
            status = self.offline_allowed
            if status:
                message = "Offline allowed."
            else:
                message = "Offline not allowed."


        elif command == "reneg":
            try:
                realm = command_args['realm']
                site = command_args['site']
            except:
                realm = self.realm
                site = self.site

            reneg_request = {
                        'login_pid' : self.login_pid,
                        'realm'     : realm,
                        'site'      : site,
                        'use_dns'   : use_dns,
                        'daemon'    : 'agent',
                        #'command'   : 'reneg',
                        }
            # Send command to agent parent process.
            try:
                status, message = self.send_command(command="reneg",
                                                request=reneg_request)
            except Exception as e:
                message = str(e)
                status = False

        return self.build_response(status, message)

    def build_response(self, status, message):
        """ Build response. """
        # Build response.
        response = build_response(status, message)
        return response

    def decode_request(self, *args, **kwargs):
        return decode_request(*args, **kwargs)

    def cleanup(self):
        """ Is called on client disconnect. """
        # Close and remove IPC queue.
        self.comm_handler.unlink()

    def close(self):
        pass
