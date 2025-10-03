# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pwd
import grp
import json
import time
import shutil

# FIXME: This is a workaround to prevent pinentry module from loading some
#        modules that will crash sddm.
sys.modules['PyQt4'] = None
sys.modules['PyKDE4'] = None

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {name}")
        msg = msg.format(name=__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import init_otpme
from otpme.lib import connections
from otpme.lib.register import register_module
from otpme.lib.offline_token import OfflineToken
from otpme.lib.smartcard.utils import detect_smartcard

from otpme.lib.exceptions import *

class PamHandler(object):
    """ Authenticate PAM user. """
    def __init__(self, pamh, argv):
        """ Init class variables. """
        register_module("otpme.lib.offline_token")
        register_module("otpme.lib.protocols.otpme_client")
        self.pamh = pamh
        self.username = None
        self.password = None
        self.user_uuid = None
        self.offline_login = False
        self.send_password = True
        self.allow_null_passwords = False
        self.connect_timeout = 3
        self.connection_timeout = 30
        self.login_session_id = None
        self.login_token = None
        self.login_interface = "tty"
        self.offline_login_token = None
        self.offline_verify_token = None
        self.offline_token_verified = False
        self.offline_token_verify_status = False
        self.offline_tokens = {}
        self.offline_sessions = {}
        self.offline_token = None
        self.offline = False
        self.realm_login = False
        self.login_status = False
        self.auth_status = False
        self.auth_failed = False
        self.hostd_conn = None
        self.login_script = None
        self.login_script_path = None
        self.login_script_uuid = None
        self.login_script_opts = None
        self.login_script_signs = None
        self.ssh_agent_conn = None
        self.ssh_agent = None
        self.ssh_agent_script = None
        self.ssh_agent_script_uuid = None
        self.ssh_agent_script_path = None
        self.ssh_agent_script_opts = None
        self.ssh_agent_script_signs = None
        self.ssh_agent_started = False
        self.ensure_ssh_agent = "auto"
        self.use_ssh_agent = "auto"
        self.use_smartcard = "auto"
        self.smartcard = None
        self.failed_message = "Login failed"
        self.auth_message = ""
        self.login_message = None
        self.message_timeout = 2
        self.env_dir = None
        self.pinentry_autoconfirm_file = None
        self.pinentry_message_file = None
        self.login_session_dir = None
        self.display = None
        # Default PAM return value.
        self.retval = self.pamh.PAM_AUTH_ERR
        self.cache_login_tokens = False
        self.online_greeting = False
        self.offline_greeting = False
        self.show_errors = False
        self.use_first_pass = False
        self.try_first_pass = False
        self.check_offline_pass_strength = False
        self.unlock_via_offline_token = False
        self.create_home_directory = False
        self.home_skeleton = None
        self.iterations_by_score = {
                                0 : 6,
                                1 : 6,
                                2 : 6,
                                3 : 5,
                                4 : 5,
                                5 : 5,
                                6 : 3,
                                7 : 3,
                                8 : 3,
                                9 : 3,
                                10 : 3,
                                }
        self.offline_key_func = "Argon2_i"
        self.offline_key_func_opts = {
                                    'iterations'    : 3,
                                    'memory'        : "auto",
                                    'min_mem'       : 65536,
                                    'max_mem'       : 262144,
                                    'threads'       : 4,
                                    }
        self.logger = config.logger

        # Try to get login session stuff from environment (e.g. when called from
        # pam_sm_open_session())
        try:
            self.login_session_id = self.pamh.env['OTPME_LOGIN_SESSION']
        except:
            # Fallback to environment variable.
            try:
                self.login_session_id = os.environ['OTPME_LOGIN_SESSION']
            except:
                pass
        try:
            self.login_session_dir = self.pamh.env['OTPME_LOGIN_SESSION_DIR']
        except:
            # Fallback to environment variable.
            try:
                self.login_session_dir = os.environ['OTPME_LOGIN_SESSION_DIR']
            except:
                pass
        # Get login token.
        try:
            self.login_token = self.pamh.env['OTPME_LOGIN_TOKEN']
        except:
            # Fallback to environment variable.
            try:
                self.login_token = os.environ['OTPME_LOGIN_TOKEN']
            except:
                pass
        # Check if the user logged in offline.
        try:
            if self.pamh.env['OTPME_OFFLINE_LOGIN'] == "True":
                self.offline_login = True
        except:
            # Fallback to environment variable.
            try:
                if os.environ['OTPME_OFFLINE_LOGIN'] == "True":
                    self.offline_login = True
            except:
                pass

        if "debug" in argv:
            config.debug_enabled = True
            config.reload(configure_logger=True)
            argv.remove("debug")

        for x in argv[1:]:
            val = None
            if "=" in x:
                try:
                    arg = x.split("=")[0]
                    val = x.split("=")[1]
                    log_msg = _("Got option: {arg}={val}", log=True)[1]
                    log_msg = log_msg.format(arg=arg, val=val)
                    self.logger.debug(log_msg)
                except:
                    log_msg = _("Ignoring malformed PAM parameter: {param}", log=True)[1]
                    log_msg = log_msg.format(param=x)
                    self.logger.warning(log_msg)
                    continue
            else:
                arg = x
                log_msg = _("Got option: {arg}", log=True)[1]
                log_msg = log_msg.format(arg=arg)
                self.logger.debug(log_msg)

            if arg == "nullok":
                self.allow_null_passwords = True
            if arg == "send_password":
                if val.lower() == "true":
                    self.send_password = True
                elif val.lower() == "false":
                    self.send_password = False
                else:
                    log_msg = _("Ignoring unknown value for send_password: {value}", log=True)[1]
                    log_msg = log_msg.format(value=val)
                    self.logger.warning(log_msg)
            if arg == "try_first_pass":
                self.try_first_pass = True
            if arg == "use_first_pass":
                self.use_first_pass = True
            if arg == "create_home":
                self.create_home_directory = True
            if arg == "home_skel":
                self.home_skeleton = val
            if arg == "realm_login":
                self.realm_login = True
            if arg == "use_smartcard":
                if val.lower() == "true":
                    self.use_smartcard = True
                elif val.lower() == "false":
                    self.use_smartcard = False
                elif val.lower() == "auto":
                    self.use_smartcard = "auto"
                else:
                    log_msg = _("Ignoring unknown value for use_smartcard: {value}", log=True)[1]
                    log_msg = log_msg.format(value=val)
                    self.logger.warning(log_msg)
            if arg == "use_ssh_agent":
                if val.lower() == "true":
                    self.use_ssh_agent = True
                    self.ensure_ssh_agent = True
                elif val.lower() == "false":
                    self.use_ssh_agent = False
                elif val.lower() == "auto":
                    self.use_ssh_agent = "auto"
                else:
                    log_msg = _("Ignoring unknown value for use_ssh_agent: {value}", log=True)[1]
                    log_msg = log_msg.format(value=val)
                    self.logger.warning(log_msg)
            if arg == "start_ssh_agent":
                if val.lower() == "auto":
                    self.ensure_ssh_agent = "auto"
                elif val.lower() == "true":
                    self.ensure_ssh_agent = True
                elif val.lower() == "false":
                    self.ensure_ssh_agent = False
            if arg == "cache_login_tokens":
                self.cache_login_tokens = True
            if arg == "show_errors":
                self.show_errors = True
            if arg == "message_timeout":
                self.message_timeout = int(val)
            if arg == "online_greeting":
                self.online_greeting = True
            if arg == "offline_greeting":
                self.offline_greeting = True
            if arg == "unlock_via_offline_token":
                self.unlock_via_offline_token = True
            if arg == "connect_timeout":
                self.connect_timeout = int(val)
            if arg == "connection_timeout":
                self.connection_timeout = int(val)
            if arg == "check_offline_pass_strength":
                self.offline_key_func_opts = {}
                if val:
                    self.check_offline_pass_strength = val.split(";")[0]
                    if ";" in val:
                        try:
                            iterations_by_score = {}
                            for x in val.split(";")[1].split(","):
                                score = int(x.split(":")[0])
                                iterations = int(x.split(":")[1])
                                iterations_by_score[score] = iterations
                            if iterations_by_score:
                                self.iterations_by_score = iterations_by_score
                        except Exception as e:
                            log_msg = _("Malformed options for PAM parameter: check_offline_pass_strength", log=True)[1]
                            self.logger.warning(log_msg)
                else:
                    self.check_offline_pass_strength = "auto"
            if arg == "offline_key_func":
                # Try to get key derivation function.
                try:
                    offline_key_func = val.split(";")[0]
                except:
                    offline_key_func = None
                    log_msg = _("Ignoring malformed PAM parameter: offline_key_func", log=True)[1]
                    self.logger.warning(log_msg)

                if offline_key_func:
                    try:
                        config.get_hash_type_default_otps(offline_key_func)
                    except UnsupportedHashType:
                        log_msg = _("Ignoring unknown value for offline_key_func: {func}", log=True)[1]
                        log_msg = log_msg.format(func=offline_key_func)
                        self.logger.warning(log_msg)
                # Set offline key derivation function.
                self.offline_key_func = offline_key_func
                # Try to get key derivation options.
                if ";" in val:
                    try:
                        func_opts = {}
                        for opt in val.split(";")[1].split(","):
                            k = opt.split(":")[0]
                            v = opt.split(":")[1]
                            func_opts[k] = v
                        if func_opts:
                            self.offline_key_func_opts = func_opts
                    except Exception as e:
                        log_msg = _("Malformed options for PAM parameter: offline_key_func", log=True)[1]
                        self.logger.warning(log_msg)

        # Try to get username.
        try:
            username = str(self.pamh.get_user())
            if len(username) != 0:
                self.username = username
                # Set login user (e.g. to get correct agent connection).
                config.login_user = self.username
                # Set shell user environment dir.
                self.env_dir = config.get_user_env_dir(self.username)
                # Autoconfirm file for otpme-pinentry.
                self.pinentry_autoconfirm_file = config.get_pinentry_autoconfirm_file()
                # Autoconfirm message file for otpme-pinentry.
                self.pinentry_message_file = config.get_pinentry_message_file()
        except self.pamh.exception:
            pass

    def get_user_uuid(self):
        # Try to get users UUID from environment.
        try:
            user_uuid = os.environ['OTPME_USER_UUID']
        except KeyError:
            # Fallback to get UUID from hostd.
            user_uuid = self.hostd_conn.get_user_uuid(self.username)
        return user_uuid

    def send_pam_message(self, msg):
        """ Send PAM message. """
        self.pamh.conversation(self.pamh.Message(self.pamh.PAM_TEXT_INFO, msg))
        time.sleep(self.message_timeout)

    def send_pam_error(self, msg):
        """ Send PAM error message. """
        self.pamh.conversation(self.pamh.Message(self.pamh.PAM_ERROR_MSG, msg))
        time.sleep(self.message_timeout)

    def get_password(self, prompt="Password:"):
        """ Get password via PAM message. """
        if self.password:
            return self.password
        # Try to get password/OTP from a previous stacked module.
        if self.use_first_pass:
            password = self.pamh.authtok
            if password is None:
                log_msg = _("No password received and 'use_first_pass' set. Authentication failed.", log=True)[1]
                self.logger.warning(log_msg)
                self.cleanup()
                return self.pamh.PAM_AUTH_ERR
        elif self.try_first_pass:
            password = self.pamh.authtok
            if password is None:
                log_msg = _("No password received and 'try_first_pass' set. Will ask user for password.", log=True)[1]
                self.logger.debug(log_msg)
        if password:
            log_msg = _("Using password from previous PAM module.", log=True)[1]
            self.logger.debug(log_msg)
        else:
            # Try to get password via PAM.
            log_msg = _("Trying to get password from PAM...", log=True)[1]
            self.logger.debug(log_msg)
            try:
                pam_msg = self.pamh.Message(self.pamh.PAM_PROMPT_ECHO_OFF, prompt)
                resp = self.pamh.conversation(pam_msg)
            except Exception as e:
                msg = _("Unable to get password from PAM: {error}")
                msg = msg.format(error=e)
                raise OTPmeException(msg)
            password = resp.resp
            # Check if null passwords are allowed.
            if not password:
                if self.allow_null_passwords:
                    log_msg = _("Got empty password and 'nullok' option enabled, continuing.", log=True)[1]
                    self.logger.debug(log_msg)
                else:
                    log_msg = _("Got empty password and 'nullok' option not set. Authentication failed.", log=True)[1]
                    self.logger.warning(log_msg)
                    raise AuthFailed(_("Empty passwords are not allowed!"))
            log_msg = _("Got password from PAM.", log=True)[1]
            self.logger.debug(log_msg)
        self.password = password
        return password

    def cleanup(self):
        """ Close connections etc. """
        agent_conn = self.get_agent_connection()
        try:
            if agent_conn.check_ssh_key_pass():
                log_msg = _("Removing SSH key passphrase from agent...", log=True)[1]
                self.logger.debug(log_msg)
                try:
                    agent_conn.del_ssh_key_pass()
                except Exception as e:
                    log_msg = _("Error removing SSH key passphrase from agent: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
        finally:
            agent_conn.close()
        if self.ssh_agent_conn:
            self.ssh_agent_conn.close()
        # Close all connections.
        connections.close_connections()

    def activate_gpg_agent_autoconfirm(self):
        """ Activate gpg-agent auto confirmation of key usage. """
        from otpme.lib.pinentry.pinentry import set_autoconfirm
        log_msg = _("Enabling GPG pinentry autoconfirmation.", log=True)[1]
        self.logger.debug(log_msg)
        # Enable autoconfirm for 30 seconds.
        expiry = str(time.time() + 30)
        set_autoconfirm(self.pinentry_autoconfirm_file,
                        confirm_key="LOGIN",
                        expiry=expiry,
                        fallback=False,
                        message_file=self.pinentry_message_file)
        # Make sure autoconfirmation file is owned by login user.
        uid = pwd.getpwnam(self.username).pw_uid
        os.chown(self.pinentry_autoconfirm_file, uid, -1)

    def deactivate_gpg_agent_autoconfirm(self):
        """ Activate gpg-agent auto confirmation of key usage. """
        from otpme.lib.pinentry.pinentry import remove_autoconfirm
        # Remove autoconfirm key "LOGIN".
        remove_autoconfirm(self.pinentry_autoconfirm_file,
                            confirm_key="LOGIN")

    def get_home_dir(self, username):
        home_exp = f"~{username}"
        home_dir = os.path.expanduser(home_exp)
        return home_dir

    def open_session(self):
        """ Get users DISPLAY etc. """
        # Make sure we got a username from PAM.
        if not self.username:
            return self.pamh.PAM_USER_UNKNOWN
        display = False
        if self.pamh.xdisplay:
             display = self.pamh.xdisplay
        else:
            if self.pamh.tty and self.pamh.tty.startswith(":"):
                display = self.pamh.tty
        if display:
            log_msg = _("Got DISPLAY from PAM session: {display}", log=True)[1]
            self.logger.debug(log_msg)
            home_dir = self.get_home_dir(self.username)
            if os.path.exists(home_dir):
                display_file = f"{home_dir}/.display"
                filetools.create_file(display_file,
                                    content=display,
                                    user=self.username,
                                    mode=0o600)

        return self.pamh.PAM_SUCCESS

    def close_session(self):
        """ Stop users agents etc. """
        # Make sure we got a username from PAM.
        if not self.username:
            return self.pamh.PAM_USER_UNKNOWN
        if not self.login_session_dir:
            return self.pamh.PAM_SUCCESS
        # Get SSH agent script.
        ssh_agent_script_file = os.path.join(self.login_session_dir, "ssh-agent-script.json")
        if os.path.exists(ssh_agent_script_file):
            agent_script_data = filetools.read_file(ssh_agent_script_file)
            agent_script_data = json.loads(agent_script_data)
            self.ssh_agent_script = agent_script_data['ssh_agent_script']
            self.ssh_agent_script_uuid = agent_script_data['ssh_agent_script_uuid']
            self.ssh_agent_script_path = agent_script_data['ssh_agent_script_path']
            self.ssh_agent_script_opts = agent_script_data['ssh_agent_script_opts']
            self.ssh_agent_script_signs = agent_script_data['ssh_agent_script_signs']
            # Stop SSH agent.
            if self.ssh_agent_status(verify_signs=False):
                try:
                    self.stop_ssh_agent(verify_signs=False)
                except Exception as e:
                    log_msg = _("Unable to run SSH agent script: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
        # Stop otpme-agent which does the user logout if required.
        log_msg = _("Stopping otpme-agent...", log=True)[1]
        self.logger.debug(log_msg)
        stuff.stop_otpme_agent(user=self.username, wait=False)
        return self.pamh.PAM_SUCCESS

    def pam_sm_setcred(self):
        """ Set users groups. """
        if config.system_user() != "root":
            return
        if not self.login_token:
            return
        log_msg = _("Getting dynamic groups from hostd.", log=True)[1]
        self.logger.debug(log_msg)
        # Get connection to hostd.
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            self.cleanup()
            log_msg = _("Unable to get connection to hostd: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return self.pamh.PAM_SYSTEM_ERR
        # Get dynamics groups of host.
        dynamic_groups = hostd_conn.get_host_dynamic_groups()
        # Get dynamics groups of token/roles.
        dynamic_groups += hostd_conn.get_token_dynamic_groups(self.login_token)
        # Get current user groups.
        current_groups = os.getgroups()
        for group in dynamic_groups:
            try:
                group_id = grp.getgrnam(group)[2]
            except KeyError:
                continue
            log_msg = _("Adding users dynamic group membership: {group_name}", log=True)[1]
            log_msg = log_msg.format(group_name=group)
            self.logger.info(log_msg)
            current_groups.append(group_id)
        current_groups = list(set(current_groups))
        os.setgroups(current_groups)
        return self.pamh.PAM_SUCCESS

    def get_ssh_agent_ctrl(self, session_id=None):
        """ Get SSH agent script control class """
        from otpme.lib.classes.ssh_agent import SSHAgent
        if not self.ssh_agent_script:
            msg = (_("Got no SSH agent script"))
            raise OTPmeException(msg)

        if self.ssh_agent:
            ssh_agent = self.ssh_agent
        else:
            if not session_id:
                session_id = self.login_session_id
            ssh_agent = SSHAgent(username=self.username,
                                login_session_id=session_id,
                                script=self.ssh_agent_script,
                                script_uuid=self.ssh_agent_script_uuid,
                                script_path=self.ssh_agent_script_path,
                                script_opts=self.ssh_agent_script_opts,
                                script_signs=self.ssh_agent_script_signs)
        return ssh_agent

    def start_ssh_agent(self, session_id=None, script=None,
        script_uuid=None, script_path=None, script_options=None,
        script_signatures=None, additional_opts=[], verify_signs=None):
        """ Make sure SSH/GPG agent is running and needed variables are set """
        ssh_auth_sock = None
        ssh_agent_pid = None
        ssh_agent_name = None
        gpg_agent_info = None

        if script:
            self.ssh_agent_script = script
        if script_uuid:
            self.ssh_agent_script_uuid = script_uuid
        if script_path:
            self.ssh_agent_script_path = script_path
        if script_options:
            self.ssh_agent_script_opts = script_options
        if script_signatures:
            self.ssh_agent_script_signs = script_signatures

        if not self.ssh_agent:
            self.ssh_agent = self.get_ssh_agent_ctrl(session_id)

        # If we got no explicit instuction to check signatures check them
        # depending on offline status.
        if verify_signs is None:
            if not self.offline:
                # In mode "auto" ssh agent script signatures are only checked
                # if agent scripts signers are configured.
                verify_signs = "auto"

        log_msg = _("Staring ssh-agent...", log=True)[1]
        self.logger.debug(log_msg)
        # Start SSH agent.
        ssh_auth_sock, \
        ssh_agent_pid, \
        ssh_agent_name, \
        gpg_agent_info = self.ssh_agent.start(additional_opts=additional_opts,
                                                verify_signs=verify_signs)

        # Set PAM env variables of the SSH agent.
        if gpg_agent_info:
            self.pamh.env['GPG_AGENT_INFO'] = gpg_agent_info
            #os.environ['GPG_AGENT_INFO'] = gpg_agent_info

        if ssh_auth_sock:
            self.pamh.env['SSH_AUTH_SOCK'] = ssh_auth_sock
            #os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock
            log_msg = _("SSH agent listening on: {socket}", log=True)[1]
            log_msg = log_msg.format(socket=ssh_auth_sock)
            self.logger.info(log_msg)

        if ssh_agent_pid:
            self.pamh.env['SSH_AGENT_PID'] = ssh_agent_pid
            #os.environ['SSH_AGENT_PID'] = ssh_agent_pid

        if ssh_agent_name:
            self.pamh.env['SSH_AGENT_NAME'] = ssh_agent_name
            #os.environ['SSH_AGENT_NAME'] = ssh_agent_name

        # Mark SSH agent as already started.
        self.ssh_agent_started = True

    def stop_ssh_agent(self, verify_signs=None):
        """ Stop SSH/GPG agent """
        if verify_signs is None:
            # In mode "auto" ssh agent script signatures are only checked
            # if agent scripts signers are configured.
            if not self.offline:
                verify_signs = "auto"

        if not self.ssh_agent:
            self.ssh_agent = self.get_ssh_agent_ctrl()

        self.ssh_agent.stop(verify_signs=verify_signs)

    def ssh_agent_status(self, verify_signs=None):
        """ Check SSH/GPG agent status """
        if verify_signs is None:
            # In mode "auto" ssh agent script signatures are only checked
            # if agent scripts signers are configured.
            if not self.offline:
                verify_signs = "auto"

        if not self.ssh_agent:
            self.ssh_agent = self.get_ssh_agent_ctrl()

        return self.ssh_agent.status(verify_signs=verify_signs)

    def run_login_script(self, verify_signs=None):
        """ Run users login script. """
        if not self.login_script:
            log_msg = _("Got no login script.", log=True)[1]
            self.logger.debug(log_msg)
            return
        if not self.login_script_uuid:
            log_msg = _("Missing login script UUID.", log=True)[1]
            self.logger.warning(log_msg)
            return
        from otpme.lib.classes import signing
        from otpme.lib import script as _script
        log_msg = _("Running login script: {path}", log=True)[1]
        log_msg = log_msg.format(path=self.login_script_path)
        self.logger.info(log_msg)

        # Get login script signers.
        login_script_signers = signing.get_signers(signer_type="login_script",
                                                    username=self.username)

        # If we got no explicit instuction to check signatures check them
        # depending on offline status.
        if verify_signs is None:
            if self.offline:
                verify_signs = False
            elif login_script_signers:
                verify_signs = True

        # Only verify script signatures if we got some and verification is
        # configured.
        if verify_signs and not login_script_signers:
            msg = (_("No login script signers configured."))
            raise OTPmeException(msg)

        if verify_signs and not self.login_script_signs:
            msg = (_("Got no login script signatures to verify."))
            raise OTPmeException(msg)

        # Add $USER variable to login script environment.
        script_env = os.environ.copy()
        script_env['USER'] = self.username

        # Run login script.
        try:
            script_returncode, \
            script_stdout, \
            script_stderr, \
            script_pid = _script.run(script_type="login_script",
                                    script_path=self.login_script_path,
                                    script_uuid=self.login_script_uuid,
                                    options=self.login_script_opts,
                                    signatures=self.login_script_signs,
                                    signers=login_script_signers,
                                    script=self.login_script,
                                    script_env=script_env,
                                    user=self.username,
                                    call=False,
                                    close_fds=True)
        except Exception as e:
            msg = _("Login script error: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)

        # Make sure script output is string.
        if isinstance(script_stdout, bytes):
            script_stdout = script_stdout.decode()
        if isinstance(script_stderr, bytes):
            script_stderr = script_stderr.decode()

        if script_returncode != 0:
            msg = _("Login script return failure: {stderr}")
            msg = msg.format(stderr=script_stderr)
            raise OTPmeException(msg)

        return script_stdout

    def get_agent_connection(self):
        """ Get otpme-agent connection. """
        retry_count = 0
        agent_conn_retry = 500
        agent_conn = connections.get("agent",
                            user=self.username,
                            autoconnect=False)
        while True:
            try:
                agent_conn.connect()
                break
            except UnknownLoginSession as e:
                # Remove session ID from agent connection to prevent auth
                # failures.
                agent_conn.login_session_id = None
                break
            except Exception as e:
                if retry_count >= agent_conn_retry:
                    msg = _("Error getting agent connection: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg)
                retry_count += 1
                time.sleep(0.01)
        return agent_conn

    def load_offline_tokens(self, reload_token=False):
        """ Load offline tokens. """
        if not reload_token:
            if self.offline_tokens:
                return
        try:
            self.offline_token.load()
            self.offline_tokens = self.offline_token.get()
        except Exception as e:
            msg = _("Error loading offline tokens: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)
        try:
            self.offline_login_token = self.offline_tokens['login_token']
        except:
            raise OTPmeException(_("Unable to find offline login token."))

        # Make sure we use destination token for linked tokens.
        if self.offline_login_token.destination_token:
            try:
                dst_token_uuid = self.offline_login_token.destination_token
                self.offline_verify_token = self.offline_tokens[dst_token_uuid]
                log_msg = _("Using destination token: {self.offline_verify_token.rel_path}", log=True)[1]
                self.logger.debug(log_msg)
            except:
                msg = _("Unable to find destination token: {token}")
                msg = msg.format(token=self.offline_login_token.destination_token)
                raise OTPmeException(msg)
        else:
            self.offline_verify_token = self.offline_login_token

        if not reload_token:
            log_msg = _("Found offline login token: {path}", log=True)[1]
            log_msg = log_msg.format(path=self.offline_login_token.rel_path)
            self.logger.info(log_msg)

    def verify_offline_token(self, login=True):
        """ Verify offline token. """
        import hashlib
        from paramiko.agent import Agent
        enc_pass = None
        auth_password = None
        smartcard_data = None
        found_smartcard = None

        # Load offline tokens.
        self.load_offline_tokens()

        if len(self.offline_tokens) == 0:
            msg = (_("Unable to do offline login: No cached tokens found."))
            raise OTPmeException(msg)

        need_encryption = self.offline_token.need_encryption
        enc_challenge = self.offline_token.enc_challenge

        if need_encryption:
            log_msg = _("Offline tokens are encrypted.", log=True)[1]
            self.logger.debug(log_msg)

        # Set verify token.
        verify_token = self.offline_verify_token

        need_password = False
        if verify_token.need_password:
            need_password = True

        # If second factor token is enabled check if we have it (cached).
        if verify_token.second_factor_token_enabled:
            # Check if we need a password to verify the second factor token.
            if verify_token.sftoken.need_password:
                need_password = True
            # Handle U2F second factor token.
            if verify_token.sftoken.pass_type == "smartcard":
                found_smartcard = verify_token.sftoken
            log_msg = _("Found offline second factor token: {sftoken_path}", log=True)[1]
            log_msg = log_msg.format(sftoken_path=verify_token.sftoken.rel_path)
            self.logger.debug(log_msg)

        if verify_token.pass_type == "smartcard":
            found_smartcard = verify_token

        # Get password via PAM if needed.
        if need_password:
            password = self.get_password()

        # Try to get SSH agent script from offline tokens.
        try:
            self.ssh_agent_script_path, \
            self.ssh_agent_script_opts, \
            self.ssh_agent_script_uuid, \
            self.ssh_agent_script_signs, \
            self.ssh_agent_script = self.offline_token.get_script("ssh-agent")
        except Exception as e:
            msg = _("Unable to get SSH agent script from offline token: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)

        # When doing a login (not a screen unlock) check if token is authorized
        # for login (e.g. check policies).
        if not self.login_status:
            # We also check if the token is allowed to login via the current
            # interface (e.g. gui, tty).
            status, \
            reply = self.hostd_conn.authorize_token(self.offline_login_token.uuid,
                                                login_interface=self.login_interface)
            if not status:
                raise AuthFailed(reply)

        # Split off password, OTP and PIN.
        result = verify_token.split_password(password)
        otp = result['otp']
        pin = result['pin']
        static_pass = result['pass']

        # Build static password part from password and PIN if given.
        static_pass_part = static_pass
        if pin:
            static_pass_part += str(pin)

        if found_smartcard:
            # If we have a smartcard offline token try to detect local
            # connected smartcard token.
            sc_types = [found_smartcard.token_type]
            try:
                self.smartcard = detect_smartcard(sc_types)
            except Exception as e:
                msg = _("Error detecting smartcard: {error}")
                msg = msg.format(error=e)
                raise OTPmeException(msg)
            if not self.smartcard:
                raise OTPmeException(_("No smartcard detected."))
            # Get smartcard client handler.
            try:
                smartcard_client_handler = config.get_smartcard_handler(found_smartcard.token_type)[0]
            except NotRegistered:
                raise
            smartcard_client_handler = smartcard_client_handler(sc_type=found_smartcard.token_type,
                                                            token_rel_path=found_smartcard.rel_path,
                                                            message_method=self.send_pam_message,
                                                            error_message_method=self.send_pam_error)
            enc_pass = smartcard_client_handler.handle_offline_challenge(smartcard=self.smartcard,
                                                                        token=found_smartcard,
                                                                        password=password,
                                                                        enc_challenge=enc_challenge)
            smartcard_data = smartcard_client_handler.get_smartcard_data(smartcard=self.smartcard,
                                                                        token=found_smartcard,
                                                                        password=password)

        # Handle SSH tokens.
        if verify_token.pass_type == "ssh_key":
            # SSH key password is always the static password entered first.
            ssh_key_pass = static_pass
            # Try to start SSH agent script.
            if not self.ssh_agent_status():
                self.start_ssh_agent()
            # Try to get SSH agent PID from environment.
            try:
                ssh_agent_pid = os.environ['SSH_AGENT_PID']
            except:
                ssh_agent_pid = None
            # For software-only OTPme SSH tokens the encryption passphrase is
            # the SSH key passphrase.
            if verify_token.ssh_private_key:
                enc_pass = static_pass_part
                otp = password
            else:
                # If the token does not have a private key (e.g. a hardware
                # token like the yubikey) we check if the token is present
                # via ssh-agent.
                log_msg = _("Getting SSH login key from ssh-agent...", log=True)[1]
                self.logger.debug(log_msg)
                if not self.ssh_agent_conn:
                    self.ssh_agent_conn = Agent()
                # Get available public keys from ssh-agent.
                agent_keys = {}
                public_keys = []
                for key in self.ssh_agent_conn.get_keys():
                    public_key = key.get_base64()
                    public_keys.append(public_key)
                    agent_keys[public_key] = key
                log_msg = _("Got {len(agent_keys)} keys from SSH agent.", log=True)[1]
                self.logger.debug(log_msg)
                # Get SSH agent key instance.
                try:
                    ssh_login_key = agent_keys[verify_token.ssh_public_key]
                except KeyError:
                    ssh_login_key = None

                if not ssh_login_key:
                    msg, log_msg = _("Cannot find SSH public key of token: {path}", log=True)
                    msg = msg.format(path=verify_token.rel_path)
                    log_msg = log_msg.format(path=verify_token.rel_path)
                    self.logger.debug(log_msg)
                    raise AuthFailed(msg)

                # When using a hardware token like the yubikey the encryption
                # passphrase is derived via ssh-agent signing.
                agent_conn = self.get_agent_connection()
                try:
                    if not agent_conn.check_ssh_key_pass():
                        log_msg = _("Adding SSH key passphrase to otpme-agent...", log=True)[1]
                        self.logger.debug(log_msg)
                        try:
                            agent_conn.add_ssh_key_pass(ssh_agent_pid=ssh_agent_pid,
                                                        ssh_key_pass=ssh_key_pass)
                        except Exception as e:
                            msg = (_("Unable to add SSH key passphrase to otpme-agent"))
                            raise OTPmeException(msg)
                finally:
                    agent_conn.close()

                # Try to derive passphrase for offline token decryption via ssh-agent.
                if need_encryption:
                    if not enc_challenge:
                        msg = (_("Offline token is missing encryption challenge."))
                        raise OTPmeException(msg)

                    log_msg = _("Getting encryption response from ssh-agent...", log=True)[1]
                    self.logger.debug(log_msg)
                    # Derive AES passphrase from challenge+static_pass_part using
                    # ssh-agent signing.
                    # https://github.com/paramiko/paramiko/issues/507
                    try:
                        _ssh_challenge = enc_challenge + static_pass_part
                        _ssh_response = ssh_login_key.sign_ssh_data(_ssh_challenge)
                        sha256 = hashlib.sha512(_ssh_response)
                        enc_pass = sha256.hexdigest()
                    except Exception as e:
                        config.raise_exception()
                        msg = _("Error deriving AES key for offline token decryption via ssh-agent: {e}")
                        raise OTPmeException(msg)

        # Handle static password tokens.
        elif verify_token.pass_type == "static":
            # For static password tokens the AES passphrase is the token
            # password.
            if need_encryption and not enc_pass:
                enc_pass = static_pass_part

            # For static password tokens the password includes the OTP and both
            # must be sent together as one string.
            otp = None
            auth_password = password

        elif verify_token.pass_type == "otp":
            # For OTP tokens the AES passphrase is the token PIN.
            if need_encryption and not enc_pass:
                enc_pass = static_pass_part
            # For OTP tokens the password is the OTP.
            otp = password
        elif verify_token.pass_type == "smartcard":
            pass
        else:
            msg, log_msg = _("Unsupported offline token found: {path} token_type: {type}", log=True)
            msg = msg.format(path=verify_token.rel_path, type=verify_token.token_type)
            log_msg = log_msg.format(path=verify_token.rel_path, type=verify_token.token_type)
            self.logger.warning(log_msg)
            raise OTPmeException(msg)

        reload_offline_token = False
        if verify_token.keep_session:
            reload_offline_token = True
            self.offline_token.keep_session = True

        # Add decryption passphrase to offline tokens.
        if need_encryption:
            reload_offline_token = True
            log_msg = _("Setting offline token encryption passphrase...", log=True)[1]
            self.logger.debug(log_msg)
            self.offline_token.set_enc_passphrase(passphrase=enc_pass,
                                key_function=self.offline_key_func,
                                key_function_opts=self.offline_key_func_opts,
                                iterations_by_score=self.iterations_by_score,
                                check_pass_strength=self.check_offline_pass_strength)
            del enc_pass

        if reload_offline_token:
            self.load_offline_tokens(reload_token=True)
            # Re-set verify token.
            verify_token = self.offline_verify_token

        # Verify offline tokens.
        log_msg = _("Verifying offline token: {verify_token}", log=True)[1]
        log_msg = log_msg.format(verify_token=verify_token.rel_path)
        self.logger.debug(log_msg)
        auth_password = str(auth_password)
        session_uuid = self.offline_token.session_uuid

        try:
            self.offline_token_verify_status = verify_token.verify(auth_type="clear-text",
                                                    session_uuid=session_uuid,
                                                    password=auth_password,
                                                    smartcard_data=smartcard_data,
                                                    otp=otp)
        except Exception as e:
            config.raise_exception()
            msg = _("Error verifying token '{path}': {error}")
            msg = msg.format(path=verify_token.rel_path, error=e)
            raise OTPmeException(msg)
        finally:
            self.offline_token_verified = True

        # Workaround for "[Errno 16] Resource busy" with yubikey.
        if self.smartcard:
            del self.smartcard
            self.smartcard = None

        if not self.offline_token_verify_status:
            msg, log_msg = _("Token verification failed: {path}", log=True)
            msg = msg.format(path=verify_token.rel_path)
            log_msg = log_msg.format(path=verify_token.rel_path)
            self.logger.debug(log_msg)
            raise AuthFailed(msg)

        log_msg = _("Token verified successful: {verify_token}", log=True)[1]
        log_msg = log_msg.format(verify_token=verify_token.rel_path)
        self.logger.debug(log_msg)

        # Add SSH key to agent.
        if verify_token.token_type == "ssh":
            if verify_token._ssh_private_key:
                from otpme.lib import ssh
                log_msg = _("Adding SSH key to agent...", log=True)[1]
                self.logger.debug(log_msg)
                try:
                    ssh.add_agent_key(verify_token._ssh_private_key)
                except Exception as e:
                    log_msg = _("Unable to add key to SSH agent: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.debug(log_msg)

        return self.offline_token_verify_status

    def offline_auth(self, login=False):
        """ Try to authenticate user via offline tokens. """
        if login:
            log_msg = _("Trying offline login...", log=True)[1]
            self.logger.info(log_msg)
        else:
            log_msg = _("Trying offline authentication...", log=True)[1]
            self.logger.info(log_msg)

        # Mark session as offline.
        self.offline_login = True

        # Activate autoconfirm of otpme-pinentry to autoconfirm key usage while
        # doing login.
        self.activate_gpg_agent_autoconfirm()

        agent_conn = None
        if login:
            # Get agent connection.
            agent_conn = self.get_agent_connection()

            # Remove old/empty agent/login session if needed.
            agent_user = agent_conn.get_user()
            if agent_user:
                try:
                    agent_conn.del_session()
                except Exception as e:
                    msg = _("Error removing empty session from agent: {e}")
                    raise OTPmeException(msg)

            # Add login session to otpme-agent.
            self.login_session_id = agent_conn.add_session(self.username, tty=self.tty)
            if not self.login_session_id:
                msg = (_("Unable to add login session to otpme-agent."))
                raise OTPmeException(msg)

        if not self.offline_token_verified:
            # Acquire offline token lock.
            self.offline_token.lock()
            # Verify offline token.
            token_verify_status = False
            token_verify_message = ""
            token_verfy_error = False
            try:
                token_verify_status = self.verify_offline_token(login=login)
            except AuthFailed as e:
                token_verify_message = str(e)
            except Exception as e:
                token_verfy_error = True
                token_verify_message = str(e)
            # Release offline token lock.
            self.offline_token.unlock()

            # Handle token verification errors.
            if token_verfy_error:
                if self.offline_login_token:
                    msg = _("User offline token verification error: {path}: {message}")
                    msg = msg.format(path=self.offline_login_token.rel_path, message=token_verify_message)
                else:
                    msg = _("User offline token verification error: {message}")
                    msg = msg.format(message=token_verify_message)
                raise OTPmeException(msg)

            # Handle token verifcation failed errors.
            if not token_verify_status:
                if token_verify_message:
                    msg = _("User offline login failed: {message}")
                    msg = msg.format(message=token_verify_message)
                else:
                    if self.offline_login_token:
                        msg = _("User offline login failed with token: {path}")
                        msg = msg.format(path=self.offline_login_token.rel_path)
                    else:
                        msg = (_("User offline login failed."))
                raise AuthFailed(msg)

        # On success set login token to agent and update offline session.
        if login:
            # Update offline session file.
            self.offline_token.lock()

            # Try to get offline sessions via login token.
            try:
                token_oid = self.offline_login_token.oid
                self.offline_sessions = self.offline_token.get_offline_sessions(token_oid)
            except NoOfflineSessionFound as e:
                pass
            except Exception as e:
                log_msg = _("Error reading offline sessions from file: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

            if self.offline_sessions:
                log_msg = _("Found {offline_sessions} offline sessions.", log=True)[1]
                log_msg = log_msg.format(offline_sessions=len(self.offline_sessions))
                self.logger.debug(log_msg)

            # Try to get login script.
            try:
                self.login_script_path, \
                self.login_script_opts, \
                self.login_script_uuid, \
                self.login_script_signs, \
                self.login_script = self.offline_token.get_script("login")
            except Exception as e:
                log_msg = _("Unable to get login script from offline token: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.debug(log_msg)

            if self.login_script_path:
                log_msg = _("Got login script from offline tokens.", log=True)[1]
                self.logger.debug(log_msg)

            # Update timestamp of login token cache file (used to calculate
            # expiry of offline tokens).
            if os.path.exists(self.offline_token.login_token_uuid_file):
                os.utime(self.offline_token.login_token_uuid_file, None)

            try:
                self.offline_token.update_offline_session(self.login_session_id)
            except NoOfflineSessionFound as e:
                log_msg = _("Found no offline session to update.", log=True)[1]
                self.logger.debug(log_msg)
            except Exception as e:
                log_msg = _("Unable to update offline session: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
            finally:
                self.offline_token.unlock()

            # Set offline login token.
            self.login_token = self.offline_login_token.rel_path

            # Set login token to otpme-agent.
            try:
                agent_conn.set_login_token(self.offline_login_token.rel_path,
                                            self.offline_login_token.pass_type)
            except Exception as e:
                log_msg = _("Unable to set login token to otpme-agent: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

            # Add RSP from offline session to otpme-agent.
            if self.offline_sessions:
                for realm in self.offline_sessions:
                    for site in self.offline_sessions[realm]:
                        session = self.offline_sessions[realm][site]
                        try:
                            agent_conn.add_rsp(realm=realm, site=site,
                                                rsp=session['rsp'],
                                                slp=session['slp'],
                                                rsp_signature=session['rsp_signature'],
                                                session_key=session['session_key'],
                                                login_time=session['login_time'],
                                                timeout=session['session_timeout'],
                                                unused_timeout=session['session_unused_timeout'],
                                                offline=session['offline_allowed'])
                        except Exception as e:
                            log_msg = _("Unable to add RSP to otpme-agent: {error}", log=True)[1]
                            log_msg = log_msg.format(error=e)
                            self.logger.warning(log_msg)
                        # Mount shares.
                        try:
                            shares = session['shares']
                        except KeyError:
                            shares = []
                        if shares:
                            mount_reply = agent_conn.mount_shares(shares=shares)
                            log_msg = mount_reply
                            self.logger.info(log_msg)
            else:
                log_msg = _("No offline session found. Relogin required when servers are available again...", log=True)[1]
                self.logger.debug(log_msg)

            # Add ACL for the login user to allow access to otpme-agent login
            # session.
            agent_conn.add_acl(username=self.username, acl="all")

            auth_message = _("Offline login succeeded with token: {path}")
            auth_message = auth_message.format(path=self.offline_login_token.rel_path)
        else:
            auth_message = _("Offline authentication succeeded with token: {path}")
            auth_message = auth_message.format(path=self.offline_login_token.rel_path)
        if agent_conn:
            agent_conn.close()

        return auth_message

        msg, log_msg = _("WARNING: You may have hit a BUG of offline_auth() in '{name}'. Authentication failed.", log=True)
        msg = msg.format(name=__name__)
        log_msg = log_msg.format(name=__name__)
        self.logger.critical(log_msg)
        raise OTPmeException(msg)

    def online_auth(self, login=False):
        """ Try to login/authenticate user against OTPme server. """
        from otpme.lib.classes.login_handler import LoginHandler
        # Activate autoconfirm of otpme-pinentry to autoconfirm key usage while
        # doing login.
        self.activate_gpg_agent_autoconfirm()

        need_ssh_key_pass = True
        if self.offline_token.pinned:
            log_msg = _("Trying pinned offline token authentication...", log=True)[1]
            self.logger.info(log_msg)
            # Acquire offline token lock.
            self.offline_token.lock()
            # Verify offline token.
            try:
                self.verify_offline_token(login=login)
            except AuthFailed as e:
                self.auth_status = False
                self.auth_failed = True
                self.auth_message = str(e)
            except Exception as e:
                self.auth_status = False
                self.auth_failed = True
                self.auth_message = str(e)
            # Release offline token lock.
            self.offline_token.unlock()

            if self.auth_failed:
                log_msg = _("Pinned offline token authentication failed: {message}", log=True)[1]
                log_msg = log_msg.format(message=self.auth_message)
                self.logger.info(log_msg)
                return
            need_ssh_key_pass = True

        # Mark session as online.
        self.offline_login = False

        if login:
            auth_only = False
            check_offline_pass_strength = self.check_offline_pass_strength
            offline_iterations_by_score = self.iterations_by_score
            offline_key_derivation_func = self.offline_key_func
            offline_key_func_opts = self.offline_key_func_opts
        else:
            auth_only = True
            check_offline_pass_strength = False
            offline_iterations_by_score = {}
            offline_key_derivation_func = None
            offline_key_func_opts = {}

        if self.login_status:
            unlock = True
            add_agent_acl = False
        else:
            unlock = False
            add_agent_acl = True

        start_ssh_agent = False
        if self.ensure_ssh_agent == "auto":
            start_ssh_agent = None
        if self.ensure_ssh_agent is True:
            start_ssh_agent = True

        # Send auth/login request.
        login_handler = LoginHandler()
        try:
            login_handler.login(username=self.username,
                                password_method=self.get_password,
                                use_ssh_agent=self.use_ssh_agent,
                                start_ssh_agent=start_ssh_agent,
                                ssh_agent_method=self.start_ssh_agent,
                                use_smartcard=self.use_smartcard,
                                offline_token=self.offline_token,
                                endpoint=True, change_user=True,
                                send_password=self.send_password,
                                auth_only=auth_only,
                                unlock=unlock,
                                sync_token_data=True,
                                mount_shares=True,
                                need_ssh_key_pass=need_ssh_key_pass,
                                add_agent_acl=add_agent_acl,
                                timeout=self.connection_timeout,
                                connect_timeout=self.connect_timeout,
                                login_session_id=self.login_session_id,
                                login_interface=self.login_interface,
                                message_method=self.send_pam_message,
                                error_message_method=self.send_pam_error,
                                cache_login_tokens=self.cache_login_tokens,
                                offline_key_derivation_func=offline_key_derivation_func,
                                offline_key_func_opts=offline_key_func_opts,
                                check_offline_pass_strength=check_offline_pass_strength,
                                offline_iterations_by_score=offline_iterations_by_score,
                                cleanup_method=self.deactivate_gpg_agent_autoconfirm)
            self.auth_status = True
        except AuthFailed as e:
            self.auth_failed = True
            self.auth_message = str(e)
        except HostDisabled as e:
            self.auth_failed = True
            self.auth_message = str(e)
        except Exception as e:
            if login:
                self.auth_message, log_msg = _("Error while sending login request: {error}", log=True)
                self.auth_message = self.auth_message.format(error=e)
                log_msg = log_msg.format(error=e)
            else:
                self.auth_message, log_msg = _("Error while authenticating with server: {error}", log=True)
                self.auth_message = self.auth_message.format(error=e)
                log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg, exc_info=True)
            return

        # Get login reply.
        login_reply = login_handler.login_reply

        ## Get login session ID.
        #self.login_session_id = login_reply['login_session_id']

        if self.auth_status is True and login:
            # Get login token.
            self.login_token = login_reply['auth_reply']['login_token']
            # Get login script
            self.login_script = login_reply['auth_reply']['login_script']
            self.login_script_uuid = login_reply['auth_reply']['login_script_uuid']
            self.login_script_path = login_reply['auth_reply']['login_script_path']
            self.login_script_opts = login_reply['auth_reply']['login_script_opts']
            self.login_script_signs = login_reply['auth_reply']['login_script_signs']

        # The SSH agent script is delivered even if the auth/login failed!
        self.ssh_agent_script = login_reply['ssh_agent_script']
        self.ssh_agent_script_uuid = login_reply['ssh_agent_script_uuid']
        self.ssh_agent_script_path = login_reply['ssh_agent_script_path']
        self.ssh_agent_script_opts = login_reply['ssh_agent_script_opts']
        self.ssh_agent_script_signs = login_reply['ssh_agent_script_signs']

    def authenticate(self):
        """
        Try to authenticate user against OTPme realm with fallback to (cached)
        offline tokens.
        """
        # Set HOME (used by key script started from agent on crypfs mount).
        home_dir = self.get_home_dir(self.username)
        os.environ['HOME'] = home_dir
        self.pamh.env['HOME'] = home_dir
        # Make sure we create a home dir if configured.
        if self.create_home_directory:
            if not os.path.exists(home_dir):
                if self.home_skeleton:
                    # Use skeleton for new home dir.
                    shutil.copytree(self.home_skeleton, home_dir)
                    filetools.set_fs_ownership(path=home_dir,
                                            user=self.username,
                                            group=True,
                                            recursive=True)
                else:
                    filetools.create_dir(path=home_dir,
                                        user=self.username,
                                        group=True,
                                        mode=0o700)

        # Try to init OTPme.
        try:
            init_otpme(use_backend=False)
        except Exception as e:
            log_msg = _("Problem initializing OTPme: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            self.cleanup()
            return self.pamh.PAM_SYSTEM_ERR

        # Make sure we got a username from PAM.
        if not self.username:
            self.cleanup()
            return self.pamh.PAM_USER_UNKNOWN

        # Check if system user exists.
        try:
            stuff.user_exists(self.username)
        except Exception as e:
            log_msg = _("User does not exist: {user}", log=True)[1]
            log_msg = log_msg.format(user=self.username)
            self.logger.warning(log_msg)
            self.cleanup()
            return self.pamh.PAM_USER_UNKNOWN

        # Set realm data to users environment.
        if config.realm:
            #os.environ['OTPME_REALM'] = config.realm
            self.pamh.env['OTPME_REALM'] = config.realm
        if config.realm_uuid:
            #os.environ['OTPME_REALM_UUID'] = config.realm_uuid
            self.pamh.env['OTPME_REALM_UUID'] = config.realm_uuid
        if config.site:
            #os.environ['OTPME_SITE'] = config.site
            self.pamh.env['OTPME_SITE'] = config.site
        if config.site_uuid:
            #os.environ['OTPME_SITE_UUID'] = config.site_uuid
            self.pamh.env['OTPME_SITE_UUID'] = config.site_uuid
        if config.site_address:
            #os.environ['OTPME_SITE_ADDRESS'] = config.site_address
            self.pamh.env['OTPME_SITE_ADDRESS'] = config.site_address

        # Get DISPLAY from PAM.
        if self.pamh.xdisplay:
             self.display = self.pamh.xdisplay
        else:
            if self.pamh.tty and self.pamh.tty.startswith(":"):
                self.display = self.pamh.tty
        if self.display:
            log_msg = _("Got DISPLAY from PAM: {self.display}", log=True)[1]
            self.logger.debug(log_msg)
            os.environ['DISPLAY'] = self.display
            self.pamh.env['DISPLAY'] = self.display
            self.login_interface = "gui"
        if self.pamh.tty:
            self.tty = self.pamh.tty
        else:
            try:
                self.tty = os.ttyname(0)
            except:
                self.tty = None
        if self.tty:
            os.environ['GPG_TTY'] = self.tty
            self.pamh.env['GPG_TTY'] = self.tty

        log_msg = _("Got PAM user: {self.username}", log=True)[1]
        self.logger.debug(log_msg)

        # Get offline token handler.
        self.offline_token = OfflineToken()

        # Get connection to hostd.
        try:
            self.hostd_conn = connections.get("hostd")
        except Exception as e:
            self.cleanup()
            log_msg = _("Unable to get connection to hostd: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            return self.pamh.PAM_SYSTEM_ERR

        # Check host status.
        status, reply = self.hostd_conn.get_host_status()
        if not status:
            log_msg = _("Got host status: {status}", log=True)[1]
            log_msg = log_msg.format(status=reply)
            self.logger.warning(log_msg)
            self.cleanup()
            return self.pamh.PAM_AUTH_ERR

        # Get user UUID.
        self.user_uuid = self.get_user_uuid()

        if not self.user_uuid:
            log_msg = _("Unknown user: {user}", log=True)[1]
            log_msg = log_msg.format(user=self.username)
            self.logger.warning(log_msg)
            self.cleanup()
            return self.pamh.PAM_USER_UNKNOWN

        # Check if user is allowed to login.
        try:
            stuff.check_login_user(user_name=self.username,
                                    user_uuid=self.user_uuid)
        except Exception as e:
            log_msg = str(e)
            self.logger.warning(log_msg)
            self.cleanup()
            return self.pamh.PAM_AUTH_ERR

        # Add user infos to environment.
        os.environ['OTPME_USER'] = self.username
        self.pamh.env['OTPME_USER'] = self.username
        os.environ['OTPME_USER_UUID'] = self.user_uuid
        self.pamh.env['OTPME_USER_UUID'] = self.user_uuid

        log_msg = _("Configuring logger...", log=True)[1]
        self.logger.debug(log_msg)
        log_banner = f"{config.log_name}:{self.username}"
        self.logger = config.setup_logger(banner=log_banner,
                                        existing_logger=config.logger)

        # Set user we want to handle offline tokens for. This also creates the
        # logins dir.
        try:
            self.offline_token.set_user(user=self.username,
                                        uuid=self.user_uuid)
        except Exception as e:
            msg = _("Error initializing offline tokens: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg)

        # Remove outdated login session directories.
        try:
            self.offline_token.lock()
            self.offline_token.remove_outdated_session_dirs()
        except Exception as e:
            log_msg = _("Error removing outdated session directories: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
        finally:
            self.offline_token.unlock()

        # Create users environment dir.
        if not os.path.exists(self.env_dir):
            filetools.create_dir(path=self.env_dir,
                                user=self.username,
                                mode=0o700)

        # Make sure otpme-agent is running as login user.
        try:
            stuff.start_otpme_agent(user=self.username, wait_for_socket=True)
        except Exception as e:
            log_msg = _("Unable to start otpme-agent: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            self.cleanup()
            return self.pamh.PAM_SYSTEM_ERR

        # Check if we are already logged in.
        try:
            # Try to get agent connection.
            agent_conn = self.get_agent_connection()
            self.login_status = agent_conn.get_status()
            #login_pass_type = agent_conn.get_login_pass_type()
            #login_token = agent_conn.get_login_token()
        except:
            self.login_status = False
            #login_pass_type = None
            #login_token = None

        # FIXME: make it possible to force screen unlock only with the login token!?!
        #if self.login_status:
        #    # If this is a screen unlock request and login token was of type
        #    # ssh_key there is not need to check if the SSH agent is running.
        #    if login_pass_type == "ssh_key":
        #        self.ensure_ssh_agent = False
        #        self.use_ssh_agent = True
        #    # FIXME: should we do the same here for smartcard sessions???
        #    #       - we need to add token type to otpme-agent for this!!!


        # If we are already logged in (e.g. this is a screen unlock request) we
        # just have to verify the given credentials.
        if self.login_status is not False:
            log_msg = _("User is already logged in. This is most likely a screen unlock request.", log=True)[1]
            self.logger.info(log_msg)

            # Get SSH agent script.
            ssh_agent_script_file = os.path.join(self.login_session_dir, "ssh-agent-script.json")
            if os.path.exists(ssh_agent_script_file):
                agent_script_data = filetools.read_file(ssh_agent_script_file)
                agent_script_data = json.loads(agent_script_data)
                self.ssh_agent_script = agent_script_data['ssh_agent_script']
                self.ssh_agent_script_uuid = agent_script_data['ssh_agent_script_uuid']
                self.ssh_agent_script_path = agent_script_data['ssh_agent_script_path']
                self.ssh_agent_script_opts = agent_script_data['ssh_agent_script_opts']
                self.ssh_agent_script_signs = agent_script_data['ssh_agent_script_signs']

            # By default we only try online authentication on screen unlock.
            try_online_auth = True
            try_offline_auth = False

            try:
                offline_allowed = agent_conn.get_offline()
            except:
                offline_allowed = False

            # If the user logged in offline or the login session allows offline
            # logins we must check if the login token is available as offline
            # token.
            if offline_allowed or self.offline_login:
                # Try to load offline tokens.
                try:
                    self.load_offline_tokens()
                except Exception as  e:
                    pass
                # If the login token is available as offline token we may try
                # offline authentication.
                if self.offline_login_token:
                    if self.offline_login_token.rel_path == self.login_token:
                        try_offline_auth = True
                        # If screen unlocking via offline tokens is enabled not
                        # need to try online auth.
                        if self.unlock_via_offline_token:
                            try_online_auth = False

            if try_online_auth:
                # Make sure ssh agent is restarted on screen unlock.
                if self.ssh_agent_status():
                    try:
                        self.stop_ssh_agent(verify_signs=False)
                    except Exception as e:
                        log_msg = _("Failed to run SSH agent script: {error}", log=True)[1]
                        log_msg = log_msg.format(error=e)
                        self.logger.warning(log_msg)
                self.start_ssh_agent()
                # Try to authenticate user with OTPme servers.
                self.online_auth(login=False)
                # If authentication was successful no need to try offline auth.
                if self.auth_status:
                    try_offline_auth = False

            if try_offline_auth:
                # We dont want default "Loging failed" as prefix to auth
                # message when doing screen unlock (which is not a login)
                self.failed_message = ""
                if self.auth_message:
                    temp_msg = self.auth_message
                    self.auth_message = _("User authentication failed: {message}")
                    self.auth_message = self.auth_message.format(message=temp_msg)
                # Fallback to offline token authentication if there was an
                # online authentication error other than AuthFailed (e.g.
                # broken network connection)
                if not self.auth_failed and self.offline_token.status():
                    # If realm authentication failed for any other reason than
                    # "AuthFailed" try offline authentication.
                    self.offline = True
                    # Reset auth failed status.
                    self.auth_failed = False
                    # Print auth failure message from online auth attempt.
                    if self.auth_message:
                        log_msg = self.auth_message
                        self.logger.warning(log_msg)
                    # Try to authenticate via offline tokens.
                    try:
                        self.auth_message = self.offline_auth(login=False)
                        self.auth_status = True
                    except AuthFailed as e:
                        self.auth_failed = True
                        self.auth_message = str(e)
                    except Exception as e:
                        self.auth_message = str(e)

                    if self.auth_status:
                        self.auth_message = _("User offline authentication successful.")
                    elif self.auth_failed:
                        self.failed_message = _("User offline authentication failed: {message}")
                        self.failed_message = self.failed_message.format(message=self.auth_message)
                        self.auth_message = ""
                    else:
                        self.failed_message = _("Error trying offline authentication: {message}")
                        self.failed_message = self.failed_message.format(message=self.auth_message)
                        self.auth_message = ""

        else:
            # Get agent connection.
            agent_conn = self.get_agent_connection()
            # Add login session to otpme-agent.
            try:
                if not self.login_session_id:
                    self.login_session_id = agent_conn.add_session(self.username, tty=self.tty)
                    if not self.login_session_id:
                        msg = (_("Unable to add login session to otpme-agent."))
                        raise OTPmeException(msg)
            finally:
                agent_conn.close()

            # Add OTPme login session to users environment. We got the session
            # ID from login_handler.login() or offline_auth().
            if self.login_session_id:
                self.login_session_dir = f"{self.env_dir}/{self.login_session_id}"
                if not os.path.exists(self.login_session_dir):
                    filetools.create_dir(path=self.login_session_dir,
                                        user=self.username,
                                        mode=0o700)
                os.environ['OTPME_LOGIN_SESSION_DIR'] = self.login_session_dir
                os.environ['OTPME_LOGIN_SESSION'] = self.login_session_id
                self.pamh.env['OTPME_LOGIN_SESSION_DIR'] = self.login_session_dir
                self.pamh.env['OTPME_LOGIN_SESSION'] = self.login_session_id

            # Make sure SSH/GPG agent is running.
            if self.ensure_ssh_agent is True:
                try:
                    # FIXME: do we still need this??
                    ## Make sure there is no SSH agent running for the user if
                    ## this is a login request. This may be needed if the user
                    ## logs in with a non-ssh token and there is a ssh agent
                    ## from an old session still running.
                    #if not self.login_status and not self.ssh_agent_started:
                    #    self.logger.debug("Stopping probably running SSH agent.")
                    #    try:
                    #        self.stop_ssh_agent()
                    #    except Exception as e:
                    #        msg = _("Unable to run SSH agent script: {error}")
                    #        msg = msg.format(error=e)
                    #        self.logger.warning(msg)
                    if not self.ssh_agent_status():
                        self.start_ssh_agent()
                except Exception as e:
                    log_msg = _("Cannot start SSH agent: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg, exc_info=True)

            # Try to auth/login user via OTPme servers.
            self.online_auth(login=self.realm_login)

            if not self.auth_status:
                if not self.auth_failed and self.offline_token.status():
                    # If realm login failed for any other reason than
                    # "AuthFailed" try offline authentication.
                    self.offline = True
                    # Print auth failure message from online login attempt.
                    if self.auth_message:
                        log_msg = self.auth_message
                        self.logger.warning(log_msg)
                    # Try logging in via offline tokens.
                    try:
                        self.auth_message = self.offline_auth(login=True)
                        self.auth_status = True
                    except AuthFailed as e:
                        self.auth_failed = True
                        self.auth_message = _("Offline login failed: {error}")
                        self.auth_message = self.auth_message.format(error=e)
                    except Exception as e:
                        self.auth_message = _("Error trying offline login: {error}")
                        self.auth_message = self.auth_message.format(error=e)

        # Set PAM return value depending on login/auth status.
        if self.auth_status:
            # Show login greeting via PAM message if configured.
            if self.offline:
                if self.offline_greeting:
                    self.login_message = (_("You are logged in offline!"))
            else:
                if self.online_greeting:
                    self.login_message = _("You are logged in to REALM '{realm}'.")
                    self.login_message = self.login_message.format(realm=config.realm)
            # Log success message.
            if self.auth_message:
                log_msg = self.auth_message
                self.logger.info(log_msg)
            # Set PAM stuff.
            self.retval = self.pamh.PAM_SUCCESS
            # Remember if this was a offline login.
            self.pamh.env['OTPME_OFFLINE_LOGIN'] = str(self.offline_login)
            #os.environ['OTPME_OFFLINE_LOGIN'] = str(self.offline_login)
            if self.login_token:
                self.pamh.env['OTPME_LOGIN_TOKEN'] = self.login_token
                #os.environ['OTPME_LOGIN_TOKEN'] = self.login_token
            else:
                log_msg = _("Uuuh, no login token set. This should not happen.", log=True)[1]
                self.logger.warning(log_msg)

            # Run login script
            if self.login_status is False:
                try:
                    self.run_login_script()
                except Exception as e:
                    log_msg = _("Error running login script: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)
            # Save SSH agent script.
            if self.ssh_agent_script:
                ssh_agent_script_file = os.path.join(self.login_session_dir, "ssh-agent-script.json")
                msg = _("Saving ssh-agent script: {file}")
                msg = msg.format(file=ssh_agent_script_file)
                agent_script_data = {
                                    'ssh_agent_script'          : self.ssh_agent_script,
                                    'ssh_agent_script_uuid'     : self.ssh_agent_script_uuid,
                                    'ssh_agent_script_path'     : self.ssh_agent_script_path,
                                    'ssh_agent_script_opts'     : self.ssh_agent_script_opts,
                                    'ssh_agent_script_signs'    : self.ssh_agent_script_signs,
                                    }
                agent_script_data = json.dumps(agent_script_data)
                filetools.create_file(ssh_agent_script_file,
                                    content=agent_script_data,
                                    user=self.username,
                                    mode=0o600)
        else:
            # Read pinentry message file.
            if os.path.exists(self.pinentry_message_file):
                try:
                    fd = open(self.pinentry_message_file, "r")
                    self.failed_message = fd.read()
                    #self.failed_message = self.failed_message.replace("\n", "")
                    fd.close()
                except Exception as e:
                    log_msg = _("Error reading pinentry message file: {file}: {error}", log=True)[1]
                    log_msg = log_msg.format(file=self.pinentry_message_file, error=e)
                    self.logger.error(log_msg)
                # Remove message file, even if reading failed.
                try:
                    os.remove(self.pinentry_message_file)
                except Exception as e:
                    log_msg = _("Error removing pinentry message file: {file}: {error}", log=True)[1]
                    log_msg = log_msg.format(file=self.pinentry_message_file, error=e)
                    self.logger.error(log_msg)

            # Show errors via PAM message if configured.
            if self.show_errors:
                if self.failed_message:
                    self.login_message = self.failed_message
                else:
                    self.login_message = self.auth_message

            # Log failed message.
            log_msg = f"{self.auth_message}: {self.failed_message}"
            self.logger.warning(log_msg)
            # Set PAM stuff.
            self.retval = self.pamh.PAM_AUTH_ERR

            # If this was a failed login request (no screen unlock) stop users
            # ssh-agent.
            if self.login_status is False:
                log_msg = _("Stopping SSH agent after failed login.", log=True)[1]
                self.logger.debug(log_msg)
                try:
                    self.stop_ssh_agent()
                except Exception as e:
                    log_msg = _("Unable to run SSH agent script: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)

        # If this is a realm login and cache_login_tokens is enabled
        # otpme-pinentry auto confirmation is deactivated by OTPmeClient()
        # after offline tokens have been saved (which runs as child process
        # and thus could lead to a race). In any other case we have to
        # make sure it is deactivated here. Same goes for triggering
        # "sync_token_data" hostd command.
        if self.login_status is not False \
        or not self.realm_login \
        or not self.cache_login_tokens \
        or self.offline:
            # Deactivate otpme-pinentry auto confirmation.
            self.deactivate_gpg_agent_autoconfirm()
            # Trigger sync.
            self.hostd_conn.trigger_token_data_sync()

        # Display login/failure message.
        if self.login_message:
            try:
                self.send_pam_message(self.login_message)
            except self.pamh.exception:
                self.cleanup()
                return self.pamh.PAM_SYSTEM_ERR

        if self.ssh_agent_status():
            try:
                self.stop_ssh_agent()
            except Exception as e:
                log_msg = _("Failed to stop SSH agent: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
        if self.ensure_ssh_agent:
            additional_opts = ['--pinentry', config.pinentry]
            try:
                self.start_ssh_agent(additional_opts=additional_opts)
            except Exception as e:
                log_msg = _("Failed to start SSH agent: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

        # Close connetions etc.
        self.cleanup()

        log_msg = _("Returning PAM status: {retval}", log=True)[1]
        log_msg = log_msg.format(retval=repr(self.retval))
        self.logger.debug(log_msg)

        # Return PAM status.
        return self.retval

        log_msg = _("WARNING: You may have hit a BUG of authenticate() in '{name}'. Authentication failed.", log=True)[1]
        log_msg = log_msg.format(name=__name__)
        self.logger.critical(log_msg)
        return self.pamh.PAM_SYSTEM_ERR
