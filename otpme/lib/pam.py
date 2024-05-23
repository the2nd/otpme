# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pwd
import time
import shutil

# FIXME: This is a workaround to prevent pinentry module from loading some
#        modules that will crash sddm.
sys.modules['PyQt4'] = None
sys.modules['PyKDE4'] = None

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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
        self.user_uuid = None
        self.password = None
        self.offline_login = False
        self.allow_null_passwords = False
        self.connect_timeout = 3
        self.connection_timeout = 30
        self.login_session_id = None
        self.login_token = None
        self.login_interface = "tty"
        self.offline_login_token = None
        self.offline_verify_token = None
        self.offline_tokens = {}
        self.offline_sessions = {}
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
        self.ensure_ssh_agent = False
        self.use_ssh_agent = "auto"
        self.use_smartcard = "auto"
        self.smartcard = None
        self.failed_message = "Login failed"
        self.auth_message = ""
        self.login_message = None
        self.message_timeout = 3
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
            config.reload()
            argv.remove("debug")

        for x in argv[1:]:
            val = None
            if "=" in x:
                try:
                    arg = x.split("=")[0]
                    val = x.split("=")[1]
                    self.logger.debug("Got option: %s=%s" % (arg, val))
                except:
                    msg = ("Ignoring malformed PAM parameter: %s" % x)
                    self.logger.critical(msg)
                    continue
            else:
                arg = x
                self.logger.debug("Got option: %s" % arg)

            if arg == "nullok":
                self.allow_null_passwords = True
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
                    msg = ("Ignoring unknown value for use_smartcard: %s" % val)
                    self.logger.critical(msg)
            if arg == "use_ssh_agent":
                if val.lower() == "true":
                    self.use_ssh_agent = True
                    self.ensure_ssh_agent = True
                elif val.lower() == "false":
                    self.use_ssh_agent = False
                elif val.lower() == "auto":
                    self.use_ssh_agent = "auto"
                else:
                    msg = ("Ignoring unknown value for use_ssh_agent: %s" % val)
                    self.logger.critical(msg)
            if arg == "start_ssh_agent":
                self.ensure_ssh_agent = True
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
                            msg = ("Malformed options for PAM parameter: "
                                    "check_offline_pass_strength")
                            self.logger.critical(msg)
                else:
                    self.check_offline_pass_strength = "auto"
            if arg == "offline_key_func":
                # Try to get key derivation function.
                try:
                    offline_key_func = val.split(";")[0]
                except:
                    offline_key_func = None
                    msg = ("Ignoring malformed PAM parameter: offline_key_func")
                    self.logger.critical(msg)

                if offline_key_func:
                    try:
                        config.get_hash_type_default_otps(offline_key_func)
                    except UnsupportedHashType:
                        msg = ("Ignoring unknown value for offline_key_func: %s"
                                % offline_key_func)
                        self.logger.warning(msg)
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
                        msg = ("Malformed options for PAM parameter: "
                                "offline_key_func")
                        self.logger.critical(msg)

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
        # Try to get password via PAM.
        self.logger.debug("Trying to get password from PAM...")
        try:
            pam_msg = self.pamh.Message(self.pamh.PAM_PROMPT_ECHO_OFF, prompt)
            resp = self.pamh.conversation(pam_msg)
        except Exception as e:
            msg = (_("Unable to get password from PAM: %s") % e)
            raise OTPmeException(msg)
        self.password = resp.resp
        # Check if null passwords are allowed.
        if not self.password:
            if self.allow_null_passwords:
                self.logger.debug("Got empty password and 'nullok' option "
                                    "enabled, continuing.")
            else:
                self.logger.warning("Got empty password and 'nullok' option "
                                    "not set. Authentication failed.")
                raise AuthFailed("Empty passwords are not allowed!")
        self.logger.debug("Got password from PAM.")
        return self.password

    def cleanup(self):
        """ Close connections etc. """
        agent_conn = self.get_agent_connection()
        if agent_conn.check_ssh_key_pass():
            self.logger.debug("Removing SSH key passphrase from agent...")
            try:
                agent_conn.del_ssh_key_pass()
            except Exception as e:
                msg = ("Error removing SSH key passphrase from agent.")
                self.logger.critical(msg)
        if self.ssh_agent_conn:
            self.ssh_agent_conn.close()
        # FIXME: do we need this?
        # Workaround for http://bugs.python.org/issue24596
        try:
            del self.smartcard
        except:
            pass
        # Close all connections.
        connections.close_connections()

    def activate_gpg_agent_autoconfirm(self):
        """ Activate gpg-agent auto confirmation of key usage. """
        from otpme.lib.pinentry.pinentry import set_autoconfirm
        self.logger.debug("Enabling GPG pinentry autoconfirmation.")
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
        if display and self.login_session_dir:
            self.logger.debug("Got DISPLAY from PAM session: %s" % display)
            if os.path.exists(self.login_session_dir):
                display_file = "%s/.display" % self.login_session_dir
                filetools.create_file(display_file,
                                    content=display,
                                    user=self.username,
                                    mode=0o600)

        return self.pamh.PAM_SUCCESS

    def get_ssh_agent_ctrl(self, session_id=None):
        """ Get SSH agent script control class """
        from otpme.lib.classes.ssh_agent import SSHAgent
        if not self.ssh_agent_script:
            msg = (_("Got no SSH agent script."))
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
        script_signatures=None, verify_signs=None):
        """ Make sure SSH/GPG agent is running and needed variables are set """
        ssh_auth_sock = None
        ssh_agent_pid = None
        ssh_agent_name = None
        gpg_agent_info = None

        if script:
            self.ssh_agent_script = script
            self.ssh_agent_script_uuid = script_uuid
            self.ssh_agent_script_path = script_path
            self.ssh_agent_script_opts = script_options
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

        if self.login_status:
            # Send "unlock" command to SSH agent script (e.g. restart scdaemon
            # make sure yubikey PIN is re-asked) if this is a screen unlock.
            ssh_auth_sock, \
            ssh_agent_pid, \
            ssh_agent_name, \
            gpg_agent_info = self.ssh_agent.unlock(verify_signs=verify_signs)
        else:
            # Make sure no SSH agent is running before starting a new one.
            self.stop_ssh_agent(verify_signs=verify_signs)

            # Start SSH agent.
            ssh_auth_sock, \
            ssh_agent_pid, \
            ssh_agent_name, \
            gpg_agent_info = self.ssh_agent.start(verify_signs=verify_signs)

        # Set PAM env variables of the SSH agent.
        if gpg_agent_info:
            self.pamh.env['GPG_AGENT_INFO'] = gpg_agent_info
            #os.environ['GPG_AGENT_INFO'] = gpg_agent_info

        if ssh_auth_sock:
            self.pamh.env['SSH_AUTH_SOCK'] = ssh_auth_sock
            #os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock

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
            self.logger.debug("Got no login script.")
            return
        if not self.login_script_uuid:
            self.logger.warning("Missing login script UUID.")
            return
        from otpme.lib.classes import signing
        from otpme.lib import script as _script
        msg = ("Running login script: %s" % self.login_script_path)
        self.logger.info(msg)

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
            msg = (_("Login script error: %s") % e)
            raise OTPmeException(msg)

        # Make sure script output is string.
        script_stdout = script_stdout.decode()
        script_stderr = script_stderr.decode()

        if script_returncode != 0:
            msg = (_("Login script return failure: %s") % script_stderr)
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
                    msg = (_("Error getting agent connection: %s") % e)
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
            raise OTPmeException(_("Error loading offline tokens: %s") % e)
        try:
            self.offline_login_token = self.offline_tokens['login_token']
        except:
            raise OTPmeException("Unable to find offline login token.")

        # Make sure we use destination token for linked tokens.
        if self.offline_login_token.destination_token:
            try:
                dst_token_uuid = self.offline_login_token.destination_token
                self.offline_verify_token = self.offline_tokens[dst_token_uuid]
                self.logger.debug("Using destination token: %s"
                                % self.offline_verify_token.rel_path)
            except:
                msg = (_("Unable to find destination token: %s")
                        % self.offline_login_token.destination_token)
                raise OTPmeException(msg)
        else:
            self.offline_verify_token = self.offline_login_token

        if not reload_token:
            self.logger.info("Found offline login token: %s"
                            % self.offline_login_token.rel_path)

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
            self.logger.debug("Offline tokens are encrypted.")

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
            self.logger.debug("Found offline second factor token: %s"
                            % verify_token.sftoken.rel_path)

        if verify_token.pass_type == "smartcard":
            found_smartcard = verify_token

        # Get password via PAM if needed.
        if need_password and not self.password:
            self.get_password()

        # Try to get SSH agent script from offline tokens.
        try:
            self.ssh_agent_script_path, \
            self.ssh_agent_script_opts, \
            self.ssh_agent_script_uuid, \
            self.ssh_agent_script_signs, \
            self.ssh_agent_script = self.offline_token.get_script("ssh-agent")
        except Exception as e:
            msg = (_("Unable to get SSH agent script form offline token: ") % e)
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
        result = verify_token.split_password(self.password)
        otp = result['otp']
        pin = result['pin']
        static_pass = result['pass']

        # Build static password part from password and PIN if given.
        static_pass_part = static_pass
        if pin:
            static_pass_part += pin

        if found_smartcard:
            # If we have a smartcard offline token try to detect local
            # connected smartcard token.
            sc_types = [found_smartcard.token_type]
            try:
                self.smartcard = detect_smartcard(sc_types)
            except Exception as e:
                msg = (_("Error detecting smartcard: %s") % e)
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
                                                                        password=self.password,
                                                                        enc_challenge=enc_challenge)
            smartcard_data = smartcard_client_handler.get_smartcard_data(smartcard=self.smartcard,
                                                                            token=found_smartcard,
                                                                            password=self.password)

        # Handle SSH tokens.
        if verify_token.pass_type == "ssh_key":
            # SSH key password is always the static password entered first.
            ssh_key_pass = static_pass
            # Try to start SSH agent script.
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
                otp = self.password
            else:
                # If the token does not have a private key (e.g. a hardware
                # token like the yubikey) we check if the token is present
                # via ssh-agent.
                self.logger.debug("Getting SSH login key from ssh-agent...")
                if not self.ssh_agent_conn:
                    self.ssh_agent_conn = Agent()
                # Get available public keys from ssh-agent.
                agent_keys = {}
                public_keys = []
                for key in self.ssh_agent_conn.get_keys():
                    public_key = key.get_base64()
                    public_keys.append(public_key)
                    agent_keys[public_key] = key
                self.logger.debug("Got %s keys from SSH agent."
                                % len(agent_keys))
                # Workaround to detect if hardware GPG card/token is present.
                # If the card is plugged in the public key of the card is
                # listed two times.
                if verify_token.card_type == "gpg":
                    if not public_keys.count(verify_token.ssh_public_key) > 1:
                        agent_keys = {}
                        public_keys = []
                else:
                    if not public_keys.count(verify_token.ssh_public_key) > 0:
                        agent_keys = {}
                        public_keys = []
                # Get SSH agent key instance.
                ssh_login_key = None
                if verify_token.ssh_public_key in agent_keys:
                    ssh_login_key = agent_keys[verify_token.ssh_public_key]

                if not ssh_login_key:
                    msg = (_("Cannot find SSH public key of token: %s")
                            % verify_token.rel_path)
                    self.logger.debug(msg)
                    raise AuthFailed(msg)

                # When using a hardware token like the yubikey the encryption
                # passphrase is derived via ssh-agent signing.
                self.logger.debug("Adding SSH key passphrase to otpme-agent...")
                try:
                    agent_conn.add_ssh_key_pass(ssh_agent_pid=ssh_agent_pid,
                                                        ssh_key_pass=ssh_key_pass)
                except Exception as e:
                    msg = (_("Unable to add SSH key passphrase to otpme-agent."))
                    raise OTPmeException(msg)

                # Try to derive passphrase for offline token decryption via ssh-agent.
                if need_encryption:
                    if not enc_challenge:
                        msg = (_("Offline token is missing encryption challenge."))
                        raise OTPmeException(msg)

                    self.logger.debug("Getting encryption response from ssh-agent...")
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
                        msg = (_("Error deriving AES key for offline "
                                "token decryption via ssh-agent: %s") % e)
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
            auth_password = self.password

        elif verify_token.pass_type == "otp":
            # For OTP tokens the AES passphrase is the token PIN.
            if need_encryption and not enc_pass:
                enc_pass = static_pass_part
            # For OTP tokens the password is the OTP.
            otp = self.password
        elif verify_token.pass_type == "smartcard":
            pass
        else:
            msg = (_("Unsupported offline token found: %s token_type: %s")
                    % (verify_token.rel_path, verify_token.token_type))
            self.logger.critical(msg)
            raise OTPmeException(msg)

        # Add decryption passphrase to offline tokens.
        if need_encryption:
            self.logger.debug("Setting offline token encryption passphrase...")
            if verify_token.keep_session:
                self.offline_token.keep_session = True
            self.offline_token.set_enc_passphrase(passphrase=enc_pass,
                                key_function=self.offline_key_func,
                                key_function_opts=self.offline_key_func_opts,
                                iterations_by_score=self.iterations_by_score,
                                check_pass_strength=self.check_offline_pass_strength)
            del enc_pass
            # Reload offline tokens after setting encryption passphrase.
            self.load_offline_tokens(reload_token=True)
            # Re-set verify token.
            verify_token = self.offline_verify_token

        # Verify offline tokens.
        self.logger.debug("Verifying offline token: %s" % verify_token.rel_path)
        token_verify_status = False
        auth_password = str(auth_password)
        session_uuid = self.offline_token.session_uuid

        try:
            token_verify_status = verify_token.verify(auth_type="clear-text",
                                                    session_uuid=session_uuid,
                                                    password=auth_password,
                                                    smartcard_data=smartcard_data,
                                                    otp=otp)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error verifying token '%s': %s")
                    % (verify_token.rel_path, e))
            raise OTPmeException(msg)

        if not token_verify_status:
            msg = (_("Token verification failed: %s") % verify_token.rel_path)
            self.logger.debug(msg)
            raise AuthFailed(msg)

        self.logger.debug("Token verified successful: %s"
                        % verify_token.rel_path)

        # Add SSH key to agent.
        if verify_token.token_type == "ssh":
            if verify_token._ssh_private_key:
                from otpme.lib import ssh
                self.logger.debug("Adding SSH key to agent...")
                try:
                    ssh.add_agent_key(verify_token._ssh_private_key)
                except Exception as e:
                    msg = ("Unable to add key to SSH agent: %s" % e)
                    self.logger.debug(msg)

        if login:
            # Try to get offline sessions via login token.
            try:
                token_oid = self.offline_login_token.oid
                self.offline_sessions = self.offline_token.get_offline_sessions(token_oid)
            except NoOfflineSessionFound as e:
                pass
            except Exception as e:
                msg = "Error reading offline sessions from file: %s" % e
                self.logger.warning(msg)

            if self.offline_sessions:
                self.logger.debug("Found %s offline sessions."
                                % len(self.offline_sessions))

            # Try to get login script.
            try:
                self.login_script_path, \
                self.login_script_opts, \
                self.login_script_uuid, \
                self.login_script_signs, \
                self.login_script = self.offline_token.get_script("login")
            except Exception as e:
                msg = ("Unable to get login script from offline token: %s" % e)
                self.logger.debug(msg)

        # Update timestamp of login token cache file (used to calculate
        # expiry of offline tokens).
        if os.path.exists(self.offline_token.login_token_uuid_file):
            os.utime(self.offline_token.login_token_uuid_file, None)

        return token_verify_status

    def offline_auth(self, login=False):
        """ Try to authenticate user via offline tokens. """
        if login:
            self.logger.info("Trying offline login...")
        else:
            self.logger.info("Trying offline authentication...")

        # Mark session as offline.
        self.offline_login = True

        # Activate autoconfirm of otpme-pinentry to autoconfirm key usage while
        # doing login.
        self.activate_gpg_agent_autoconfirm()

        if login:
            # Get agent connection.
            agent_conn = self.get_agent_connection()

            # Remove old/empty agent/login session if needed.
            agent_user = agent_conn.get_user()
            if agent_user:
                try:
                    agent_conn.del_session()
                except Exception as e:
                    msg = (_("Error removing empty session from "
                            "agent: %s") % e)
                    raise OTPmeException(msg)

            # Add login session to otpme-agent.
            self.login_session_id = agent_conn.add_session(self.username)
            if not self.login_session_id:
                msg = (_("Unable to add login session to otpme-agent."))
                raise OTPmeException(msg)

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
                msg = (_("User offline token verification error: %s: %s")
                        % (self.offline_login_token.rel_path,
                        token_verify_message))
            else:
                msg = (_("User offline token verification error: %s")
                        % token_verify_message)
            raise OTPmeException(msg)


        # Handle token verifcation failed errors.
        if not token_verify_status:
            if token_verify_message:
                msg = (_("User offline login failed: %s")
                        % token_verify_message)
            else:
                if self.offline_login_token:
                    msg = (_("User offline login failed with token: %s")
                            % self.offline_login_token.rel_path)
                else:
                    msg = (_("User offline login failed."))
            raise AuthFailed(msg)

        # On success set login token to agent and update offline session.
        if login:
            # Update offline session file.
            try:
                self.offline_token.lock()
                self.offline_token.update_offline_session(self.login_session_id)
                self.offline_token.unlock()
            except NoOfflineSessionFound as e:
                msg = "Found no offline session to update."
                self.logger.debug(msg)
            except Exception as e:
                msg = "Unable to update offline session: %s" % e
                self.logger.warning(msg)

            # Set offline login token.
            self.login_token = self.offline_login_token.rel_path

            agent_conn = self.get_agent_connection()
            # Set login token to otpme-agent.
            try:
                agent_conn.set_login_token(self.offline_login_token.rel_path,
                                                self.offline_login_token.pass_type)
            except Exception as e:
                self.logger.warning("Unable to set login token to otpme-agent: "
                                    "%s" % e)

            # Add RSP from offline session to otpme-agent.
            for realm in self.offline_sessions:
                for site in self.offline_sessions[realm]:
                    session = self.offline_sessions[realm][site]
                    try:
                        agent_conn.add_rsp(realm=realm, site=site,
                                            rsp=session['rsp'],
                                            rsp_signature=session['rsp_signature'],
                                            session_key=session['session_key'],
                                            login_time=session['login_time'],
                                            timeout=session['session_timeout'],
                                            unused_timeout=session['session_unused_timeout'],
                                            offline=session['offline_allowed'])
                    except Exception as e:
                        self.logger.warning("Unable to add RSP to otpme-agent: "
                                            "%s" % e)
            if not self.offline_sessions:
                self.logger.debug("No offline session found. Relogin required "
                                "when servers are available again...")

            # Add ACL for the login user to allow access to otpme-agent login
            # session.
            agent_conn.add_acl(username=self.username, acl="all")

            auth_message = (_("Offline login succeeded with token: %s")
                            % self.offline_login_token.rel_path)
        else:
            auth_message = (_("Offline authentication succeeded with token: %s")
                            % self.offline_login_token.rel_path)

        return auth_message

        msg = (_("WARNING: You may have hit a BUG of offline_auth() in '%s'. "
                "Authentication failed.") % __name__)
        self.logger.critical(msg)
        raise OTPmeException(msg)

    def online_auth(self, login=False):
        """ Try to login/authenticate user against OTPme server. """
        from otpme.lib.classes.login_handler import LoginHandler
        login_handler = LoginHandler()

        # Mark session as online.
        self.offline_login = False

        # Activate autoconfirm of otpme-pinentry to autoconfirm key usage while
        # doing login.
        self.activate_gpg_agent_autoconfirm()

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

        # Send auth/login request.
        try:
            login_handler.login(username=self.username,
                                password=self.password,
                                password_method=self.get_password,
                                use_ssh_agent=self.use_ssh_agent,
                                ssh_agent_method=self.start_ssh_agent,
                                use_smartcard=self.use_smartcard,
                                endpoint=True, change_user=True,
                                auth_only=auth_only,
                                unlock=unlock,
                                sync_token_data=True,
                                need_ssh_key_pass=True,
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
                self.auth_message = (_("Error while sending login request: "
                                    "%s") % e)
            else:
                self.auth_message = (_("Error while authenticating with "
                                    "server: %s") % e)
            self.logger.warning(self.auth_message, exc_info=True)
            return

        # Get login reply.
        login_reply = login_handler.login_reply

        # Get login session ID.
        self.login_session_id = login_reply['login_session_id']

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
        # Make sure we create a home dir if configured.
        if self.create_home_directory:
            home_exp = "~%s" % self.username
            home_dir = os.path.expanduser(home_exp)
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
            msg = ("Problem initializing OTPme: %s" % e)
            self.logger.critical(msg)
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
            self.logger.warning("User does not exist: %s" % self.username)
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
            self.logger.debug("Got DISPLAY from PAM: %s" % self.display)
            #os.environ['DISPLAY'] = self.display
            self.pamh.env['DISPLAY'] = self.display
            self.login_interface = "gui"

        self.logger.debug("Got PAM user: %s" % self.username)

        # Get offline token handler.
        self.offline_token = OfflineToken()

        # Get connection to hostd.
        try:
            self.hostd_conn = connections.get("hostd")
        except Exception as e:
            self.cleanup()
            self.logger.critical("Unable to get connection to hostd: %s" % e)
            return self.pamh.PAM_SYSTEM_ERR

        # Check host status.
        status, reply = self.hostd_conn.get_host_status()
        if not status:
            self.logger.warning("Got host status: %s" % reply)
            self.cleanup()
            return self.pamh.PAM_AUTH_ERR

        # Try to get users UUID from environment.
        try:
            self.user_uuid = os.environ['OTPME_USER_UUID']
        except:
            pass
        # Fallback to get UUID from hostd.
        if not self.user_uuid:
            self.user_uuid = self.hostd_conn.get_user_uuid(self.username)

        if not self.user_uuid:
            self.logger.warning("Unknown user: %s" % self.username)
            self.cleanup()
            return self.pamh.PAM_USER_UNKNOWN

        # Check if user is allowed to login.
        try:
            stuff.check_login_user(user_name=self.username,
                                    user_uuid=self.user_uuid)
        except Exception as e:
            self.logger.warning(e)
            self.cleanup()
            return self.pamh.PAM_AUTH_ERR

        # Add user infos to environment.
        #os.environ['OTPME_USER'] = self.username
        self.pamh.env['OTPME_USER'] = self.username
        #os.environ['OTPME_USER_UUID'] = self.user_uuid
        self.pamh.env['OTPME_USER_UUID'] = self.user_uuid

        # Try to get password/OTP from a previous stacked module.
        if self.use_first_pass:
            self.password = self.pamh.authtok
            if self.password is None:
                self.logger.warning("No password received and 'use_first_pass' "
                                    "set. Authentication failed.")
                self.cleanup()
                return self.pamh.PAM_AUTH_ERR
        elif self.try_first_pass:
            self.password = self.pamh.authtok
            if self.password is None:
                self.logger.debug("No password received and 'try_first_pass' "
                                "set. Will ask user for password.")
        if self.password:
            self.logger.debug("Using password from previous PAM module.")

        self.logger.debug("Configuring logger...")
        log_banner = "%s:%s" % (config.log_name, self.username)
        self.logger = config.setup_logger(banner=log_banner,
                                        existing_logger=config.logger)

        # Set user we want to handle offline tokens for. This also creates the
        # logins dir.
        try:
            self.offline_token.set_user(user=self.username,
                                        uuid=self.user_uuid)
        except Exception as e:
            msg = (_("Error initializing offline tokens: %s") % e)
            raise OTPmeException(msg)

        # Remove outdated login session directories.
        try:
            self.offline_token.lock()
            self.offline_token.remove_outdated_session_dirs()
        except Exception as e:
            msg = "Error removing outdated session directories: %s" % e
            self.logger.critical(msg)
        finally:
            self.offline_token.unlock()

        # Create users environment dir.
        if not os.path.exists(self.env_dir):
            filetools.create_dir(path=self.env_dir,
                                user=self.username,
                                mode=0o700)

        # Make sure otpme-agent is running as login user.
        try:
            stuff.start_otpme_agent(user=self.username, wait_for_socket=False)
        except Exception as e:
            self.logger.critical("Unable to start otpme-agent: %s" % e)
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
        if self.login_status != False:
            msg = ("User is already logged in. This is most "
                    "likely a screen unlock request.")
            self.logger.info(msg)
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
                    self.auth_message = (_("User authentication failed: %s")
                                        % self.auth_message)
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
                        self.logger.warning(self.auth_message)
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
                        self.auth_message = (_("User offline authentication "
                                                "successful."))
                    elif self.auth_failed:
                        self.failed_message = (_("User offline authentication "
                                                "failed: %s")
                                                % self.auth_message)
                        self.auth_message = ""
                    else:
                        self.failed_message = (_("Error trying offline "
                                                "authentication: %s")
                                                % self.auth_message)
                        self.auth_message = ""

        else:
            # Try to auth/login user via OTPme servers.
            self.online_auth(login=self.realm_login)

            if not self.auth_status:
                if not self.auth_failed and self.offline_token.status():
                    # If realm login failed for any other reason than
                    # "AuthFailed" try offline authentication.
                    self.offline = True
                    # Print auth failure message from online login attempt.
                    if self.auth_message:
                        self.logger.warning(self.auth_message)
                    # Try logging in via offline tokens.
                    try:
                        self.auth_message = self.offline_auth(login=True)
                        self.auth_status = True
                    except AuthFailed as e:
                        self.auth_failed = True
                        self.auth_message = (_("Offline login failed: %s") % e)
                    except Exception as e:
                        self.auth_message = (_("Error trying offline login: %s")
                                                % e)

        # Set PAM return value depending on login/auth status.
        if self.auth_status:
            # Show login greeting via PAM message if configured.
            if self.offline:
                if self.offline_greeting:
                    self.login_message = (_("You are logged in offline!"))
            else:
                if self.online_greeting:
                    self.login_message = (_("You are logged in to REALM '%s'.")
                                            % config.realm)
            # Log success message.
            if self.auth_message:
                self.logger.info(self.auth_message)
            # Set PAM stuff.
            self.retval = self.pamh.PAM_SUCCESS
            # Add OTPme login session to users environment. We got the session
            # ID from login_handler.login() or offline_auth().
            if self.login_session_id:
                self.login_session_dir = "%s/%s" % (self.env_dir,
                                                self.login_session_id)
                if not os.path.exists(self.login_session_dir):
                    filetools.create_dir(path=self.login_session_dir,
                                        user=self.username,
                                        mode=0o700)
                #os.environ['OTPME_LOGIN_SESSION_DIR'] = self.login_session_dir
                #os.environ['OTPME_LOGIN_SESSION'] = self.login_session_id
                self.pamh.env['OTPME_LOGIN_SESSION_DIR'] = self.login_session_dir
                self.pamh.env['OTPME_LOGIN_SESSION'] = self.login_session_id

            # Remember if this was a offline login.
            self.pamh.env['OTPME_OFFLINE_LOGIN'] = str(self.offline_login)
            #os.environ['OTPME_OFFLINE_LOGIN'] = str(self.offline_login)
            if self.login_token:
                self.pamh.env['OTPME_LOGIN_TOKEN'] = self.login_token
                #os.environ['OTPME_LOGIN_TOKEN'] = self.login_token
            else:
                msg = "Uuuh, no login token set. This should not happen."
                self.logger.warning(msg)

            # Make sure SSH/GPG agent is running.
            if self.ensure_ssh_agent:
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
                    #        self.logger.warning("Unable to run SSH agent script: %s" % e)
                    if not self.ssh_agent_status():
                        self.start_ssh_agent()
                except Exception as e:
                    self.logger.warning("Cannot start SSH agent: %s" % e)

            # Run login script
            if self.login_status is False:
                try:
                    self.run_login_script()
                except Exception as e:
                    msg = ("Error running login script: %s" % e)
                    self.logger.warning(msg)
        else:
            # Read pinentry message file.
            if os.path.exists(self.pinentry_message_file):
                try:
                    fd = open(self.pinentry_message_file, "r")
                    self.failed_message = fd.read()
                    #self.failed_message = self.failed_message.replace("\n", "")
                    fd.close()
                except Exception as e:
                    msg = ("Error reading pinentry message file: %s: %s"
                        % (self.pinentry_message_file, e))
                    self.logger.error(msg)
                # Remove message file, even if reading failed.
                try:
                    os.remove(self.pinentry_message_file)
                except Exception as e:
                    msg = ("Error removing pinentry message file: %s: %s"
                        % (self.pinentry_message_file, e))
                    self.logger.error(msg)

            # Show errors via PAM message if configured.
            if self.show_errors:
                if self.failed_message:
                    self.login_message = self.failed_message
                else:
                    self.login_message = self.auth_message

            # Log failed message.
            msg = "%s: %s" % (self.auth_message, self.failed_message)
            self.logger.warning(msg)
            # Set PAM stuff.
            self.retval = self.pamh.PAM_AUTH_ERR

            # If this was a failed login request (no screen unlock) stop users
            # ssh-agent.
            if self.login_status is False:
                self.logger.debug("Stopping SSH agent after failed login.")
                try:
                    self.stop_ssh_agent()
                except Exception as e:
                    msg = ("Unable to run SSH agent script: %s" % e)
                    self.logger.warning(msg)

        # If this is a realm login and cache_login_tokens is enabled
        # otpme-pinentry auto confirmation is deactivated by OTPmeClient()
        # after offline tokens have been saved (which runs as child process
        # and thus could lead to a race). In any other case we have to
        # make sure it is deactivated here. Same goes for triggering
        # "sync_token_data" hostd command.
        if self.login_status != False \
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

        # Close connetions etc.
        self.cleanup()

        self.logger.debug("Returning PAM status: %s" % repr(self.retval))

        # Return PAM status.
        return self.retval

        msg = (_("WARNING: You may have hit a BUG of authenticate() in '%s'. "
                "Authentication failed.") % __name__)
        self.logger.critical(msg)
        return self.pamh.PAM_SYSTEM_ERR
