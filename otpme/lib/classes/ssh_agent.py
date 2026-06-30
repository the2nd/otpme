# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.classes import signing

from otpme.lib.exceptions import *

class SSHAgent(object):
    """ Class to start/stop ssh-agent via users SSH agent script. """
    def __init__(self, username, script, script_path, script_uuid,
        script_opts=None, script_signs=None, login_session_id=None):
        """ Init """
        if not login_session_id:
            try:
                login_session_id = os.environ['OTPME_LOGIN_SESSION']
            except Exception:
                raise Exception("Please set OTPME_LOGIN_SESSION variable.") from None
        self.logger = config.logger
        self.username = username
        self.login_session_id = login_session_id
        self.ssh_agent_script = script
        self.ssh_agent_script_uuid = script_uuid
        self.ssh_agent_script_path = script_path
        self.ssh_agent_script_opts = script_opts
        self.ssh_agent_script_signs = script_signs
        self.env_dir = f"{config.env_dir}/{self.username}"
        self.gpg_agent_info = None
        self.ssh_auth_sock = None
        self.ssh_agent_pid = None
        self.ssh_agent_name = None

    def run_ssh_agent_script(self, command, verify_signs="auto", additional_opts=None):
        """ Run users SSH agent script. """
        if additional_opts is None:
            additional_opts = []
        if not self.ssh_agent_script:
            raise OTPmeException("Got no SSH agent script.")

        from otpme.lib import script as _script
        log_msg = _("Running SSH agent script command: {command}", log=True)[1]
        log_msg = log_msg.format(command=command)
        self.logger.debug(log_msg)

        # Get signers.
        signers = None
        if verify_signs:
            signers = signing.get_signers(signer_type="agent_script",
                                            username=self.username)

        if verify_signs is True and not signers:
            msg = ("SSH agent script signature verification "
                    "enabled but no agent script signers configured.")
            raise OTPmeException(msg)

        # In "auto" mode we only verify script signatures if we got some and
        # agent script signers are configured.
        if verify_signs == "auto":
            if not signers:
                verify_signs = False

        if verify_signs and not self.ssh_agent_script_signs:
            msg = ("Got no SSH script signatures to verify")
            raise OTPmeException(msg)

        # Add socket paths etc. to script environment.
        script_env = os.environ.copy()
        script_env['OTPME_LOGIN_SESSION'] = self.login_session_id

        # Add command to script options.
        script_options = []
        if self.ssh_agent_script_opts:
            script_options += self.ssh_agent_script_opts
        if additional_opts:
            script_options += additional_opts

        script_options.append(command)

        # Run agent script.
        try:
            agent_returncode, \
            agent_stdout, \
            agent_stderr, \
            agent_pid = _script.run(script_type="agent_script",
                                    script_path=self.ssh_agent_script_path,
                                    script_uuid=self.ssh_agent_script_uuid,
                                    script=self.ssh_agent_script,
                                    options=script_options,
                                    verify_signatures=verify_signs,
                                    signatures=self.ssh_agent_script_signs,
                                    signers=signers,
                                    script_env=script_env,
                                    user=self.username,
                                    call=False,
                                    close_fds=True)
        except Exception as e:
            msg = _("Error running SSH agent script: {e}")
            msg = msg.format(e=e)
            raise Exception(msg) from e

        # Make sure script output is string.
        if isinstance(agent_stdout, bytes):
            agent_stdout = agent_stdout.decode()
        if isinstance(agent_stderr, bytes):
            agent_stderr = agent_stderr.decode()

        if agent_returncode != 0:
            agent_out = agent_stdout + agent_stderr
            msg = _("SSH agent script returned error: {agent_out}")
            msg = msg.format(agent_out=agent_out)
            raise Exception(msg)

        if command == "start":
            # Try to get agent variables from agent script.
            ssh_agent_name, \
            ssh_agent_pid, \
            ssh_auth_sock, \
            gpg_agent_info = stuff.get_agent_vars(agent_stdout)

            # Set env variables if we got them from the agent script.
            if gpg_agent_info:
                log_msg = _("GPG_AGENT_INFO: {info}", log=True)[1]
                log_msg = log_msg.format(info=gpg_agent_info)
                self.logger.debug(log_msg)
                os.environ['GPG_AGENT_INFO'] = gpg_agent_info
                self.gpg_agent_info = gpg_agent_info

            if ssh_auth_sock:
                log_msg = _("SSH_AUTH_SOCK: {sock}", log=True)[1]
                log_msg = log_msg.format(sock=ssh_auth_sock)
                self.logger.debug(log_msg)
                os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock
                self.ssh_auth_sock = ssh_auth_sock

            if ssh_agent_pid:
                log_msg = _("SSH_AGENT_PID: {pid}", log=True)[1]
                log_msg = log_msg.format(pid=ssh_agent_pid)
                self.logger.debug(log_msg)
                os.environ['SSH_AGENT_PID'] = ssh_agent_pid
                self.ssh_agent_pid = ssh_agent_pid

            if ssh_agent_name:
                log_msg = _("SSH_AGENT_NAME: {name}", log=True)[1]
                log_msg = log_msg.format(name=ssh_agent_name)
                self.logger.debug(log_msg)
                os.environ['SSH_AGENT_NAME'] = ssh_agent_name
                self.ssh_agent_name = ssh_agent_name

        return True

    def start(self, verify_signs=None, additional_opts=None):
        """ Make sure SSH/GPG agent is running and needed variables are set """
        if additional_opts is None:
            additional_opts = []
        log_msg = _("Starting user SSH agent script...", log=True)[1]
        self.logger.debug(log_msg)
        # Start SSH agent script.
        self.run_ssh_agent_script(command="start",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)
        return self.ssh_auth_sock, \
                self.ssh_agent_pid, \
                self.ssh_agent_name, \
                self.gpg_agent_info


    def stop(self, verify_signs=None, additional_opts=None):
        """ Stop SSH/GPG agent """
        if additional_opts is None:
            additional_opts = []
        self.run_ssh_agent_script(command="stop",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)


    def add_key(self, verify_signs=None, additional_opts=None):
        """ Send 'add_key' command to agent script """
        if additional_opts is None:
            additional_opts = []
        self.run_ssh_agent_script(command="add_key",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)
        return self.ssh_auth_sock, \
                self.ssh_agent_pid, \
                self.ssh_agent_name, \
                self.gpg_agent_info


    def unlock(self, verify_signs=None, additional_opts=None):
        """ Send 'unlock' command to agent script """
        if additional_opts is None:
            additional_opts = []
        self.run_ssh_agent_script(command="unlock",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)
        return self.ssh_auth_sock, \
                self.ssh_agent_pid, \
                self.ssh_agent_name, \
                self.gpg_agent_info


    def status(self, verify_signs=None, additional_opts=None):
        """ Check SSH/GPG agent status """
        if additional_opts is None:
            additional_opts = []
        return self.run_ssh_agent_script(command="status",
                                    verify_signs=verify_signs,
                                    additional_opts=additional_opts)
