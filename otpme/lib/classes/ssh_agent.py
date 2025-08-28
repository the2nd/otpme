# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
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
            except:
                raise Exception("Please set OTPME_LOGIN_SESSION variable.")
        self.logger = config.logger
        self.username = username
        self.login_session_id = login_session_id
        self.ssh_agent_script = script
        self.ssh_agent_script_uuid = script_uuid
        self.ssh_agent_script_path = script_path
        self.ssh_agent_script_opts = script_opts
        self.ssh_agent_script_signs = script_signs
        self.env_dir = "%s/%s" % (config.env_dir, self.username)
        self.gpg_agent_info = None
        self.ssh_auth_sock = None
        self.ssh_agent_pid = None
        self.ssh_agent_name = None

    def run_ssh_agent_script(self, command, verify_signs="auto", additional_opts=[]):
        """ Run users SSH agent script. """
        if not self.ssh_agent_script:
            raise OTPmeException("Got no SSH agent script.")

        from otpme.lib import script as _script
        msg = ("Running SSH agent script command: %s" % command)
        self.logger.debug(msg)

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
            msg = (_("Error running SSH agent script: %s") % e)
            raise Exception(msg)

        # Make sure script output is string.
        if isinstance(agent_stdout, bytes):
            agent_stdout = agent_stdout.decode()
        if isinstance(agent_stderr, bytes):
            agent_stderr = agent_stderr.decode()

        # Try to get agent variables from agent script.
        ssh_agent_name, \
        ssh_agent_pid, \
        ssh_auth_sock, \
        gpg_agent_info = stuff.get_agent_vars(agent_stdout)

        # Set env variables if we got them from the agent script.
        if gpg_agent_info:
            self.logger.debug("GPG_AGENT_INFO: %s" % gpg_agent_info)
            os.environ['GPG_AGENT_INFO'] = gpg_agent_info
            self.gpg_agent_info = gpg_agent_info

        if ssh_auth_sock:
            self.logger.debug("SSH_AUTH_SOCK: %s" % ssh_auth_sock)
            os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock
            self.ssh_auth_sock = ssh_auth_sock

        if ssh_agent_pid:
            self.logger.debug("SSH_AGENT_PID: %s" % ssh_agent_pid)
            os.environ['SSH_AGENT_PID'] = ssh_agent_pid
            self.ssh_agent_pid = ssh_agent_pid

        if ssh_agent_name:
            self.logger.debug("SSH_AGENT_NAME: %s" % ssh_agent_name)
            os.environ['SSH_AGENT_NAME'] = ssh_agent_name
            self.ssh_agent_name = ssh_agent_name

        if agent_returncode == 0:
            return True

        return False

    def start(self, verify_signs=None, additional_opts=[]):
        """ Make sure SSH/GPG agent is running and needed variables are set """
        self.logger.debug("Starting user SSH agent script...")
        # Start SSH agent script.
        self.run_ssh_agent_script(command="start",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)
        return self.ssh_auth_sock, \
                self.ssh_agent_pid, \
                self.ssh_agent_name, \
                self.gpg_agent_info


    def stop(self, verify_signs=None, additional_opts=[]):
        """ Stop SSH/GPG agent """
        self.run_ssh_agent_script(command="stop",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)


    def unlock(self, verify_signs=None, additional_opts=[]):
        """ Send 'unlock' command to agent script """
        self.run_ssh_agent_script(command="unlock",
                                verify_signs=verify_signs,
                                additional_opts=additional_opts)
        return self.ssh_auth_sock, \
                self.ssh_agent_pid, \
                self.ssh_agent_name, \
                self.gpg_agent_info


    def status(self, verify_signs=None, additional_opts=[]):
        """ Check SSH/GPG agent status """
        return self.run_ssh_agent_script(command="status",
                                    verify_signs=verify_signs,
                                    additional_opts=additional_opts)
