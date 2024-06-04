# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import re
from otpme.lib import config
from otpme.lib.protocols import status_codes
from otpme.lib.register import register_module
from otpme.lib.socket.connect import ConnectSocket
from otpme.lib.protocols.request import build_request
from otpme.lib.protocols.response import decode_response
from otpme.lib.socket.handler import SocketProtoHandler

from otpme.lib.exceptions import *

class AgentConn(object):
    """ Class to handle connections to OTPme daemons. """
    def __init__(self, user=None, autoconnect=False, login_session_id=None,
        connect_timeout=3, timeout=120):
        # Get agent socket.
        self.socket_uri = config.get_agent_socket(user)
        self.connection = ConnectSocket(socket_uri=self.socket_uri,
                                        socket_handler=SocketProtoHandler,
                                        use_ssl=False)

        # Try to get our login session ID from env.
        if login_session_id is None:
            try:
                self.login_session_id = os.environ['OTPME_LOGIN_SESSION']
            except:
                self.login_session_id = None
        else:
            self.login_session_id = login_session_id

        self.connected = False
        self.connect_timeout = connect_timeout
        self.timeout = timeout
        self.logger = config.logger

        if autoconnect:
            try:
                self.connect()
            except Exception as e:
                msg = "Agent autoconnect failed: %s" % e
                self.logger.warning(msg)
                self.close()
                raise

    def __str__(self):
        if config.use_api:
            name = "API"
        else:
            name = self.socket_uri
        return name

    def get_status(self):
        """ Get login status from otpme-agent. """
        status, status_code, reply = self.send("status")
        if status_code == status_codes.OK:
            if " (offline) " in reply:
                return None
            else:
                return True
        return False

    def get_realm(self):
        """ Get session realm from otpme-agent. """
        username = None
        status, status_code, reply = self.send("get_realm")
        if status_code == status_codes.OK:
            username = reply
        return username

    def get_site(self):
        """ Get session site from otpme-agent. """
        username = None
        status, status_code, reply = self.send("get_site")
        if status_code == status_codes.OK:
            username = reply
        return username

    def get_user(self):
        """ Get session user from otpme-agent. """
        username = None
        status, status_code, reply = self.send("get_user")
        if status_code == status_codes.OK:
            username = reply
        return username

    def get_login_token(self):
        """ Get login token from otpme-agent. """
        status, status_code, reply = self.send("status")
        if status_code != status_codes.OK:
            raise Exception(reply)
        login_token = re.sub('.* token: ([^ ]*) .*', r'\1', reply)
        return login_token

    def get_login_pass_type(self):
        """ Get login pass type from otpme-agent. """
        status, status_code, reply = self.send("status")
        if status_code != status_codes.OK:
            raise Exception(reply)
        login_pass_type = re.sub('.* type: ([^ ]*)$', r'\1', reply)
        return login_pass_type

    def get_offline(self):
        """ Get session offline info."""
        status, status_code, reply = self.send("get_offline")
        if status_code == status_codes.OK:
            return True
        return False

    #def get_rsp(self):
    #    """ get RSP from otpme-agent. """
    #    username = False
    #    rsp = False
    #    status, status_code, reply = self.send("get_rsp")
    #    if status_code == status_codes.OK:
    #        username = re.sub('^username: ([^:]*) rsp: (.*)$', r'\1', reply)
    #        rsp = re.sub('^username: ([^:]*) rsp: (.*)$', r'\2', reply)
    #        return username, rsp
    #    elif status_code == "403":
    #        raise Exception(reply)
    #    else:
    #        return False, False

    def get_sotp(self):
        """ Get SOTP from otpme-agent. """
        username = None
        otp = None
        status, status_code, reply = self.send("get_sotp")
        if status_code == status_codes.OK:
            username = re.sub('^username: ([^:]*) sotp: (.*)$', r'\1',
                            reply)
            otp = re.sub('^username: ([^:]*) sotp: (.*)$', r'\2',
                        reply)
        return username, otp

    def get_srp(self):
        """ Get SRP from otpme-agent. """
        username = None
        srp = None
        status, status_code, reply = self.send("get_srp")
        if status_code == status_codes.OK:
            username = re.sub('^username: ([^:]*) srp: (.*)$', r'\1',
                            reply)
            srp = re.sub('^username: ([^:]*) srp: (.*)$', r'\2',
                        reply)
        return username, srp

    def get_slp(self):
        """ Get SLP from otpme-agent. """
        username = None
        session_logout_pass = None
        status, status_code, reply = self.send("get_slp")
        if status_code != status_codes.OK:
            raise Exception(_("Error getting SLP from agent: %s")
                            % reply)
        username = re.sub('^username: ([^:]*) slp: (.*)$', r'\1',
                        reply)
        session_logout_pass = re.sub('^username: ([^:]*) slp: (.*)$', r'\2',
                                    reply)
        return username, session_logout_pass

    def get_sessions(self):
        """ Get otpme-agent sessions."""
        status, status_code, reply = self.send("get_sessions")
        if status_code != status_codes.OK:
            raise Exception(_("Error getting session list from agent: %s")
                            % reply)
        return reply

    def add_session(self, username, session_id=None):
        """ Add session to otpme-agent. """
        command_args = {
                        'username'      : username,
                        'session_id'    : session_id,
                    }
        status, status_code, reply = self.send("add_session", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Error adding login session to agent: %s")
                            % reply)
        # Session ID includes ":"
        session_id = ":".join(reply.split(":")[1:]).replace(" ", "")
        return session_id

    def del_session(self):
        """ Del session from otpme-agent. """
        status, status_code, reply = self.send("del_session")
        if status_code != status_codes.OK:
            msg = (_("Error removing login session from agent: %s") % reply)
            raise OTPmeException(msg)
        return reply

    def add_rsp(self, realm, site, rsp, slp, login_time, timeout, unused_timeout,
        rsp_signature=None, session_key=None, offline=False):
        """ Add RSP to otpme-agent. """
        command_args = {
                        'realm'         : realm,
                        'site'          : site,
                        'rsp'           : rsp,
                        'rsp_signature' : rsp_signature,
                        'slp'           : slp,
                        'session_key'   : session_key,
                        'offline'       : offline,
                        'login_time'    : login_time,
                        'timeout'       : timeout,
                        'unused_timeout': unused_timeout,
                    }
        status, status_code, reply = self.send("add_rsp", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Failed to set RSP: %s") % reply)
        self.logger.debug("Added RSP to otpme-agent: %s/%s" % (realm, site))

    def reneg_session(self, realm=None, site=None):
        """ Send session reneg command to otpme-agent. """
        command_args = {
                        'realm'         : realm,
                        'site'          : site,
                    }
        status, status_code, reply = self.send("reneg", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Error: %s") % reply)
        return reply

    def set_login_token(self, login_token, login_pass_type):
        """ Set login token to otpme-agent. """
        command_args = {
                        'login_token'       : login_token,
                        'login_pass_type'   : login_pass_type,
                    }
        status, status_code, reply = self.send("set_login_token", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Failed to set login token: %s") % reply)

    def add_ssh_key_pass(self, ssh_agent_pid, ssh_key_pass):
        """ Add RSP to otpme-agent. """
        command_args = {
                        'ssh_agent_pid' : ssh_agent_pid,
                        'ssh_key_pass'  : ssh_key_pass,
                    }
        status, status_code, reply = self.send("add_ssh_key_pass", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Failed to add SSH key passphrase to agent: %s")
                            % reply)

    def check_ssh_key_pass(self):
        """ Check if otpme-agent does have a SSH key pass. """
        status, status_code, reply = self.send("check_ssh_key_pass")
        if status_code == status_codes.OK:
            return True
        return False

    def get_ssh_key_pass(self):
        """ Get SSH key passphrase from otpme-agent. """
        username = None
        ssh_key_pass = None
        status, status_code, reply = self.send("get_ssh_key_pass")
        if status_code == status_codes.OK:
            username = re.sub('^username: ([^:]*) ssh_key_pass: (.*)$', r'\1',
                            reply)
            ssh_key_pass = re.sub('^username: ([^:]*) ssh_key_pass: (.*)$', r'\2',
                                reply)
        return username, ssh_key_pass

    def del_ssh_key_pass(self):
        """ Del SSH key passphrase from otpme-agent. """
        status, status_code, reply = self.send("del_ssh_key_pass")
        if status_code != status_codes.OK:
            msg = (_("Failed to remove SSH key passphrase from agent: %s")
                    % reply)
            raise Exception(msg)

    def add_acl(self, username, acl):
        """ Add ACL to otpme-agent. """
        command_args = {
                        'username'  : username,
                        'acl'       : acl,
                    }
        status, status_code, reply = self.send("add_acl", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Failed to add ACL to agent: %s")
                            % reply)

    def del_acl(self, username, acl):
        """ Del ACL from otpme-agent. """
        command_args = {
                        'username'  : username,
                        'acl'       : acl,
                    }
        status, status_code, reply = self.send("del_acl", **command_args)
        if status_code != status_codes.OK:
            raise Exception(_("Failed to remove ACL from agent: %s")
                            % reply)

    def connect(self, connect_timeout=None, timeout=None):
        """ Initiate connection with agent socket. """
        register_module("otpme.lib.protocols.client.agent1")
        if self.connected:
            return
        if connect_timeout is None:
            connect_timeout = self.connect_timeout

        if timeout is None:
            timeout = self.timeout

        try:
            self.connection.connect(connect_timeout=connect_timeout,
                                    timeout=timeout)
        except Exception as e:
            msg = (_("Agent connection failed: %s") % e)
            if not config.file_logging and not config.debug_enabled:
                msg = (_("%s Try '-d' for debug output.") % msg)
            raise Exception(msg)

        # Build helo command.
        helo_command = "helo"
        try:
            supported_protocols = config.get_otpme_protocols("agent")
        except:
            supported_protocols = None
        if not supported_protocols:
            msg = "Unable to load agent protocols."
            raise OTPmeException(msg)
        helo_args = {'supported_protocols' : supported_protocols}
        # Send helo command to agent.
        status, status_code, msg = self.send(helo_command, **helo_args)

        if status_code != status_codes.OK:
            msg = (_("Error sending helo command to otpme-agent: %s") % msg)
            raise OTPmeException(msg)

        if self.login_session_id:
            command_args = {
                            'login_session_id' : self.login_session_id,
                        }
            status, status_code, msg = self.send("auth", **command_args)
            if status_code != status_codes.OK:
                if status_code == status_codes.ERR and msg == "Unknown session.":
                    raise UnknownLoginSession(str(msg))
                else:
                    msg = (_("Authentication with otpme-agent failed: %s") % msg)
                    raise OTPmeException(msg)
        self.connected = True

    def send(self, command, **command_args):
        """ Send command requests to agent and handle response. """
        response = ""

        if 'use_dns' not in command_args:
            command_args['use_dns'] = config.use_dns

        try:
            request = build_request(command=command,
                                    command_args=command_args)
        except Exception as e:
            msg = (_("Faild to build request: %s") % e)
            raise OTPmeException(msg)

        # Send request.
        try:
            self.connection.send(request)
        except Exception as e:
            config.raise_exception()
            raise Exception(_("Error while sending: %s") % e)

        # Receive response.
        try:
            response = self.connection.recv()
        except Exception as e:
            config.raise_exception()
            raise Exception(_("Error while receiving: %s") % e)

        status_code, response = decode_response(response)

        # Handle status code.
        if status_code == status_codes.OK:
            status = True
        else:
            status = False

        return status, status_code, response

    def close(self):
        """ Close connection. """
        self.connection.close()
        self.connected = False
