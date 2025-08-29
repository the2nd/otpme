# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import net
from otpme.lib import config
from otpme.lib import connections

from otpme.lib.exceptions import *

class LoginHandler(object):
    """ Class to login, logout and auth users. """
    def __init__(self):
        self.login_reply = {}
        self.logger = config.logger

    def get_agent_status(self):
        """ Check if agent is running. """
        from otpme.lib.classes.otpme_agent import OTPmeAgent
        otpme_agent = OTPmeAgent()
        agent_status, pid = otpme_agent.status(quiet=True)
        return agent_status

    def get_agent_connection(self):
        """ Get connection to otpme-agent. """
        # Try to get agent connection.
        try:
            agent_conn = connections.get("agent")
        except UnknownLoginSession as e:
            msg = (_("Unknown session: %s") % agent_conn.login_session_id)
            raise UnknownLoginSession(msg)
        except Exception as e:
            raise OTPmeException(_("Unable to get agent connection: %s") % e)
        return agent_conn

    def login(self, realm=None, site=None, username=None, password=None,
        send_password=True, login_interface="tty", use_smartcard=False,
        start_ssh_agent=False, use_ssh_agent="auto", password_method=None,
        ssh_agent_method=None, need_ssh_key_pass=False, change_user=False,
        endpoint=True, unlock=False, interactive=False, add_agent_session=None,
        add_login_session=True, check_login_status=True, cache_login_tokens=False,
        sync_token_data=False, auth_only=False, start_otpme_agent=True, jwt_auth=False,
        jwt_method=None, message_method=None, error_message_method=None, connect_timeout=3,
        timeout=30, node=None, offline_key_derivation_func=None, offline_token=None,
        mount_shares=False, offline_key_func_opts={}, check_offline_pass_strength=False,
        offline_iterations_by_score={}, offline_session_key=None,
        login_session_id=None, add_agent_acl=False, cleanup_method=None,
        socket_uri=None, login_use_dns=False, use_dns=False):
        """ Send realm login request. """
        login = True
        exception = None

        # Indicates that we should not send an login request, just authenticate
        # the user.
        if auth_only:
            login = False
            mount_shares = False
            add_login_session = False
            # If we have no login session ID instruct OTPmeClient() to add a
            # new login session to otpme-agent.
            if not login_session_id:
                add_agent_session = True

        if not username:
            if config.login_user:
                username = config.login_user
            else:
                username = config.system_user()

        if change_user:
            otpme_agent_user = username
        else:
            otpme_agent_user = None

        # Get login point via DNS. This is required e.g. if a notebook from one
        # site wants to login on another site. This may happen for trusted sites.
        if login_use_dns:
            # Get hosts DNS domain. This is typically set via DHCP.
            domain = net.get_host_domainname()
            # Try to get realm/site to connect to via DNS.
            x = net.get_otpme_site(domain)
            realm = x['realm']
            site = x['site']

        if node:
            port = config.default_ports['authd']
            socket_uri = "tcp://%s:%s" % (node, port)

        # Try to get connection to authd.
        try:
            auth_conn = connections.get(daemon="authd",
                                    timeout=timeout,
                                    connect_timeout=connect_timeout,
                                    use_dns=use_dns,
                                    use_agent=False,
                                    use_ssh_agent=use_ssh_agent,
                                    start_ssh_agent=start_ssh_agent,
                                    ssh_agent_method=ssh_agent_method,
                                    start_otpme_agent=start_otpme_agent,
                                    need_ssh_key_pass=need_ssh_key_pass,
                                    send_password=send_password,
                                    password_method=password_method,
                                    handle_response=True,
                                    login_interface=login_interface,
                                    jwt_method=jwt_method,
                                    use_smartcard=use_smartcard,
                                    cache_login_tokens=cache_login_tokens,
                                    sync_token_data=sync_token_data,
                                    username=username, password=password,
                                    login=login, cleanup_method=cleanup_method,
                                    error_message_method=error_message_method,
                                    message_method=message_method,
                                    otpme_agent_user=otpme_agent_user,
                                    request_jwt=True, verify_jwt=True,
                                    autoconnect=True, auto_auth=False,
                                    jwt_auth=jwt_auth,
                                    add_agent_acl=add_agent_acl, unlock=unlock,
                                    add_agent_session=add_agent_session,
                                    add_login_session=add_login_session,
                                    login_session_id=login_session_id,
                                    check_login_status=check_login_status,
                                    interactive=interactive, endpoint=endpoint,
                                    mount_shares=mount_shares,
                                    offline_token=offline_token,
                                    offline_key_derivation_func=offline_key_derivation_func,
                                    offline_key_func_opts=offline_key_func_opts,
                                    check_offline_pass_strength=check_offline_pass_strength,
                                    offline_iterations_by_score=offline_iterations_by_score,
                                    offline_session_key=offline_session_key,
                                    socket_uri=socket_uri, realm=realm, site=site)
        except ConnectionError as e:
            msg = "Login connection failed: %s" % e
            self.logger.warning(msg)
            raise
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to connect to auth daemon: %s") % e)
            raise OTPmeException(msg)

        # Send auth/login request.
        login_message = None
        if auth_only:
            login_command = "auth_verify"
        else:
            login_command = None
        try:
            login_message = auth_conn.authenticate(command=login_command)
        except HostDisabled as e:
            msg = (_("Realm login failed: %s") % e)
            exception = HostDisabled(msg)
        except AuthFailed as e:
            msg = (_("Realm login failed: %s") % e)
            exception = AuthFailed(msg)
        except AlreadyLoggedIn as e:
            msg = str(e).replace("'", "")
            exception = AlreadyLoggedIn(msg)
        except Exception as e:
            msg = str(e)
            exception = Exception(msg)
            config.raise_exception()
        finally:
            auth_conn.close()

        # Build login reply.
        self.login_reply = {
                'login_message'             : login_message,
                'login_session_id'          : auth_conn.login_session_id,
                'ssh_agent_script'          : auth_conn.ssh_agent_script,
                'ssh_agent_script_uuid'     : auth_conn.ssh_agent_script_uuid,
                'ssh_agent_script_path'     : auth_conn.ssh_agent_script_path,
                'ssh_agent_script_opts'     : auth_conn.ssh_agent_script_opts,
                'ssh_agent_script_signs'    : auth_conn.ssh_agent_script_signs,
                'auth_reply'                : auth_conn.auth_reply,
                'rsp'                       : auth_conn.rsp,
        }

        # Raise exception if there was one.
        if exception:
            raise exception

        return login_message

    def logout(self, username=None):
        """ Send realm logout request. """
        logout_message = ""

        # Check if OTPme agent is running.
        agent_status = self.get_agent_status()
        if not agent_status:
            msg = "You are not logged in."
            raise NotLoggedIn(msg)

        # Try to get agent connection.
        agent_conn = None
        try:
            try:
                agent_conn = self.get_agent_connection()
            except UnknownLoginSession as e:
                msg = "You are not logged in."
                raise NotLoggedIn(msg)
            except Exception as e:
                raise Exception(str(e))

            # Get login status from otpme-agent.
            if not agent_conn.get_status():
                raise NotLoggedIn("You are not logged in.")

            # Get username of logged in user.
            agent_username = agent_conn.get_user()

            # Check username.
            if not username:
                username = agent_username
            if username != agent_username:
                msg = (_("You are not logged in as user '%s'.") % username)
                raise NotLoggedIn(msg)
            # Umount shares.
            try:
                agent_conn.umount_shares()
            except Exception as e:
                raise Exception(_("Error unmounting shares: %s") % e)
            # Logout user via agent command.
            try:
                logout_message = agent_conn.del_session()
            except Exception as e:
                raise Exception(_("Error logging out: %s") % e)
        finally:
            if agent_conn:
                agent_conn.close()

        return logout_message

    def whoami(self, verify_server_session=True):
        """ Check login status for user got from otpme-agent """
        msg = "You are not logged in."

        # Check if OTPme agent is running.
        agent_status = self.get_agent_status()
        if not agent_status:
            raise NotLoggedIn(msg)

        # Try to get agent connection.
        try:
            agent_conn = self.get_agent_connection()
        except UnknownLoginSession as e:
            raise NotLoggedIn(msg)
        except Exception as e:
            msg = str(e)
            raise Exception(msg)

        # Get login status from otpme-agent.
        login_status = agent_conn.get_status()

        # Get username.
        agent_username = agent_conn.get_user()

        if not login_status:
            if agent_username:
                msg = (_("%s (no login session)") % agent_username)
            raise NotLoggedIn(msg)

        # Get login session realm/site.
        login_realm = agent_conn.get_realm()
        login_site = agent_conn.get_site()

        if not verify_server_session:
            return agent_username

        # Try to get connection to mgmtd.
        mgmt_conn = None
        try:
            mgmt_conn = connections.get(daemon="mgmtd",
                                        realm=login_realm,
                                        site=login_site,
                                        use_agent=True,
                                        auto_auth=False,
                                        username=agent_username,
                                        autoconnect=True)
        except AuthFailed as e:
            msg = (_("Authentication failed: %s") % e)
            status_message = (_("%s (online: %s)") % (agent_username, msg))
        except Exception as e:
            status_message = (_("%s (offline)") % agent_username)

        if mgmt_conn:
            command_args = {}
            try:
                status, \
                status_code, \
                status_message, \
                binary_data = mgmt_conn.send("status", command_args)
                status_message = (_("%s (online)") % agent_username)
            except AuthFailed as e:
                msg = (_("Authentication failed: %s") % e)
                status_message = (_("%s (online: %s)") % (agent_username, msg))
            except Exception as e:
                msg = str(e)
                status_message = (_("%s (online: %s)") % (agent_username, msg))

        return status_message
