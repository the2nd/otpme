# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import connections
from otpme.lib.register import register_module

from otpme.lib.exceptions import *

class OTPmeMgmtClient(object):
    """ Class that implements OTPme management client. """
    def __init__(self, login_data={}, interactive=True, aes_pass=None):
        # Get logger.
        self.logger = config.logger
        # May hold username + OTPs/passwords to connect to realms.
        self.login_data = login_data
        # May hold a password to decrypt some AES data (e.g. users private RSA
        # key)
        self.aes_pass = aes_pass
        self.interactive = interactive

    def __getattr__(self, name):
        """ Forward method call to protocol handler. """
        try:
            attr = self.__getattribute__(name)
            return attr
        except AttributeError:
            pass
        def handler_function(*args, **kwargs):
            realm = config.connect_realm
            site = config.connect_site
            # Get daemon connection.
            daemon_conn = self.get_daemon_connection(realm=realm,
                                                    site=site)
            method = getattr(daemon_conn, name)
            # Try to run method.
            response = method(*args, **kwargs)
            return response

        return handler_function

    def get_jwt(self, challenge):
        authd_conn_kwargs = {}
        authd_conn_kwargs['use_ssl'] = False
        authd_conn_kwargs['auto_auth'] = False
        authd_conn_kwargs['local_socket'] = True
        authd_conn_kwargs['auto_preauth'] = False
        authd_conn_kwargs['handle_host_auth'] = False
        authd_conn_kwargs['handle_user_auth'] = False
        authd_conn_kwargs['encrypt_session'] = False
        socket_uri = config.authd_socket_path
        try:
            authd_conn = connections.get(daemon="authd",
                                        socket_uri=socket_uri,
                                        **authd_conn_kwargs)
        except AuthFailed as e:
            log_msg = _("Failed to get authd connection (socket): {e}'", log=True)[1]
            log_msg = log_msg.format(e=e)
            self.logger.warning(log_msg)
            raise
        except Exception as e:
            log_msg = _("Error connecting ot authd (socket): {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.error(log_msg, exc_info=True)
            raise
        command = "get_jwt"
        command_args = {}
        command_args['jwt_reason'] = "REALM_AUTH"
        command_args['jwt_challenge'] = challenge
        command_args['jwt_accessgroup'] = config.realm_access_group
        # Send command.
        try:
            status, \
            status_code, \
            response, \
            binary_data = authd_conn.send(command, command_args)
        except Exception as e:
            msg = _("Error requesting JWT: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        finally:
            authd_conn.close()
        if not status:
            msg = _("Error requesting JWT: {response}")
            msg = msg.format(response=response)
            raise OTPmeException(msg)
        return response

    def get_daemon_connection(self, realm, site):
        """ Connect to mgmtd in the given realm/site. """
        try:
            username = self.login_data[realm]['username']
        except:
            username = None
        try:
            password = self.login_data[realm]['password']
        except:
            password = None

        socket_uri = None
        conn_kwargs = {}
        conn_kwargs['realm'] = realm
        conn_kwargs['site'] = site
        conn_kwargs['username'] = username
        conn_kwargs['password'] = password
        conn_kwargs['use_agent'] = True
        conn_kwargs['auto_auth'] = False
        conn_kwargs['auto_preauth'] = False
        if config.use_socket:
            conn_kwargs['use_agent'] = False
            if site == config.site:
                conn_kwargs['use_ssl'] = False
                conn_kwargs['local_socket'] = True
                conn_kwargs['handle_host_auth'] = False
                conn_kwargs['handle_user_auth'] = False
                conn_kwargs['encrypt_session'] = False
                socket_uri = config.mgmtd_socket_path
            else:
                register_module("otpme.lib.classes.realm")
                conn_kwargs['auto_auth'] = True
                conn_kwargs['auto_preauth'] = True
                conn_kwargs['jwt_auth'] = True
                conn_kwargs['jwt_method'] = self.get_jwt

        daemon_conn = connections.get("mgmtd",
                                    socket_uri=socket_uri,
                                    interactive=self.interactive,
                                    aes_pass=self.aes_pass,
                                    **conn_kwargs)
        return daemon_conn

    def send(self, command, subcommand=None,
        command_args={}, object_list=[],
        realm=None, site=None, **kwargs):
        """ Send the given command to mgmtd. """
        # realm/site we will connect to.
        if realm is None:
            connect_realm = config.connect_realm
        else:
            connect_realm = realm
        if site is None:
            connect_site = config.connect_site
        else:
            connect_site = site

        # Add command and object identifier.
        command_args['subcommand'] = subcommand

        # Send non-object commands.
        if not object_list:
            # Get connection to mgmtd of the given realm/site.
            daemon_conn = self.get_daemon_connection(realm=connect_realm,
                                                    site=connect_site)
            # Send command to MGMT daemon.
            status, response = daemon_conn.send_command(command=command,
                                                    command_args=command_args,
                                                    **kwargs)
            return status, response

        ## Make sure object class is registered.
        #module = f"otpme.lib.classes.{command}"
        #register_module(module)

        # If this command includes a OTPme object (e.g. user, token etc.)
        # we need to do some special handling.
        objects = {}
        for _id in object_list:
            if _id.startswith("/"):
                x = oid.resolve_path(_id, object_type=command)
                object_realm = x['realm']
                object_site = x['site']
                object_name = x['name']
                if subcommand != "show":
                    if not object_name:
                        msg = _("Invalid path: {id}")
                        msg = msg.format(id=_id)
                        raise OTPmeException(msg)
                # Get object realm/site.
                connect_realm = object_realm
                if object_site:
                    connect_site = object_site
            else:
                object_realm = connect_realm
                object_site = connect_site
            if not object_realm in objects:
                objects[object_realm] = {}
            if not object_site in objects[object_realm]:
                objects[object_realm][object_site] = []
            objects[object_realm][object_site].append(_id)
        for realm in objects:
            for site in objects[realm]:
                # Get connection to mgmtd of the given realm/site.
                daemon_conn = self.get_daemon_connection(realm=connect_realm,
                                                        site=connect_site)
                for _id in objects[realm][site]:
                    command_args['object_identifier'] = _id
                    # Send command to MGMT daemon.
                    status, response = daemon_conn.send_command(command=command,
                                            command_args=command_args, **kwargs)
                    if status is False:
                        return status, response
        return status, response

    #def close(self):
    #    """ Close all daemon connections. """
    #    connections.close_connections()
