# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import connections
#from otpme.lib.register import register_module

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
            reply = method(*args, **kwargs)
            return reply

        return handler_function

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
        daemon_conn = connections.get("mgmtd",
                                    realm=realm,
                                    site=site,
                                    use_agent=True,
                                    auto_auth=False,
                                    auto_preauth=False,
                                    username=username,
                                    password=password,
                                    interactive=self.interactive,
                                    aes_pass=self.aes_pass)
        return daemon_conn

    def send(self, command, subcommand=None,
        command_args={}, object_list=[], **kwargs):
        """ Send the given command to mgmtd. """
        # realm/site we will connect to.
        connect_realm = config.connect_realm
        connect_site = config.connect_site

        # Add command and object identifier.
        command_args['subcommand'] = subcommand

        # Send non-object commands.
        if not object_list:
            # Get connection to mgmtd of the given realm/site.
            daemon_conn = self.get_daemon_connection(realm=connect_realm,
                                                    site=connect_site)
            # Send command to MGMT daemon.
            status, reply = daemon_conn.send_command(command=command,
                                    command_args=command_args, **kwargs)
            return status, reply

        ## Make sure object class is registered.
        #module = "otpme.lib.classes.%s" % command
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
                        msg = (_("Invalid path: %s") % _id)
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
                    status, reply = daemon_conn.send_command(command=command,
                                            command_args=command_args, **kwargs)
                    if status is False:
                        return status, reply
        return status, reply

    #def close(self):
    #    """ Close all daemon connections. """
    #    connections.close_connections()
