# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-host-1.0"

def register():
    config.register_otpme_protocol("hostd", PROTOCOL_VERSION)

class OTPmeHostP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-host-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "hostd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeHostP1, self).__init__(self.daemon, **kwargs)

    def get_user_uuid(self, username):
        """ Send 'get_user_uuid' command to hostd. """
        user_uuid = None
        command = "get_user_uuid"
        command_args = {'username':username}
        status, \
        status_code, \
        reply = self.connection.send(command, command_args)
        if status:
            user_uuid = reply
        return user_uuid

    def get_user_site(self, username):
        """ Send 'get_user_site' command to hostd. """
        user_site = None
        command = "get_user_site"
        command_args = {'username':username}
        status, \
        status_code, \
        reply = self.connection.send(command, command_args)
        if status:
            user_site = reply
        return user_site

    def get_site_cert(self, realm, site):
        """ Get site certificate. """
        if not config.uuid:
            return
        if realm == config.realm and site == config.site:
            try:
                site_cert = config.host_data['site_cert']
                return site_cert
            except:
                pass
        if (config.daemon_mode or config.use_api) and config.use_backend:
            # Load certificate of site we want to connect to.
            result = backend.search(object_type="site",
                                    attribute="name",
                                    value=site,
                                    realm=realm,
                                    return_type="instance")
            if not result:
                raise OTPmeException(_("Unknown site: %s") % site)
            s = result[0]
            site_cert = s.cert
        else:
            command = "get_site_cert"
            command_args = {
                            'realm' : realm,
                            'site'  : site,
                            }
            status, \
            status_code, \
            reply =  self.connection.send(command, command_args)
            if not status:
                msg = (_("Unable to get site certificate: %s") % reply)
                raise OTPmeException(msg)
            site_cert = reply
        if not site_cert:
            msg = (_("Missing site certificate: %s/%s") % (realm, site))
            raise OTPmeException(msg)
        return site_cert

    def get_host_status(self):
        """ Get host status. """
        command = "get_host_status"
        status, \
        status_code, \
        reply = self.connection.send(command)
        return status, reply

    def authorize_token(self, token_uuid, login_interface):
        """ Authorize token. """
        command = "authorize_token"
        command_args = {
                        'token_uuid'        : token_uuid,
                        'login_interface'   : login_interface,
                        }
        status, \
        status_code, \
        reply = self.connection.send(command, command_args)
        return status, reply

    def get_daemon_socket(self, daemon, node_name):
        """ Send command to hostd. """
        command = "get_daemon_socket"
        command_args = {}
        command_args['daemon'] = daemon
        command_args['node_name'] = node_name
        status, \
        status_code, \
        reply = self.connection.send(command, command_args)
        if not status:
            raise OTPmeException(reply)
        socket_uri = reply
        return socket_uri

    def trigger_token_data_sync(self):
        """ Send sync commands to hostd. """
        self.logger.debug("Calling hostd to trigger resync of token data...")
        # Trigger OTP/counter sync (e.g. push current HOTP counter to server)
        self.connection.send("sync_objects")
        self.connection.send("sync_token_data")
        self.connection.send("sync_ssh_authorized_keys")
