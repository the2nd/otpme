# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import json
from otpme.lib import cache
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import connections
from otpme.lib import multiprocessing

from otpme.lib.classes.host import Host
from otpme.lib.classes.node import Node
from otpme.lib.protocols import status_codes
from otpme.lib.job.callback import JobCallback
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.daemon.clusterd import cluster_daemon_reload

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-join-1.0"

def register():
    config.register_otpme_protocol("joind", PROTOCOL_VERSION, server=True)

class OTPmeJoinP1(OTPmeServer1):
    """ Class that implements join server for protocol OTPme-join-1.0 """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "joind"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # We may need an authenticated user if no JOTP was given.
        self.require_auth = "user"
        self.require_preauth = True
        # The joining node does not have our site cert that is needed to
        # negotiate the a session key.
        self.encrypt_session = True
        # The accessgroup we authenticate users against.
        self.access_group = config.join_access_group
        # Indicates that the JOIN accessgroup should inherith tokens from the
        # REALM accessgroup.
        self.check_parent_groups = True
        # Indicates parent class to require a client certificate.
        self.require_client_cert = False
        # Host types we support.
        self.supported_host_types = [ 'node', 'host' ]
        # Cannot verify not existing host on join.
        self.verify_host = False
        # The site object of the current request.
        self.request_site = None
        # Join requests require master node.
        self.require_master_node = True
        # JOTP/LOTP to use for decryption.
        self.session_otp = None
        # OTP type in use.
        self.session_otp_type = None
        # Indicates master node join.
        self.master_node_join = False
        # Join/Leave job uuid.
        self.job_uuid = None
        self.callback = None
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def get_host(self, host_name):
        """ Get host object. """
        # Search for existing hosts. We only search for hosts of our site
        # because we do not support cross site joins.
        hosts = backend.search(object_type="host",
                                attribute="name",
                                value=host_name,
                                realm=config.realm,
                                return_type="instance")
        # Search for existing nodes.
        nodes = backend.search(object_type="node",
                                attribute="name",
                                value=host_name,
                                realm=config.realm,
                                return_type="instance")
        result = hosts + nodes

        host = None
        found_hosts = {}
        for x in result:
            if x.type in [ "host", "node" ]:
                found_hosts[x.oid] = x

        if len(found_hosts) > 1:
            msg = (_("Uuuh, more than one host with this name exists: %s")
                        % ", ".join(found_hosts))
            raise OTPmeException(msg)

        if len(found_hosts) == 1:
            host = list(found_hosts.values())[0]

        return host

    def join_realm(self, site, host_type, host_name,
        host_unit, host, callback, force=False):
        """ Try to join given host to realm. """
        self.logger.debug("Trying to join %s: %s" % (host_type, host_name))
        # If the user is authenticated (not used an JOTP) and the host already
        # exists we have to verify ACLs when calling join_realm().
        if self.authenticated and host:
            verify_acls = True
        else:
            verify_acls = False

        # Try to add host if it does not exist.
        if not host:
            if host_type == "host":
                host_class = Host
            if host_type == "node":
                host_class = Node
            self.logger.debug("Adding %s: %s" % (host_type, host_name))
            host = host_class(name=host_name,
                            unit=host_unit,
                            site=site.name,
                            realm=config.realm)
            try:
                host.add(gen_jotp=True,
                        callback=callback)
            except Exception as e:
                message = (_("Error adding %s: %s") % (host_type, e))
                status = False
                self.logger.debug(message)
                config.raise_exception()
                return self.build_response(status, message)

        # Write changed objects.
        cache.flush()

        # For master node join requests we have to check some things.
        if host_type == "node":
            if host.site_uuid != config.site_uuid:
                s = backend.get_object(object_type="site", uuid=host.site_uuid)
                if not s:
                    message = (_("Unknown site: %s") % host.site_uuid)
                    status = False
                    return self.build_response(status, message)

                # The site must be disabled for master node join.
                if s.enabled:
                    message = (_("Cannot do master node join for enabled site: %s")
                                % s.name)
                    status = False
                    return self.build_response(status, message)

                # Check if the joining host is a node.
                if host.type != "node":
                    message = (_("Wrong host type: %s") % host.type)
                    status = False
                    return self.build_response(status, message)

                all_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=host.realm,
                                            site=host.site,
                                            return_type="name")
                # Check if the joining node is the first node of this site.
                if len(all_nodes) != 1:
                    message = (_("Node is not the first node of site: %s") % s.name)
                    status = False
                    return self.build_response(status, message)
                self.master_node_join = True

        # Make host join the realm.
        try:
            host.join_realm(verify_acls=verify_acls,
                            callback=callback)
        except Exception as e:
            config.raise_exception()
            message = (_("Error joining realm: %s") % e)
            status = False
            return self.build_response(status, message)

        # Write changed objects.
        cache.flush()

        # Make sure we clean node from cache to prevent issues when joining
        # node from other site because checksums are not updated for objects
        # from other sites.
        if host.site_uuid != config.site_uuid:
            cache.clear(host.oid)

        self.logger.debug("Selecting objects for join reply...")

        # Build list with initial sync objects.
        sync_objects = []

        # Add joining node/host.
        sync_objects.append((host.type, host.uuid))

        # Add realm.
        sync_objects.append(("realm", config.realm_uuid))

        # Add all sites to sync list.
        result = backend.search(object_type="site",
                                attribute="name",
                                value="*",
                                return_type="uuid")
        for x in result:
            sync_objects.append(("site", x))

        # Add all units.
        result = backend.search(object_type="unit",
                                attribute="name",
                                value="*",
                                return_type="uuid")
        for x in result:
            sync_objects.append(("unit", x))

        # Add all nodes.
        result = backend.search(object_type="node",
                                attribute="name",
                                value="*",
                                return_type="uuid")
        for x in result:
            sync_objects.append(("node", x))

        # Add all CAs.
        result = backend.search(object_type="ca",
                                attribute="name",
                                value="*",
                                return_type="uuid")
                                #realm=config.realm,
                                #site=config.site)
        for x in result:
            sync_objects.append(("ca", x))

        # If this is a master node join we have to add all objects of the site.
        if host.site_uuid != config.site_uuid:
            # Add nodes site.
            sync_objects.append(("site", host.site_uuid))

            # Add all objects of the site.
            for x in config.tree_object_types:
                result = backend.search(object_type=x,
                                        attribute="uuid",
                                        value="*",
                                        return_type="uuid",
                                        site=host.site,
                                        realm=config.realm)
                for uuid in result:
                    sync_objects.append((x, uuid))

                result = backend.search(object_type=x,
                                        attribute="uuid",
                                        value="*",
                                        return_type="uuid",
                                        site=host.site,
                                        realm=config.realm,
                                        template=True)
                for uuid in result:
                    sync_objects.append((x, uuid))
        else:
            # Add base accessgroups.
            base_access_groups = config.get_base_objects("accessgroup")
            for x in base_access_groups:
                result = backend.search(object_type="accessgroup",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("accessgroup", x))

            # Add groups. We need users group at this stage because of
            # SSL files ownership on new host/node.
            groups_to_add = [config.users_group]
            # Add base groups.
            groups_to_add += list(config.get_base_objects("group"))
            for x in groups_to_add:
                result = backend.search(object_type="group",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("group", x))

            # Add base roles.
            base_roles = config.get_base_objects("role")
            for x in base_roles:
                result = backend.search(object_type="role",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("role", x))

            # Add base users.
            base_users = config.get_base_objects("user")
            per_site_users = config.get_per_site_objects("user")
            for x in base_users:
                if x in per_site_users:
                    continue
                result = backend.search(object_type="user",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("user", x))

            # Add base scripts.
            base_scripts = config.get_base_objects("script")
            for x in base_scripts:
                result = backend.search(object_type="script",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("script", x))

            # Add base policies.
            base_policies = config.get_base_objects("policy")
            for x in base_policies:
                result = backend.search(object_type="policy",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("policy", x))

            # Add base dictionaries.
            base_dictionaries = config.get_base_objects("dictionary")
            for x in base_dictionaries:
                result = backend.search(object_type="dictionary",
                                        attribute="name",
                                        value=x,
                                        return_type="uuid",
                                        realm=config.realm,
                                        site=config.site)
                for x in result:
                    sync_objects.append(("dictionary", x))

        # Get object configs.
        sync_object_configs = {}
        for x in sync_objects:
            object_type = x[0]
            uuid = x[1]
            o = backend.get_object(object_type=object_type, uuid=uuid)
            # Skip orphan objects.
            if not o:
                msg = ("Unable to get object for join request: %s (%s)"
                        % (uuid, object_type))
                self.logger.warning(msg)
                continue
            object_config = o.get_sync_config(peer=host)
            object_id = o.oid.full_oid
            sync_object_configs[object_id] = object_config

        # Build join reply.
        join_reply = {
                    'jotp'                  : host.jotp,
                    'object_configs'        : sync_object_configs,
                    'master_node_join'      : self.master_node_join,
                    'password_hash_salt'    : config.password_hash_salt,
                    }

        # Encode join reply.
        message = json.encode(join_reply)
        status = True

        # Make sure we clean node from cache to prevent issues when joining
        # node from other site because checksums are not updated for objects
        # from other sites.
        cache.clear(host.oid)

        self.logger.debug("Join phase 1 finished successful.")

        return self.build_response(status, message)

    def finish_join(self, host, host_public_key, callback,
        host_cert=None, host_cert_req=None, site_cert_req=None):
        """ Finalize realm join of given host. """
        msg = ("Trying to finalize realm join: %s" % host.name)
        self.logger.debug(msg)
        # Finalize realm join.
        try:
            host.join_realm(verify_acls=False,
                            cert=host_cert,
                            cert_req=host_cert_req,
                            public_key=host_public_key,
                            finish=True,
                            callback=callback)
        except CertVerifyFailed as e:
            message = (_("Error joining realm: %s") % e)
            status = False
            return self.build_response(status, message)
        except Exception as e:
            config.raise_exception()
            message = (_("Error joining realm: %s") % e)
            status = False
            return self.build_response(status, message)

        # Write changed objects.
        cache.flush()

        # Make sure we clean node from cache to prevent issues when joining
        # node from other site because checksums are not updated for objects
        # from other sites.
        if host.site_uuid != config.site_uuid:
            cache.clear(host.oid)

        # Build final join reply.
        join_reply = {
                    'lotp'      : host.lotp,
                    'host_cert' : host.cert,
                    }

        # Get hosts site.
        site = backend.get_object(object_type="site", uuid=host.site_uuid)
        # Get hosts site CA.
        site_ca = backend.get_object(object_type="ca", uuid=site.ca)

        # If this is a master node join we have to enable nodes site.
        if host.site_uuid != config.site_uuid:
            # Set site master node.
            self.logger.debug("Setting site master node: %s" % host.fqdn)
            # Enable site if needed.
            if not site.enabled:
                self.logger.debug("Enabling site: %s" % site.name)
                site.enable(force=True,
                            verify_acls=False,
                            run_policies=False,
                            callback=callback)
                # Write site.
                try:
                    site._write(callback=callback)
                except Exception as e:
                    msg = "Failed to write site: %s" % e
                    self.logger.critical(msg)

            # Make sure we clean site from cache to prevent issues when joining
            # node from other site because checksums are not updated for objects
            # from other sites.
            cache.clear(site.oid)

            # If we got a CSR for the SITE_CA of a new site sign it.
            if site_cert_req:
                realm = backend.get_object(object_type="realm",
                                        uuid=config.realm_uuid)
                realm_ca = backend.get_object(object_type="ca",
                                                uuid=realm.ca)
                # The common name of the CSR must be the site CA path.
                common_name = site_ca.path
                self.logger.debug("Generating CA certificate: %s" % common_name)
                try:
                    cert, key = realm_ca.create_ca_cert(common_name,
                                                        cert_req=site_cert_req,
                                                        verify_acls=False,
                                                        callback=callback)
                except Exception as e:
                    cert = None
                    self.logger.warning("Error signing CSR: %s" % e)
                # Add cert to local remote site object.
                site_ca.set_cert(cert=cert, callback=callback)

                # Write CA.
                try:
                    site_ca._write(callback=callback)
                except Exception as e:
                    msg = "Failed to write site CA: %s" % e
                    self.logger.critical(msg)
                # Make sure we clean CA from cache to prevent issues when joining
                # node from other site because checksums are not updated for objects
                # from other sites.
                cache.clear(site_ca.oid)
                # Add cert to reply.
                join_reply['ca_cert'] = cert

        # Make sure host is enabled.
        try:
            host.enable(force=True,
                        verify_acls=False,
                        callback=callback)
        except Exception as e:
            message = (_("Error enabling %s: %s") % (host.type, e))
            self.logger.debug(message)
            status = False
            return self.build_response(status, message)

        # Write changed objects.
        cache.flush()

        # Build join message.
        msg = []
        host_desc = "%s%s" % (host.type[0].upper(), host.type[1:])
        msg.append("%s %s joined successful realm %s." % (host_desc, host.name, config.realm))

        # Only hosts from own site can leave the realm.
        if host.site_uuid == config.site_uuid:
            if host.lotp_enabled and host.lotp:
                x = ("You can use the following LOTP to leave the realm: %s"
                        % host.lotp)
                msg.append(x)

        ## Make sure all online nodes gets new node object.
        #if host.type == "node":
        #    self.update_node_object(host)

        # Add join message to reply.
        join_reply['message'] = "\n".join(msg)

        # Encode join reply.
        message = json.encode(join_reply)
        status = True

        # Write changed objects.
        cache.flush()

        self.logger.debug("Join phase 2 finished successful.")
        self.logger.info(msg[0])
        return self.build_response(status, message)

    def handle_join_command(self, host_name, host_type,
        host, jotp, force, _request, finish):
        """ Handle join command. """
        # Check host join status.
        if host and host.joined and not force:
            host_desc = "%s%s" % (host.type[0].upper(), host.type[1:])
            msg = (_("WARNING: %s has already joined this realm. "
                    "Please use -f to override.") % host_desc)
            raise OTPmeException(msg)

        # Verify given JOTP.
        if host and jotp:
            # Make sure JOTP is enabled for host/node.
            if not host.jotp_enabled:
                msg = "JOTP disabled for host: %s" % host
                raise OTPmeException(msg)
            # Make sure we compare JOTP as string.
            if host.jotp != str(jotp):
                msg = (_("Permission denied: Wrong JOTP"))
                raise OTPmeException(msg)

        # Try to get host unit.
        try:
            host_unit = _request['unit']
        except:
            host_unit = None

        # Set default unit.
        if not host_unit:
            if host_type == "node":
                host_unit = config.get_default_unit("node")
            else:
                host_unit = config.get_default_unit("host")

        # Check host type.
        if not host_type in self.supported_host_types:
            msg = (_("Unknown host type: %s") % host_type)
            raise OTPmeException(msg)

        ## Only admin users may join nodes.
        #if host_type == "node":
        #    if self.authenticated and not config.auth_token.is_admin():
        #        msg = (_("Permission denied."))
        #        raise OTPmeException(msg)

        if host_type == "host":
            if self.request_site.name != config.site:
                msg = (_("Cannot join host of other site."))
                raise OTPmeException(msg)

        if host:
            replace_existing_host = False
            # Admin users may override existing node/host.
            if self.authenticated and config.auth_token.is_admin():
                if force:
                    replace_existing_host = True

            # Check type of existing host.
            if host.type != host_type:
                if replace_existing_host:
                    host.delete(force=True)
                    host = None
                else:
                    msg = (_("%s already exists: %s")
                            % (host.type, host.name))
                    raise OTPmeException(msg)

            # Verify host unit.
            if host:
                if host_unit != host.unit:
                    if replace_existing_host:
                        host.delete(force=True)
                        host = None
                    else:
                        msg = (_("%s already exists in unit: %s")
                                % (host.type, host.unit))
                        raise OTPmeException(msg)

        if finish:
            # When finalizing the join process we need an JOTP.
            if not jotp:
                msg = (_("Need JOTP to finalize join process."))
                raise OTPmeException(msg)

            # When finalizing the join process the host must exist.
            if not host:
                msg = (_("Unknown %s: %s") % (host_type, host_fqdn))
                self.logger.debug("Join phase 2 error: %s" % msg)
                # Prevent hostname testing for not authenticated users.
                if not self.authenticated:
                    msg = (_("Access denied."))
                raise OTPmeException(msg)

            # Try to get host cert.
            try:
                host_cert = _request['host_cert']
            except:
                host_cert = None
            # Try to get host cert request.
            try:
                host_cert_req = _request['host_cert_req']
            except:
                host_cert_req = None
            # Try to get CSR for new site CA.
            try:
                site_cert_req = _request['site_cert_req']
            except:
                site_cert_req = None
            # Try to get host public key.
            try:
                host_public_key = _request['host_public_key']
            except:
                host_public_key = None

            # Try to finalize join process of host.
            return self.finish_join(host, host_public_key,
                                    host_cert=host_cert,
                                    host_cert_req=host_cert_req,
                                    site_cert_req=site_cert_req,
                                    callback=self.callback)

        # If we got a JOTP the host must already exist to proceed.
        if jotp and not host:
            msg = (_("Access denied."))
            self.logger.debug("Join phase 1 error: Unknown %s: %s"
                                % (host_type, host_fqdn))
            raise OTPmeException(msg)

        # Try to join host.
        return self.join_realm(self.request_site,
                            host_type,
                            host_name,
                            host_unit,
                            host,
                            self.callback,
                            force=force)

    def handle_leave_command(self, host_fqdn, host, lotp, _request):
        """ Handle leave command. """
        # When leaving the realm the host must exist. ;)
        if not host:
            msg = (_("Unknown host: %s") % host_fqdn)
            self.logger.debug("Leaving host error: %s" % msg)
            # Prevent hostname testing for not authenticated users.
            if not self.authenticated:
                msg = (_("Access denied."))
            raise OTPmeException(msg)

        # Cannot leave host from other site.
        if host.site_uuid != config.site_uuid:
            msg = (_("Cannot leave %s from other site: %s")
                        % (host.type, host.name))
            raise OTPmeException(msg)

        msg = ("Trying to leave realm for %s: %s" % (host.type, host.name))
        self.logger.debug(msg)

        # Make sure the given FQDN matches the client cert of the
        # connecting host BEFORE verifying the LOTP.
        if self.client_cn != host.fqdn:
            msg = (_("Access denied: Client certificate does not match "
                        "host FQDN: %s %s") % (self.client_cn, host.fqdn))
            raise OTPmeException(msg)
        # Verify given LOTP.
        if lotp:
            # Make sure LOTP is enabled for host/node.
            if not host.lotp_enabled:
                msg = "LOTP disabled for host: %s" % host
                raise OTPmeException(msg)
            # Make sure we compare LOTP as string.
            if host.lotp != str(lotp):
                msg = (_("Access denied: Wrong LOTP"))
                raise OTPmeException(msg)

        # Without valid LOTP the user must be authenticated.
        if not lotp and not self.authenticated:
            msg = (_("Access denied: Not authenticated"))
            raise OTPmeException(msg)

        try:
            keep_cert = _request['keep_cert']
        except:
            keep_cert = False

        try:
            keep_host = _request['keep_host']
        except:
            keep_host = False

        if keep_cert:
            keep_host = True

        # If the user is authenticated (not used a LOTP) we have to verify
        # ACLs when calling leave_realm().
        if self.authenticated:
            verify_acls = True
        else:
            verify_acls = False

        # Make host leave the realm.
        if keep_host:
            try:
                host.leave_realm(keep_cert=keep_cert,
                                verify_acls=verify_acls,
                                callback=self.callback)
            except Exception as e:
                msg = (_("Error leaving realm: %s") % e)
                raise OTPmeException(msg)

            try:
                host.disable(force=True,
                            verify_acls=False,
                            callback=self.callback)
            except Exception as e:
                msg = (_("Error disabling %s: %s") % (host.type, e))
                raise OTPmeException(msg)
        else:
            try:
                host.delete(force=True,
                            verify_acls=False,
                            callback=self.callback)
            except Exception as e:
                msg = (_("Error deleting %s: %s") % (host.type, e))

        # Write changed objects.
        cache.flush()

        # Make sure all online nodes gets node object updated (disabled).
        if host.type == "node":
            self.update_node_object(host)

        # Build leave response.
        status = True
        host_desc = "%s%s" % (host.type[0].upper(), host.type[1:])
        message = (_("%s %s leaved successful realm %s.")
                    % (host_desc, host.name, config.realm))
        self.logger.info(message)
        if host.allow_jotp_rejoin:
            message = (_("%s\nYou can use the following JOTP to re-join the "
                        "%s: %s") % (message, host.type, host.jotp))
        return self.build_response(status, message)

    def _process(self, command, command_args):
        """ Handle join data received from join_handler """
        # All valid commands.
        valid_commands = [
                        "join",
                        "leave",
                        "add_ca_crl",
                        "add_site_cert",
                        ]

        if config.site_init:
            message = (_("Cannot join while site init is running."))
            status = False
            return self.build_response(status, message)

        # Check if we got a valid command.
        if not command in valid_commands:
            message = (_("Unknown command: %s") % command)
            status = False
            return self.build_response(status, message)

        # Get join request.
        try:
            _request = command_args['request']
        except:
            message = "No request found."
            status = False
            return self.build_response(status, message)

        # Try to get site to join host to.
        try:
            site = command_args['site']
        except:
            site = config.site

        # Try to get FQDN of host/node.
        try:
            host_fqdn = command_args['host_fqdn']
        except:
            message = (_("JOIN_INCOMPLETE_COMMAND: Missing host FQDN."))
            status = False
            self.logger.warning(message)
            return self.build_response(status, message)

        # Load site.
        self.request_site = backend.get_object(object_type="site",
                                realm=config.realm,
                                name=site)
        if not self.request_site:
            message = (_("Unknown site: %s") % site)
            status = False
            self.logger.warning(message)
            return self.build_response(status, message)

        # Get hostname from FQDN.
        host_name = host_fqdn.split(".")[0]

        # Try to get host type.
        try:
            host_type = command_args['host_type']
        except:
            host_type = "host"

        if host_type == "node":
            search_attrs = {
                            'uuid'      : {'value':"*"},
                            'enabled'   : {'value':True},
                        }
            enabled_nodes = backend.search(object_type="node",
                                        attributes=search_attrs,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="name")
            missing_nodes = []
            member_nodes = multiprocessing.member_nodes
            for node_name in enabled_nodes:
                if node_name == config.host_data['name']:
                    continue
                if node_name == host_name:
                    continue
                if node_name in member_nodes:
                    continue
                missing_nodes.append(node_name)
            if missing_nodes:
                status = False
                missing_nodes = " ".join(missing_nodes)
                message = ("Please wait for nodes to join the cluster: %s"
                            % missing_nodes)
                return self.build_response(status, message)

        # Get host object.
        try:
            host = self.get_host(host_name)
        except Exception as e:
            config.raise_exception()
            message = "Failed to get %s: %s" % (host_type, e)
            status = False
            self.logger.debug(message)
            return self.build_response(status, message)

        if command == "join" and host:
            if host.site != self.request_site.name:
                message = (_("Cannot join %s from site %s."
                            % (host_type, self.request_site.name)))
                status = False
                self.logger.warning(message)
                return self.build_response(status, message)
            if host.type != host_type:
                message = (_("%s with name %s already exists."
                            % (host.type, host_name)))
                status = False
                self.logger.warning(message)
                return self.build_response(status, message)

        # Check if we got an encrypted request.
        try:
            encrypted = command_args['encrypted']
        except:
            encrypted = False

        if not self.session_otp:
            if host:
                if command == "leave":
                    self.session_otp = host.lotp
                    self.session_otp_type = "LOTP"
                else:
                    self.session_otp = host.jotp
                    self.session_otp_type = "JOTP"

        session_key = None
        session_enc_mod = None
        if encrypted:
            if not host:
                message = "Unknown %s: %s" % (host_type, host_name)
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            # Make sure host does have a JOTP/LOTP.
            if not self.session_otp:
                message = (_("Permission denied: Host does not have a %s set")
                            % self.session_otp_type)
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            # Make sure request includes encryption type.
            try:
                enc_type = command_args['enc_type']
            except:
                message = "Got encrypted join request without encryption type."
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            # Make sure request includes key salt.
            try:
                key_salt = command_args['key_salt']
            except:
                message = "Got encrypted join request without key salt."
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            # Make sure request includes JOTP hash type.
            try:
                otp_hash_type = command_args['otp_hash_type']
            except:
                message = "Got encrypted join request without JOTP hash type."
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            # Check if we support the hash type.
            if otp_hash_type not in config.get_hash_types():
                message = "Server does not support hash type: %s" % otp_hash_type
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)

            # Try to load session encryption.
            try:
                session_enc_mod = config.get_encryption_module(enc_type)
            except Exception as e:
                status = False
                message = "Failed to load session encryption: %s" % e
                return self.build_response(status, message, encrypt=False)
            # Get encryption key from JOTP.
            try:
                x = session_enc_mod.derive_key(self.session_otp,
                                    salt=key_salt,
                                    hash_type=otp_hash_type)
            except Exception as e:
                message = "Failed to generate decryption key: %s" % e
                status = False
                self.logger.debug(message)
                return self.build_response(status, message)
            session_key = x['key']

        # Decode/decrypt join request.
        try:
            _request = json.decode(_request,
                                encryption=session_enc_mod,
                                encoding="base64",
                                enc_key=session_key)
        except Exception as e:
            if encrypted:
                message = ("Failed to decrypt request. Wrong %s?"
                            % self.session_otp_type.upper())
            else:
                message = ("Failed to decode request: %s" % e)
            status = False
            self.logger.debug(message)
            return self.build_response(status, message)

        # For encrypted requests (e.g. JOTP) we have to make sure that request
        # args match command args (e.g. no MITM).
        if encrypted:
            try:
                r_command = _request['command']
            except:
                message = "Request is missing command."
                status = False
                return self.build_response(status, message)
            try:
                r_site = _request['site']
            except:
                r_site = config.site
            try:
                r_host_fqdn = _request['host_fqdn']
            except:
                message = "Request is missing FQDN."
                status = False
                return self.build_response(status, message)
            try:
                r_host_name = _request['host_name']
            except:
                message = "Request is missing hostname."
                status = False
                return self.build_response(status, message)
            if r_command != command:
                message = ("Command missmatch of encrypted request: %s <> %s"
                            % (command, r_command))
                status = False
                return self.build_response(status, message)
            if r_site != site:
                message = ("Site argument mismatch of encrypted request: %s <> %s"
                            % (site, r_site))
                status = False
                return self.build_response(status, message)
            if r_host_fqdn != host_fqdn:
                message = ("FQDN argument mismatch of encrypted request: %s <> %s"
                            % (host_fqdn, r_host_fqdn))
                status = False
                return self.build_response(status, message)
            if r_host_name != host_name:
                message = ("Hostname argument mismatch of encrypted request: %s <> %s"
                            % (host_name, r_host_name))
                status = False
                return self.build_response(status, message)

        # Try to get force parameter.
        try:
            force = _request['force']
        except:
            force = False

        # Try to get JOTP.
        try:
            jotp = _request['jotp']
        except:
            jotp = None

        # Try to get LOTP.
        try:
            lotp = _request['lotp']
        except:
            lotp = None

        # Try to get finish flag.
        try:
            finish = _request['finish']
        except:
            finish = False

        # We need at least JOTP/LOTP or an authenticated user.
        if not jotp and not lotp and not self.authenticated:
            message = (_("Please auth first."))
            status = status_codes.NEED_HOST_AUTH
            return self.build_response(status, message)

        # Make sure JOTP/LOTP request is encrypted.
        if jotp and not encrypted and not finish:
            message = (_("Got JOTP in unencrypted request."))
            status = False
            return self.build_response(status, message)
        if lotp and not encrypted:
            message = (_("Got LOTP in unencrypted request."))
            status = False
            return self.build_response(status, message)

        # Check join ACL.
        if command == "join" and not jotp:
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=config.join_access_group,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            join_access_group = result[0]
            join_acl = "join:%s" % host_type
            if not join_access_group.verify_acl(join_acl):
                message = (_("Permission denied."))
                status = False
                self.logger.warning(message)
                return self.build_response(status, message)

        # Check leave ACL.
        if command == "leave" and not lotp:
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=config.join_access_group,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            join_access_group = result[0]
            join_acl = "leave:%s" % host_type
            if not join_access_group.verify_acl(join_acl):
                message = (_("Permission denied."))
                status = False
                self.logger.warning(message)
                return self.build_response(status, message)

        if not self.job_uuid:
            # Add callback with job UUID needed for proper object locking.
            self.job_uuid = stuff.gen_uuid()
        if not self.callback:
            self.callback = JobCallback(uuid=self.job_uuid)
            # Disable sending of client messages.
            self.callback.disable()

        # Add job to running jobs to prevent master failover while host/node join.
        if self.job_uuid not in multiprocessing.running_jobs:
            add_job = False
            if command == "join":
                add_job = True
                auth_token = "JOTP"
                name = "join %s %s" % (host_type, host_name)
            elif command == "leave":
                add_job = True
                auth_token = "JOTP"
                name = "leave %s %s" % (host_type, host_name)
            if add_job:
                if config.auth_token:
                    auth_token = config.auth_token.rel_path
                multiprocessing.running_jobs[self.job_uuid] = {
                                                        'name'      : name,
                                                        'start_time': time.time(),
                                                        'auth_token': auth_token,
                                                        'pid'       : os.getpid(),
                                                        }
        if command == "join":
            try:
                join_result = self.handle_join_command(host_name,
                                                host_type,
                                                host,
                                                jotp,
                                                force,
                                                _request,
                                                finish)
            except Exception as e:
                multiprocessing.running_jobs.pop(self.job_uuid)
                status = False
                message = str(e)
                self.logger.warning(message)
                return self.build_response(status, message)
            if finish:
                multiprocessing.running_jobs.pop(self.job_uuid)
            return join_result

        if command == "leave":
            try:
                leave_result = self.handle_leave_command(host_fqdn,
                                                        host,
                                                        lotp,
                                                        _request)
            except Exception as e:
                status = False
                message = str(e)
                self.logger.warning(message)
                multiprocessing.running_jobs.pop(self.job_uuid)
                return self.build_response(status, message)
            multiprocessing.running_jobs.pop(self.job_uuid)
            return leave_result

        if command == "add_site_cert":
            status = False
            message = (_("Permission denied"))
            # If this is a master node join we may have to update site cert.
            if self.master_node_join:
                # Get hosts site.
                site = backend.get_object(object_type="site",
                                        uuid=host.site_uuid)
                # Try to get cert.
                try:
                    cert = _request['cert']
                except:
                    status = False
                    message = (_("Malformed command: missing certificate"))
                    return self.build_response(status, message)
                # Add cert to local remote site object.
                site.cert = cert
                # Save object.
                try:
                    site._write(callback=self.callback)
                    status = True
                    message = (_("CRL update successful"))
                except Exception as e:
                    status = False
                    message = (_("Failed to update CRL: %s") % e)
                # Write changed objects.
                cache.flush()
                # Make sure we clean site from cache to prevent issues
                # when joining node from other site because checksums
                # are not updated for objects from other sites.
                cache.clear(site.oid)

            return self.build_response(status, message)

        if command == "add_ca_crl":
            status = False
            message = (_("Permission denied"))
            # If this is a master node join we have to update sites CRL.
            if host.type == "node" and host.site_uuid != config.site_uuid:
                # Get hosts site.
                site = backend.get_object(object_type="site",
                                        uuid=host.site_uuid)
                # Try to get CRL.
                try:
                    crl = _request['crl']
                except:
                    status = False
                    message = (_("Malformed command: missing CRL"))
                    return self.build_response(status, message)
                # Get hosts site CA.
                site_ca = backend.get_object(object_type="ca",
                                            uuid=site.ca)
                # Add CRL to local remote site object.
                try:
                    site_ca.set_crl(crl)
                    site_ca._write(callback=self.callback)
                    status = True
                    message = (_("CRL update successful"))
                except Exception as e:
                    status = False
                    message = (_("Failed to update CRL: %s") % e)
                # Make sure we clean CA from cache to prevent issues
                # when joining node from other site because checksums
                # are not updated for objects from other sites.
                cache.clear(site_ca.oid)
                # Update realm CA data.
                site_ca.update_realm_ca_data()
                # Reload after adding new CRL.
                cluster_daemon_reload()
                #self._send_daemon_msg(daemon="controld",
                #                        command="reload",
                #                        timeout=1)

            return self.build_response(status, message)

    def update_node_object(self, node):
        # Make sure all online nodes gets the node object updated.
        online_nodes = multiprocessing.get_list(name="otpme_online_nodes")
        for node_name in online_nodes:
            # Skip joining node.
            if node_name == node.name:
                continue
            # Skip ourselves.
            if node_name == config.host_data['name']:
                continue
            try:
                socket_uri = stuff.get_daemon_socket("clusterd", node_name)
            except Exception as e:
                socket_uri = None
                msg = "Failed to get daemon socket: %s" % e
                self.logger.warning(msg)
            if socket_uri:
                try:
                    clusterd_conn = connections.get("clusterd",
                                                    timeout=None,
                                                    socket_uri=socket_uri)
                except Exception as e:
                    clusterd_conn = None
                    msg = ("Failed to get cluster connection: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
            if clusterd_conn:
                try:
                    clusterd_conn.write(node.oid.full_oid,
                                        node.object_config.copy(),
                                        node.last_modified,
                                        node.last_used)
                except Exception as e:
                    msg = ("Failed to update node object: %s: %s"
                            % (node.object_id, e))
                    self.logger.warning(msg)
                clusterd_conn.close()

    def _close(self):
        pass
