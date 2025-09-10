# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import shutil

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import net
from otpme.lib import host
from otpme.lib import json
from otpme.lib import cache
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import nsscache
from otpme.lib import filetools
from otpme.lib.pki import utils
from otpme.lib import init_otpme
from otpme.lib import connections
from otpme.lib import sign_key_cache
from otpme.lib.messages import message
#from otpme.lib.messages import error_message
from otpme.lib.job.callback import JobCallback
#from otpme.lib.protocols.client.sync1 import validate_received_object

from otpme.lib.exceptions import *

logger = config.logger

class JoinHandler(object):
    def __init__(self):
        self.realm = None
        self.site = None
        self.unit = None
        self.username = None
        self.socket_uri = None
        self.host_name = None
        self.host_type = None
        self.host_fqdn = None
        self._my_site = None
        self._my_site_ca = None
        self.encrypt_session = False
        self.otp_hash_type = None
        self.session_key = None
        self.session_key_salt = None
        self.session_enc_algo = config.disk_encryption
        self.session_enc_algo_mod = config.disk_encryption_mod
        self._current_action = None

    def send(self, command, command_args, request, **kwargs):
        """ Send request to joind. """
        # Get connection to joind.
        joind_conn = self.get_daemon_conn(**kwargs)
        # Handle encryption.
        enc_key = None
        enc_mod = None
        if self.encrypt_session:
            enc_key = self.session_key
            enc_mod = self.session_enc_algo_mod
            # Add key salt to command args.
            command_args['encrypted'] = True
            command_args['enc_type'] = self.session_enc_algo
            command_args['key_salt'] = self.session_key_salt
            command_args['otp_hash_type'] = self.otp_hash_type
        # Encode join request.
        request = json.encode(request,
                            encoding="base64",
                            encryption=enc_mod,
                            enc_key=enc_key)
        # Add request.
        command_args['request'] = request
        # Send request.
        status, \
        status_code, \
        reply, \
        binary_data = joind_conn.send(command, command_args)
        # Decode/decrypt reply.
        if reply.startswith("JSON"):
            reply = json.decode(reply,
                                encoding="base64",
                                encryption=enc_mod,
                                enc_key=enc_key)
        return status, status_code, reply

    def get_daemon_conn(self, realm, site, socket_uri,
        username=None, password=None, jotp=None, lotp=None,
        trust_site_cert=False, check_site_cert=None,
        fingerprint_digest="sha256"):
        """ Get connection to joind. """
        auto_auth = True
        auto_preauth = False
        site_ident = False
        trust_site_cert_fp = None
        if self._current_action == "join":
            if jotp:
                auto_auth = False
                auto_preauth = True
            if not trust_site_cert:
                if check_site_cert:
                    trust_site_cert_fp = check_site_cert
            site_ident = True
            request_jwt = False
            verify_preauth = False
            verify_server = False
            allow_untrusted = True
            check_connected_site = False
        elif self._current_action == "leave":
            if lotp:
                auto_auth = False
                auto_preauth = True
            request_jwt = True
            verify_preauth = True
            verify_server = True
            allow_untrusted = False
            check_connected_site = True
        else:
            msg = "Cannot connect without action."
            raise OTPmeException(msg)

        # Get connection to joind.
        try:
            joind_conn = connections.get("joind",
                                    realm=realm,
                                    site=site,
                                    socket_uri=socket_uri,
                                    username=username,
                                    password=password,
                                    site_ident=site_ident,
                                    site_ident_digest=fingerprint_digest,
                                    trust_site_cert=trust_site_cert,
                                    trust_site_cert_fp=trust_site_cert_fp,
                                    use_ssh_agent=config.use_ssh_agent,
                                    use_smartcard=config.use_smartcard,
                                    auto_auth=auto_auth,
                                    auto_preauth=auto_preauth,
                                    interactive=True,
                                    use_ssl=True,
                                    use_agent=False,
                                    start_otpme_agent=False,
                                    encrypt_session=False,
                                    request_jwt=request_jwt,
                                    verify_server=verify_server,
                                    verify_preauth=verify_preauth,
                                    allow_untrusted=allow_untrusted,
                                    check_connected_site=check_connected_site,
                                    timeout=30)
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to connect to join daemon: %s") % e)
            raise OTPmeException(msg)
        return joind_conn

    def init_host(self):
        """ Init OTPme. """
        # Reload config and init OTPme after objects have been added. We need to
        # init in API mode because no daemons are running yet because we may need to
        # modify our node object below.
        config.reload()
        config.use_api = True
        init_otpme()
        config.use_api = False
        # Get our site + CA.
        self._my_site = backend.get_object(object_type="site", uuid=config.site_uuid)
        self._my_site_ca = backend.get_object(object_type="ca", uuid=self._my_site.ca)
        # Get our host.
        self._my_host = backend.get_object(object_type=self.host_type, uuid=config.uuid)

    def get_domain(self, realm=None, site=None, host_fqdn=None):
        """ Get domain from args. """
        # Build search domain from realm/site.
        if site and realm:
            domain = "%s.%s" % (site, realm)
            return domain
        # Try to get search domain from host FQDN.
        domain = ".".join(host_fqdn.split(".")[1:])
        if domain:
            return domain
        msg = (_("Unable to get domain from host FQDN: %s") % host_fqdn)
        raise OTPmeException(msg)

    def complete_args(self, realm=None, site=None,
        host_fqdn=None, domain=None, username=None):
        """ Complete args. """
        # Try to get OTPme realm from command line.
        if realm is None:
            realm = config.connect_realm

        # Try to get OTPme site from command line.
        if site is None:
            site = config.connect_site

        # Get Domain.
        if not domain:
            domain = self.get_domain(realm, site, host_fqdn)

        # Try to get joind URI via DNS.
        socket_uri = net.get_daemon_uri("joind", domain)
        if not socket_uri:
            msg = (_("Unable to resolve joind address for: %s") % domain)
            raise OTPmeException(msg)
        logger.debug("Got joind socket via DNS: %s" % socket_uri)

        # Try to get realm/site we will connect to from DNS.
        try:
            dns_result = net.get_otpme_site(domain)
            dns_realm = dns_result['realm']
            dns_site = dns_result['site']
        except:
            dns_site = None
            dns_realm = None

        # Use realm from DNS if none was given.
        if realm is None:
            realm = dns_realm

        # Use site from DNS if none was given.
        if site is None:
            site = dns_site

        ## Make sure we connect to the correct realm/site.
        #if realm:
        #    if realm != dns_realm:
        #        msg = ("Got wrong realm from DNS: %s" % dns_realm)
        #        raise OTPmeException(msg)
        #if site:
        #    if site != dns_site:
        #        msg = ("Got wrong site from DNS: %s" % dns_site)
        #        raise OTPmeException(msg)

        # Get username.
        if not username:
            if config.login_user:
                username = config.login_user
            else:
                username = config.system_user()

        # Set args.
        self.realm = realm
        self.site = site
        self.username = username
        self.socket_uri = socket_uri

    def set_password_salt(self, join_reply):
        """ Set password hashing salt. """
        password_hash_salt = join_reply['password_hash_salt']
        config.set_password_salt(password_hash_salt)

    def gen_site_ca_req(self, key_len):
        """ Create CSR and key for site CA cert. """
        # Generate CSR.
        site_ca_cert_req, site_ca_key = utils.create_csr(self._my_site_ca.path,
                                                country=self._my_site_ca.country,
                                                state=self._my_site_ca.state,
                                                locality=self._my_site_ca.locality,
                                                organization=self._my_site_ca.organization,
                                                ou=self._my_site_ca.ou,
                                                email=self._my_site_ca.email,
                                                key_len=key_len)
        return site_ca_cert_req, site_ca_key

    def gen_host_cert_req(self, key_len=None):
        """ Generate host cert/key. """
        if key_len is None:
            if self.host_type == "host":
                key_len = config.default_host_key_len
            else:
                key_len = config.default_node_key_len
        # Generate CSR.
        host_cert_req, host_key = utils.create_csr(self._my_host.fqdn,
                                                country=self._my_site_ca.country,
                                                state=self._my_site_ca.state,
                                                locality=self._my_site_ca.locality,
                                                organization=self._my_site_ca.organization,
                                                ou=self._my_site_ca.ou,
                                                email=self._my_site_ca.email,
                                                key_len=key_len)
        return host_cert_req, host_key

    def handle_master_node_stuff(self, join_reply, site_ca_key,
        host_cert_req, password, jotp, conn_kwargs):
        """ Handle stuff only to do for master node join. """
        if not self._my_site_ca.cert or not self._my_site_ca.key:
            # Get CA cert from reply.
            site_ca_cert = join_reply['ca_cert']
            # Make sure CA CRL is empty.
            self._my_site_ca.crl = None
            # Add new cert/key to site CA.
            self._my_site_ca.set_cert(cert=site_ca_cert, key=site_ca_key)
            # Save changes.
            cache.flush()

        # Create site certificate if needed.
        if not self._my_site.cert or not self._my_site.key:
            self._my_site.renew_cert(verify_acls=False)
            # Save changes.
            cache.flush()
            # Update site certificate on remote site.
            logger.debug("Sending site certificate to joind...")
            # Build command.
            #command_args = {}
            #command = "add_site_cert %s" % self._my_host.fqdn
            command = "add_site_cert"
            command_args = {
                            'host_fqdn' : self._my_host.fqdn,
                            'host_type' : self._my_host.type,
                            'site'      : self._my_host.site,
                            }
            # Build request.
            request = {}
            request['command'] = command
            request['host_fqdn'] = self._my_host.fqdn
            request['host_type'] = self._my_host.type
            request['host_name'] = self._my_host.name
            request['site'] = self._my_host.site
            request['cert'] = self._my_site.cert
            request['jotp'] = jotp
            # Try to send site certificate.
            status, \
            status_code, \
            join_reply = self.send(command,
                                command_args,
                                request,
                                **conn_kwargs)
            if not status:
                msg = (_("Sending site certificate failed: %s") % join_reply)
                raise OTPmeException(msg)

        # Enabling site on master node join.
        if not self._my_site.enabled:
            self._my_site.enable(force=True,
                        verify_acls=False,
                        run_policies=False)

        # Add site objects.
        callback = JobCallback(api_mode=True)
        self._my_site.add_base_objects(callback=callback)
        self._my_site.add_base_groups(callback=callback)
        self._my_site.add_per_site_objects(callback=callback)

        # Finish node join and create node cert.
        self._my_host.join_realm(verify_acls=False,
                                cert_req=host_cert_req,
                                finish=True)

        # Reload CA after node cert generation.
        self._my_site_ca = backend.get_object(object_type="ca", uuid=self._my_site.ca)

        logger.debug("Sending CRL to joind...")
        # Build command.
        #command_args = {}
        #command = "add_ca_crl %s" % self._my_host.fqdn
        command = "add_ca_crl"
        command_args = {
                        'host_fqdn' : self._my_host.fqdn,
                        'host_type' : self._my_host.type,
                        'site'      : self._my_host.site,
                        }
        # Build request.
        request = {}
        request['command'] = command
        request['host_fqdn'] = self._my_host.fqdn
        request['host_type'] = self._my_host.type
        request['host_name'] = self._my_host.name
        request['site'] = self._my_host.site
        request['jotp'] = jotp
        request['crl'] = self._my_site_ca.crl
        # Try to send initial CRL.
        status, \
        status_code, \
        join_reply = self.send(command,
                            command_args,
                            request,
                            **conn_kwargs)
        if not status:
            msg = (_("Sending CRL failed: %s") % join_reply)
            raise OTPmeException(msg)

        # Make sure master node is ready.
        config.touch_node_sync_file()

        return self._my_host.cert

    def process_objects(self, join_reply):
        """ Add base objects etc.. """
        # Get base objects from reply.
        object_configs = join_reply['object_configs']

        add_list = {}
        add_order = config.object_add_order

        # Add empty list to add_list dict for each object type.
        for i in add_order: add_list[i] = {}

        msg = ("Processing base objects from joind...")
        message(msg)
        logger.debug(msg)
        # Build list with objects to add grouped by object type.
        for x in object_configs:
            object_id = oid.get(object_id=x)
            object_type = object_id.object_type
            add_list[object_type][object_id.full_oid] = object_id

        # Add base objects.
        my_uuid = None
        #site_oid = oid.get(object_type="site", realm=self.realm, name=self.site)
        for object_type in add_order:
            for x in sorted(add_list[object_type]):
                object_id = add_list[object_type][x]
                object_config = object_configs[object_id.full_oid]
                current_object_config = backend.read_config(object_id)
                if current_object_config:
                    new_checksum = object_config['CHECKSUM']
                    current_checksum = current_object_config['CHECKSUM']
                    if current_checksum == new_checksum:
                        continue
                logger.debug("Adding object: %s" % object_id)
                # Write object to backend.
                try:
                    backend.write_config(object_id=object_id,
                                    full_index_update=True,
                                    full_acl_update=True,
                                    full_ldif_update=True,
                                    object_config=object_config)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Joining %s failed: Error adding object %s: %s")
                            % (self.host_type, object_id, e))
                    raise OTPmeException(msg)
                # Update signers cache.
                if object_type == "user":
                    x_user = backend.get_object(object_type="user",
                                                object_id=object_id)
                    if x_user.public_key:
                        try:
                            sign_key_cache.add_cache(object_id, x_user.public_key)
                        except Exception as e:
                            msg = ("Unable to add signer cache: %s: %s"
                                    % (object_id, e))
                            logger.critical(msg)
                # Enable sync and auth for all sites.
                if object_type == "site":
                    x_site = backend.get_object(object_type="site",
                                                object_id=object_id)
                    if not x_site.sync_enabled:
                        try:
                            x_site.enable_sync(verify_acls=False)
                        except Exception as e:
                            msg = ("Error enabling sync with site: %s: %s"
                                    % (x_site, e))
                            logger.warning(msg)
                    if not x_site.auth_enabled:
                        try:
                            x_site.enable_auth(verify_acls=False)
                        except Exception as e:
                            msg = ("Error enabling auth of site: %s: %s"
                                    % (x_site, e))
                            logger.warning(msg)

                if object_type == self.host_type:
                    object_name = object_id.name
                    #object_realm = object_id.realm
                    #object_site = object_id.site
                    #object_fqdn = "%s.%s.%s" % (object_name,
                    #                            object_site,
                    #                            object_realm)
                    # FIXME: we should add an option "--ignore-fqdn" and check for full FQDN if not given!!
                    #if object_fqdn == self.host_fqdn:
                    if object_name == self.host_name:
                        my_uuid = object_config['UUID']
        if not my_uuid:
            msg = (_("Join reply is missing %s object.") % self.host_type)
            raise OTPmeException(msg)

        msg = ("Writing %s UUID to file: %s" % (self.host_type, config.uuid_file))
        logger.debug(msg)
        try:
            fd = open(config.uuid_file, "w")
            fd.write(my_uuid)
            fd.close()
        except Exception as e:
            msg = (_("Error writing UUID file: %s") % e)
            raise OTPmeException(msg)

    def send_join_request(self, jotp, force, conn_kwargs):
        """ Send initial join request. """
        msg = "Trying to join"
        if self.realm and self.site:
            msg = ("%s %s/%s"
                % (msg, self.realm, self.site))
        else:
            msg = ("%s (%s)"
                % (msg, self.socket_uri))
        message(msg)

        # Build join request.
        join_request = {}
        join_request['jotp'] = jotp
        join_request['site'] = self.site
        join_request['unit'] = self.unit
        join_request['force'] = force
        join_request['command'] = "join"
        join_request['host_type'] = self.host_type
        join_request['host_name'] = self.host_name
        join_request['host_fqdn'] = self.host_fqdn

        # Build join command.
        command_args = {}
        command_args['site'] = self.site
        command_args['host_type'] = self.host_type
        #command = "join %s" % self.host_fqdn
        command_args['host_fqdn'] = self.host_fqdn
        command = "join"

        logger.debug("Sending realm join request...")
        # Send join command.
        status, \
        status_code, \
        join_reply = self.send(command,
                            command_args,
                            join_request,
                            **conn_kwargs)
        if not status:
            msg = (_("Joining %s failed (join request): %s") % (self.host_type, join_reply))
            raise OTPmeException(msg)

        return join_reply

    def send_final_join_request(self, force, conn_kwargs, jotp,
        host_cert=None, host_cert_req=None, site_ca_cert_req=None):
        """ Send final join request. """
        # Build finish join request.
        join_request = {}
        join_request['site'] = self.site
        join_request['unit'] = self.unit
        join_request['force'] = force
        join_request['finish'] = True
        join_request['command'] = "join"
        join_request['host_type'] = self.host_type
        join_request['host_name'] = self.host_name
        join_request['host_fqdn'] = self.host_fqdn
        # Add JOTP to finalize join process.
        join_request['jotp'] = jotp
        # Add site CA CSR to request.
        join_request['site_cert_req'] = site_ca_cert_req
        join_request['host_cert'] = host_cert
        join_request['host_cert_req'] = host_cert_req
        # Add host auth key (public).
        join_request['host_public_key'] = self._my_host.public_key

        # Build join command.
        command_args = {}
        command_args['site'] = self.site
        command_args['host_type'] = self.host_type
        #command = "join %s" % self.host_fqdn
        command_args['host_fqdn'] = self.host_fqdn
        command = "join"
        logger.debug("Sending final realm join request...")
        # Try to finalize realm join.
        status, \
        status_code, \
        join_reply = self.send(command,
                            command_args,
                            join_request,
                            **conn_kwargs)
        if not status:
            msg = (_("Joining %s failed (final join request): %s" ) % (self.host_type, join_reply))
            raise OTPmeException(msg)

        return join_reply

    def join_realm(self, domain=None, realm=None, site=None, host_type="host",
        host_fqdn=None, username=None, password=None, jotp=None,
        host_key_len=None, site_key_len=None, unit=None,
        force=False, trust_site_cert=False, no_daemon_start=False,
        check_site_cert=None, fingerprint_digest=None, create_db_indexes=False):
        """ Join this node/host to realm. """
        if jotp is not None:
            if not isinstance(jotp, str):
                msg = "JOTP needs to be of type str()."
                raise OTPmeException(msg)

        # Set realm join mode.
        config.realm_join = True
        config.use_backend = True
        # Set current action.
        self._current_action = "join"
        # Set host type.
        self.host_type = host_type
        # Set to be checked in transaction.
        config.host_data['type'] = host_type

        # Check host status.
        if config.uuid:
            init_otpme()
            my_host = backend.get_object(object_type=self.host_type, uuid=config.uuid)
            if my_host:
                msg = ("Host is already a realm member.")
                raise OTPmeException(msg)

        # Generate AES master key.
        try:
            config.gen_master_key(skip_if_exists=True)
        except Exception as e:
            msg = (_("Error generating master key: %s") % e)
            raise OTPmeException(msg)

        # Initialize backend (e.g. set file permissions)
        backend.init(init_file_dir_perms=True)

        # Get host FQDN if none was given.
        if not host_fqdn:
            host_fqdn = net.get_host_fqdn()

        # Get hostname from FQDN
        self.host_name = host_fqdn.split(".")[0]
        self.host_fqdn = host_fqdn

        # Complete and set arguments.
        self.complete_args(realm, site, host_fqdn, domain, username)
        # Args to pass to each send() call.
        conn_kwargs = {}
        conn_kwargs['realm'] = self.realm
        conn_kwargs['site'] = self.site
        conn_kwargs['socket_uri'] = self.socket_uri
        conn_kwargs['trust_site_cert'] = trust_site_cert
        conn_kwargs['check_site_cert'] = check_site_cert
        conn_kwargs['fingerprint_digest'] = fingerprint_digest
        conn_kwargs['username'] = self.username
        conn_kwargs['password'] = password
        conn_kwargs['jotp'] = jotp

        if not self.username and not jotp:
            msg = ("Need 'username' or 'jotp' to join realm.")
            raise OTPmeException(msg)

        # With JOTP we can encrypt the join request.
        if jotp:
            # Make sure we encrypt communication from now on.
            self.encrypt_session = True
            # Set hash type to derive session key from JOTP
            self.otp_hash_type = config.join_jotp_hash_type
            # Get encryption key from JOTP.
            x = self.session_enc_algo_mod.derive_key(jotp, hash_type=self.otp_hash_type)
            self.session_key_salt = x['salt']
            self.session_key = x['key']

        # Send initial join request.
        join_reply = self.send_join_request(jotp, force, conn_kwargs)
        # Get master node join status.
        master_node_join = join_reply['master_node_join']
        # Set password hashing salt.
        self.set_password_salt(join_reply)
        # Add base objects etc..
        self.process_objects(join_reply)

        # Init host and load required objects.
        self.init_host()

        # If this is the first node of this site we may need to request a
        # site CA certificate here.
        site_ca_key = None
        site_ca_cert_req = None
        if master_node_join:
            if not self._my_site_ca.cert or not self._my_site_ca.key:
                # Create site CA CSR.
                site_ca_cert_req, site_ca_key = self.gen_site_ca_req(site_key_len)

        # Get host cert/key.
        try:
            host_cert = config.host_data['cert']
        except Exception as e:
            host_cert = None
        try:
            host_key = config.host_data['key']
        except Exception as e:
            host_key = None

        host_cert_req = None
        # Generate new host cert CSR and key if needed.
        if not master_node_join:
            if not host_cert or not host_key:
                host_cert_req, host_key = self.gen_host_cert_req(key_len=host_key_len)

        # Generate host auth key.
        host_private_key = self._my_host.gen_auth_key()

        # Make sure changes get committed.
        self._my_host._cache()
        # Save changes. This must be done before sending final join request
        # go get a newer "last modified" timestamp on peer than on this host.
        cache.flush()

        # Get JOTP to finish realm join.
        finish_jotp = join_reply['jotp']
        # Send final join request.
        join_reply = self.send_final_join_request(force, conn_kwargs,
                                    site_ca_cert_req=site_ca_cert_req,
                                    host_cert_req=host_cert_req,
                                    host_cert=host_cert,
                                    jotp=finish_jotp)

        # Get join message.
        join_message = join_reply['message']

        if master_node_join:
            node_cert_req, host_key = self.gen_host_cert_req(key_len=host_key_len)
            host_cert = self.handle_master_node_stuff(join_reply,
                                                    site_ca_key,
                                                    node_cert_req,
                                                    password, jotp,
                                                    conn_kwargs)

        elif host_cert_req:
            host_cert = join_reply['host_cert']
            self._my_host.cert = host_cert

        self._my_host.enable(force=True,
                            verify_acls=False)
        self._my_host._write()

        # Mark node as new node.
        if host_type == "node":
            filetools.touch(config.node_joined_file)

        # Update nsscache:
        master_site = self._my_site.get_master_site()
        nsscache.update(config.realm, config.site)
        nsscache.update(config.realm, master_site.name)
        # Enable nsscache symlinks.
        nsscache.enable()

        # Update host cert/key files. This must be done after nsscache update
        # because we need the users group available via nsswitch.
        host.update_data(host_cert=host_cert,
                        host_key=host_key,
                        host_auth_key=host_private_key)

        # Close all connections.
        connections.close_connections()

        # Start OTPme daemons.
        if not no_daemon_start:
            msg = "Starting OTPme daemons..."
            message(msg)
            stuff.start_otpme_daemon()

        # Make sure DB indices are created after adding all objects.
        if create_db_indexes:
            _index = config.get_index_module()
            if _index.is_available():
                msg = "Creating DB indexes..."
                message(msg)
                _index.command("create_db_indices")

        # FIXME: wait for  sync of authorized_key (the last sync????) to finish????
        #       - make this an option???

        return join_message

    def leave_realm(self, domain=None, host_type="host", username=None,
        password=None, lotp=None, keep_host=False, keep_data=False,
        keep_cache=None, keep_cert=None, keep_auth_key=None,
        offline=False, socket_uri=None):
        """ Leave realm. """
        if not os.path.exists(config.uuid_file):
            msg = ("Host is not a realm member.")
            raise OTPmeException(msg)

        if lotp is not None:
            if not isinstance(lotp, str):
                msg = "LOTP needs to be of type str()."
                raise OTPmeException(msg)

        self.host_type = host_type
        self._current_action = "leave"

        # Make sure we use API for all actions when called with offline=True.
        if offline:
            config.use_api = True

        # Check for master node.
        if not offline:
            init_otpme()
            if config.master_node:
                msg = ("Master node cannot leave realm.")
                raise OTPmeException(msg)

        reply = ""
        # Set realm join mode.
        config.realm_join = True
        config.use_backend = True

        # Set default values.
        if keep_data:
            keep_cert = True
            keep_cache = True
        if keep_cert is None:
            keep_cert = False
        if keep_cache is None:
            keep_cache = False
        if keep_auth_key is None:
            keep_auth_key = False

        if not username:
            if config.login_user:
                username = config.login_user
            else:
                username = config.system_user()

        if not offline and (not username and not lotp):
            msg = ("Need 'username' or 'lotp' to leave realm.")
            raise OTPmeException(msg)

        # Stop OTPme agents.
        for pid in stuff.get_pid_by_name("otpme-agent"):
            stuff.kill_pid(pid, kill_timeout=10)

        if not offline:
            # Get hosts FQDN.
            self.host_fqdn = config.host_data['fqdn']
            # Get hostname from FQDN
            self.host_name = self.host_fqdn.split(".")[0]

            # Get realm to leave if no domain was given.
            if not domain:
                domain = config.realm

            logger.debug("Trying to get master node via DNS...")
            # Try to get joind URI via DNS.
            if not socket_uri:
                socket_uri = net.get_daemon_uri("joind", domain)
            if not socket_uri:
                msg = (_("Unable to resolve domain: %s") % domain)
                raise OTPmeException(msg)

            # With LOTP we can encrypt the leave request.
            if lotp:
                # Make sure we encrypt communication from now on.
                self.encrypt_session = True
                # Set hash type to derive session key from LOTP
                self.otp_hash_type = config.join_lotp_hash_type
                # Get encryption key from LOTP.
                x = self.session_enc_algo_mod.derive_key(lotp, hash_type=self.otp_hash_type)
                self.session_key_salt = x['salt']
                self.session_key = x['key']

            # Args to pass to each send() call.
            conn_kwargs = {}
            conn_kwargs['lotp'] = lotp
            conn_kwargs['username'] = username
            conn_kwargs['password'] = password
            conn_kwargs['socket_uri'] = socket_uri
            conn_kwargs['realm'] = config.realm
            conn_kwargs['site'] = config.site

            # Build leave command.
            #command_args = {}
            #command = "leave %s" % self.host_fqdn
            command_args = {'host_fqdn':self.host_fqdn}
            command = "leave"
            # Build request.
            leave_request = {}
            leave_request['lotp'] = lotp
            leave_request['command'] = "leave"
            leave_request['host_type'] = self.host_type
            leave_request['host_name'] = self.host_name
            leave_request['host_fqdn'] = self.host_fqdn
            leave_request['keep_cert'] = keep_cert
            leave_request['keep_host'] = keep_host

            logger.debug("Sending realm leave request...")
            # Send leave command.
            status, \
            status_code, \
            reply = self.send(command, command_args, leave_request, **conn_kwargs)

            if not status:
                msg = (_("Failed to leave realm: %s") % reply)
                raise OTPmeException(msg)

        # Close all connections.
        connections.close_connections()

        # Make sure index is stopped.
        _index = config.get_index_module()
        if _index.need_start:
            if _index.status():
                _index.stop()
        # Make sure cache is stopped.
        _cache = config.get_cache_module()
        if _cache.status():
            _cache.stop()

        # Remove realm data.
        remove_files = [
                    config.ssl_site_cert_file,
                    config.ssl_ca_file,
                    ]

        remove_dirs = [
                    config.data_dir,
                    config.cache_dir,
                    config.spool_dir,
                    ]

        if not keep_data:
            if not keep_cache:
                # Remove nsscache symlinks.
                nsscache.disable()
                remove_dirs.append(config.cache_dir)

            if not keep_cert:
                remove_files.append(config.ssl_key_file)
                remove_files.append(config.ssl_cert_file)

            if not keep_auth_key:
                remove_files.append(config.host_key_file)

            # Remove data from backend.
            backend.drop()

            for x in remove_files:
                logger.debug("Removing file: %s" % x)
                if not os.path.exists(x):
                    continue
                try:
                    os.remove(x)
                except Exception as e:
                    msg = (_("Error removing file: %s") % e)
                    raise OTPmeException(msg)

            for x in remove_dirs:
                logger.debug("Removing dir: %s" % x)
                if not os.path.exists(x):
                    continue
                try:
                    shutil.rmtree(x)
                except Exception as e:
                    msg = (_("Error removing dir: %s") % e)
                    raise OTPmeException(msg)

        if os.path.exists(config.uuid_file):
            logger.debug("Removing UUID file: %s" % config.uuid_file)
            try:
                os.remove(config.uuid_file)
            except Exception as e:
                msg = (_("Error removing UUID file: %s") % e)
                raise OTPmeException(msg)

        return reply
