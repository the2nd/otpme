# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.pki import utils
from otpme.lib.classes.ca import Ca
from otpme.lib.pki.cert import SSLCert
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.classes.otpme_object import OTPmeClientObject
from otpme.lib.classes.otpme_object import run_pre_post_add_policies

from otpme.lib.classes.otpme_object import \
                        get_acls as _get_acls
from otpme.lib.classes.otpme_object import \
                        get_value_acls as _get_value_acls
from otpme.lib.classes.otpme_object import \
                        get_default_acls as _get_default_acls
from otpme.lib.classes.otpme_object import \
                        get_recursive_default_acls as _get_recursive_default_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

read_acls = []

write_acls = [
                "join",
                "leave",
                "limit_logins",
                "unlimit_logins",
            ]

read_value_acls = {
                "view"      : [
                                "roles",
                                "tokens",
                                "key",
                                "cert",
                                "jotp",
                                "lotp",
                                "jotp_rejoin",
                                "policy",
                                "groups",
                                ],
            }

write_value_acls = {
                "add"       : [
                                "role",
                                "token",
                                "group",
                                ],
                "remove"    : [
                                "role",
                                "token",
                                "group",
                                ],
                "edit"      : [
                                "public_key",
                                ],
                "enable"    : [
                                "jotp",
                                "lotp",
                                "jotp_rejoin",
                                ],
                "disable"   : [
                                "jotp",
                                "lotp",
                                "jotp_rejoin",
                                 ],
                "renew"     : [ "cert" ],
                "revoke"    : [ "cert" ],
}

default_acls = []

recursive_default_acls = []

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(**kwargs):
    return _get_value_acls(read_value_acls, write_value_acls, **kwargs)

def get_default_acls(**kwargs):
    return _get_default_acls(default_acls, **kwargs)

def get_recursive_default_acls(**kwargs):
    return _get_recursive_default_acls(recursive_default_acls, **kwargs)

class OTPmeHost(OTPmeClientObject):
    """ Generic OTPme host object """
    def __init__(self, object_id=None, name=None, path=None,
        unit=None, realm=None, site=None, **kwargs):
        # Call parent class init.
        super(OTPmeHost, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        unit=unit,
                                        name=name,
                                        path=path,
                                        **kwargs)
        # Set some default values.
        self.acl_inheritance_enabled = False
        # Host join status.
        self.joined = False
        self.jotp = None
        self.lotp = None
        self.jotp_enabled = True
        self.lotp_enabled = True
        self.allow_jotp_rejoin = False
        self.public_key = None
        self.join_date = None
        self.join_node = None
        self.join_node_cache = None
        self.join_token = None
        self.join_token_cache  = None
        self.private_key = None

    def _get_object_config(self, object_config=None):
        """ Get object config dict """
        base_config = {
                        'PUBLIC_KEY'                : {
                                                        'var_name'  : 'public_key',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },

                        'ROLES'                     : {
                                                        'var_name'  : 'roles',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'TOKENS'                    : {
                                                        'var_name'  : 'tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'TOKEN_OPTIONS'             : {
                                                        'var_name'  : 'token_options',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },

                        'TOKEN_LOGIN_INTERFACES'    : {
                                                        'var_name'  : 'token_login_interfaces',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },

                        'JOINED'                      : {
                                                        'var_name'  : 'joined',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'JOTP'                      : {
                                                        'var_name'  : 'jotp',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },

                        'LOTP'                      : {
                                                        'var_name'  : 'lotp',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },

                        'JOTP_ENABLED'         : {
                                                        'var_name'  : 'jotp_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'LOTP_ENABLED'         : {
                                                        'var_name'  : 'lotp_enabled',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'ALLOW_JOTP_REJOIN'         : {
                                                        'var_name'  : 'allow_jotp_rejoin',
                                                        'type'      : bool,
                                                        'required'  : False,
                                                    },

                        'JOIN_DATE'                 : {
                                                        'var_name'  : 'join_date',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        'JOIN_JODE'                 : {
                                                        'var_name'  : 'join_node',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'JOIN_JODE_CACHE'           : {
                                                        'var_name'  : 'join_node_cache',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'JOIN_TOKEN'                 : {
                                                        'var_name'  : 'join_token',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'JOIN_TOKEN_CACHE'          : {
                                                        'var_name'  : 'join_token_cache',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        }

        _object_config = {}
        # Merge child config with base host config.
        for i in base_config:
            if i in object_config:
                conf = object_config[i]
                object_config.pop(i)
            else:
                conf = base_config[i]
                _object_config[i] = conf

        for i in object_config:
            _object_config[i] = object_config[i]

        return super(OTPmeHost, self)._get_object_config(object_config=_object_config)

    @property
    def fqdn(self):
        """ Set instance variables. """
        fqdn = "%s.%s.%s" % (self.name, self.site, self.realm)
        return fqdn

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()

    def get_sync_parameters(self, realm, site, peer_uuid):
        """ Get data to build sync list. """
        # Get peer.
        peer = backend.get_object(uuid=peer_uuid)
        if not peer:
            msg = "Unknown peer: %s" % peer_uuid
            raise OTPmeException(msg)
        # Objects not to sync.
        skip_admin = True
        include_templates = False
        skip_per_site_users = True
        skip_internal_users = True
        # Get sync object types.
        sync_object_types = config.get_sync_object_types(host_type=self.type)
        valid_object_types = list(sync_object_types)
        result = backend.search(object_type="site",
                                realm=realm,
                                attribute="name",
                                value=site,
                                return_type="instance")
        if not result:
            msg = "Unknown site: %s" % site
            raise OTPmeException(msg)

        _site = result[0]

        if self.type == "node":
            if peer.type == "node":
                # Check if peer is node from ours site.
                if _site.uuid == self.site_uuid:
                    skip_admin = False
                    include_templates = True
                    skip_per_site_users = False
                    skip_internal_users = False
                else:
                    skip_admin = True
                    include_templates = False
                    skip_per_site_users = True
                    skip_internal_users = True
        if self.type == "host":
            # Check if peer is host from our site
            if peer.type == "host":
                if peer.site_uuid == self.site_uuid:
                    skip_admin = False
                    include_templates = False
                    skip_per_site_users = False
                    skip_internal_users = True
                else:
                    msg = "Host is from wrong site."
                    raise OTPmeException(msg)
        skip_users = []
        if skip_per_site_users:
            skip_users += list(config.get_per_site_objects("user"))
        if skip_internal_users:
            skip_users += config.get_internal_objects("user")
        skip_users = list(set(skip_users))

        # Build sync parameters.
        sync_params = {
                    'realm'                 : realm,
                    'site'                  : site,
                    'skip_list'             : [],
                    'skip_admin'            : skip_admin,
                    'skip_users'            : skip_users,
                    'include_uuids'         : [],
                    'object_types'          : sync_object_types,
                    'include_templates'     : include_templates,
                    'valid_object_types'    : valid_object_types,
                    }
        return sync_params

    def get_ssh_authorized_keys(self, user=None, verbose_level=0,
        _caller="API", callback=default_callback, **kwargs):
        """ Get authorized keys from all valid SSH tokens. """
        possible_tokens = {}
        if _caller == "API":
            authorized_keys = {}
        else:
            authorized_keys = []

        # Get user UUID if user is given.
        user_uuid = None
        if user:
            result = backend.search(object_type="user",
                                            attribute="name",
                                            value=user,
                                            return_type="uuid")
            if not result:
                msg = "Unknown user: %s" % user
                return callback.error(msg)
            user_uuid = result[0]

        token_types = ['ssh', 'link']
        valid_tokens = self.get_tokens(token_types=token_types,
                                    user_uuid=user_uuid,
                                    include_roles=True,
                                    include_options=True,
                                    return_type="uuid")
        # Get realm accessgroup.
        if not self.logins_limited:
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=config.realm_access_group,
                                    return_type="instance",
                                    realm=config.realm,
                                    site=self.site)
            if not result:
                msg = (_("Unable to find realm accessgroup: %s")
                        % config.realm_access_group)
                raise OTPmeException(msg)

            realm_access_group = result[0]
            ag_tokens = realm_access_group.get_tokens(token_types=token_types,
                                                        user_uuid=user_uuid,
                                                        include_roles=True,
                                                        include_options=True,
                                                        return_type="uuid")
            for token_uuid in ag_tokens:
                if token_uuid in valid_tokens:
                    continue
                valid_tokens[token_uuid] = ag_tokens[token_uuid]

        for token_uuid in valid_tokens:
            # Get token.
            token = backend.get_object(object_type="token",
                                        uuid=token_uuid)
            # Get user from token owner.
            user = backend.get_object(object_type="user",
                                    uuid=token.owner_uuid)
            if not user:
                continue
            try:
                token_options = valid_tokens[token.uuid]['token_options']
            except:
                token_options = {}
            if not user.uuid in possible_tokens:
                possible_tokens[user.uuid] = {}
            entry = {token.uuid : [user, token, token_options]}
            possible_tokens[user.uuid].update(entry)

        if not possible_tokens:
            return callback.ok(authorized_keys)

        # Check all tokens.
        processed_tokens = []
        for user_name in possible_tokens:
            for token_uuid in possible_tokens[user_name]:
                user = possible_tokens[user_name][token_uuid][0]
                token = possible_tokens[user_name][token_uuid][1]
                try:
                    token_options = possible_tokens[user_name][token_uuid][2]
                except:
                    token_options = {}

                # Check if token is authorized for SSH login to this host.
                try:
                    self.authorize_token(token, login_interface="ssh")
                except OTPmeException as e:
                    msg = ("Not adding unauthorized SSH token: %s: %s"
                            % (token, e))
                    logger.debug(msg)
                    continue
                except Exception as e:
                    msg = ("Failed to authorize SSH token: %s: %s"
                            % (token, e))
                    logger.debug(msg)
                    continue

                # Make sure we check destination token for linked tokens.
                verify_token = token
                if token.destination_token:
                    verify_token = token.get_destination_token()
                    if not verify_token:
                        continue
                    # Skip disabled destination tokens.
                    if not verify_token.enabled:
                        continue

                # Skip non-SSH tokens.
                if verify_token.token_type != "ssh":
                    continue

                # Skip SSH token without public key.
                if not verify_token.ssh_public_key:
                    msg = ("Ignoring SSH token without public key: %s"
                            % verify_token.rel_path)
                    logger.debug(msg)
                    continue

                entry = {
                        'user_uuid'         : user.uuid,
                        'token_path'        : token.rel_path,
                        'token_options'     : token_options,
                    }

                if token.uuid in processed_tokens:
                    continue
                processed_tokens.append(token.uuid)

                if _caller == "API":
                    authorized_keys[token.uuid] = entry
                else:
                    key_str = "ssh-%s %s" % (token.key_type, token.ssh_public_key)
                    if token_options:
                        key_str = "%s %s" % (token_options, key_str)
                    if not user_uuid:
                        key_str = "%s %s" % (user.name, key_str)
                    authorized_keys.append(key_str)

        if _caller != "API":
            authorized_keys = "\n".join(authorized_keys)

        return callback.ok(authorized_keys)

    @check_acls(['enable:jotp'])
    @object_lock()
    @backend.transaction
    def enable_jotp(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable JOTP usage. """
        if self.jotp_enabled:
            return callback.error(_("JOTP already enabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_jotp",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.jotp_enabled = True
        if not self.jotp:
            self.jotp = self.gen_jotp()
        msg = ("You can use the following JOTP to join the %s: %s"
                % (self.type, self.jotp))
        callback.send(msg)
        return self._cache(callback=callback)

    @check_acls(['disable:jotp'])
    @object_lock()
    @backend.transaction
    def disable_jotp(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable JOTP usage. """
        if not self.jotp_enabled:
            return callback.error(_("JOTP already disabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_jotp",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.jotp_enabled = False
        return self._cache(callback=callback)

    @check_acls(['enable:lotp'])
    @object_lock()
    @backend.transaction
    def enable_lotp(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable LOTP usage. """
        if self.lotp_enabled:
            return callback.error(_("LOTP already enabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_lotp",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.lotp_enabled = True
        if not self.lotp:
            self.lotp = self.gen_jotp()
        msg = ("You can use the following LOTP to join the %s: %s"
                % (self.type, self.lotp))
        callback.send(msg)
        return self._cache(callback=callback)

    @check_acls(['disable:lotp'])
    @object_lock()
    @backend.transaction
    def disable_lotp(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable LOTP usage. """
        if not self.lotp_enabled:
            return callback.error(_("LOTP already disabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_lotp",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.lotp_enabled = False
        return self._cache(callback=callback)

    @check_acls(['enable:jotp_rejoin'])
    @object_lock()
    @backend.transaction
    def enable_jotp_rejoin(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable JOTP rejoining. """
        if self.allow_jotp_rejoin:
            return callback.error(_("LOTP rejoin already enabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_jotp_rejoin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.allow_jotp_rejoin = True
        if not self.jotp:
            self.jotp = self.gen_jotp()
        msg = ("You can use the following JOTP to (re-)join the %s: %s"
                % (self.type, self.jotp))
        callback.send(msg)
        return self._cache(callback=callback)

    @check_acls(['disable:jotp_rejoin'])
    @object_lock()
    @backend.transaction
    def disable_jotp_rejoin(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable JOTP rejoining. """
        if not self.allow_jotp_rejoin:
            return callback.error(_("LOTP rejoin already disabled."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_jotp_rejoin",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.allow_jotp_rejoin = False
        self.jotp = None
        return self._cache(callback=callback)

    @check_acls(['edit:public_key'])
    @object_lock(full_lock=True)
    @backend.transaction
    def change_public_key(self, public_key=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change host public key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_public_key",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        # Check if we got SSH public key as argument.
        if public_key is None:
            public_key = callback.ask("Please enter/paste public key: ")
        if public_key:
            self.public_key = public_key
        else:
            self.public_key = None

        return self._cache(callback=callback)

    @check_acls(['revoke:cert'])
    @object_lock(full_lock=True)
    @backend.transaction
    def revoke_cert(self, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Revoke our certificate. """
        if self.cert is None:
            return callback.error("Host does not have a certificate.")
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("revoke_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        issuer = utils.get_issuer(self.cert)
        try:
            ca = Ca(path=issuer)
        except Exception as e:
            msg = (_("Unable to load issuer CA: %s") % issuer)
            return callback.error(msg)
        if not ca.exists():
            msg = (_("Unknown issuer CA: %s") % issuer)
            return callback.error(msg)

        # Try to revoke our certificate.
        try:
            ca.revoke_cert(cert=self.cert,
                            verify_acls=False,
                            _caller=_caller,
                            callback=callback)
        except CertAlreadyRevoked as e:
            if _caller == "API":
                raise
            else:
                return callback.error(str(e))
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to revoke certificate: %s") % e)
            return callback.error(msg)

        self.cert = None

        return self._cache(callback=callback)

    @check_acls(['renew:cert'])
    @object_lock(full_lock=True)
    @backend.transaction
    def renew_cert(self, cert_req, cert_valid=None, run_policies=True,
        verbose_level=0, _caller="API", callback=default_callback, **kwargs):
        """ Renew our certificate. """
        # Make sure we got a CSR with the correct FQDN.
        try:
            utils.verify_cn(self.fqdn, csr=cert_req)
        except Exception as e:
            config.raise_exception()
            msg = "Certificate request error: %s" % e
            logger.warning(msg)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("renew_cert",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        if cert_valid is None:
            if self.type == "host":
                cert_valid = config.default_host_validity
            if self.type == "node":
                cert_valid = config.default_node_validity

        # Load site CA.
        site = backend.get_object(object_type="site", uuid=config.site_uuid)
        site_ca = backend.get_object(object_type="ca", uuid=site.ca)
        if not site_ca:
            msg = (_("Problem loading site CA '%s'.")
                    % config.site_ca_path)
            return callback.error(msg)

        msg = (_("Generating new certificate..."))
        logger.debug(msg)
        if verbose_level > 0:
            callback.send(msg)
            # Wait a moment before starting CPU intensive job to prevent delay
            # when transmitting above message to user.
            time.sleep(0.01)

        # Try to renew our cert.
        try:
            cert, \
            key = site_ca.create_host_cert(cn=self.fqdn,
                                        host_type=self.type,
                                        valid=cert_valid,
                                        cert_req=cert_req,
                                        verify_acls=False,
                                        callback=callback,
                                        _caller=_caller)
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to create new certificate: %s") % e)
            return callback.error(msg)

        # Revoke old cert.
        if self.cert:
            try:
                self.revoke_cert(verify_acls=False,
                                callback=callback,
                                _caller=_caller)
            except CertAlreadyRevoked:
                pass
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        # Set new cert.
        self.cert = cert

        self._cache(callback=callback)

        return key, cert

    def gen_jotp(self):
        """ Gen realm join/leave OTP. """
        if self.type == "host":
            jotp_len = config.host_jotp_len
        if self.type == "node":
            jotp_len = config.node_jotp_len
        jotp = stuff.gen_secret(jotp_len)
        return jotp

    @object_lock(full_lock=True)
    @backend.transaction
    def gen_auth_key(self, callback=default_callback, **kwargs):
        """ Generate host auth key pair. """
        _host_key = RSAKey(bits=config.default_host_auth_key_len)
        self.public_key = _host_key.public_key_base64
        private_key = _host_key.private_key_base64
        self._cache(callback=callback)
        return private_key

    def load_auth_key(self, private=False):
        """ Load host auth key. """
        if private:
            msg = (_("Unable to load %s auth key: This is not %s %s")
                    % (self.type, self.type, self.fqdn))
            if self.name != config.host_data['name']:
                raise OTPmeException(msg)
            if self.realm != config.host_data['realm']:
                raise OTPmeException(msg)
            if self.site != config.host_data['site']:
                raise OTPmeException(msg)
        key_type = "public"
        if private:
            key_type = "private"
        msg = ("Loading %s %s auth key." % (self.type, key_type))
        if config.debug_level() > 3:
            logger.debug(msg)
        try:
            if private:
                auth_key = config.host_data['auth_key']
            else:
                auth_key = self.public_key
            auth_key = RSAKey(key=auth_key)
        except Exception as e:
            msg = (_("Failed to load %s auth key.") % self.type)
            raise OTPmeException(msg)
        return auth_key

    def gen_challenge(self):
        """ Generate host authentication challenge. """
        if config.debug_level() > 3:
            logger.debug("Generating %s auth challenge." % self.type)
        epoch_time = str(int(time.time()))
        nonce = stuff.gen_secret(len=32)
        challenge = "%s:%s" % (epoch_time, nonce)
        return challenge

    def sign_challenge(self, challenge):
        """ Sign authentication challenge. """
        auth_key = self.load_auth_key(private=True)
        if config.debug_level() > 3:
            logger.debug("Signing %s auth challenge." % self.type)
        response = auth_key.sign(challenge)
        response = encode(response, "hex")
        return response

    def verify_challenge(self, challenge, response):
        """ Verify authentication challenge/response. """
        auth_key = self.load_auth_key()
        response = decode(response, "hex")
        if config.debug_level() > 3:
            logger.debug("Verifying %s auth challenge." % self.type)
        # Verify challenge/response.
        if auth_key.verify(response, challenge):
            epoch_time = int(time.time())
            challenge_time = int(challenge.split(":")[0])
            challenge_age = epoch_time - challenge_time
            # FIXME: Make max challenge age an option!!!?
            max_callenge_age = 5
            if challenge_age <= max_callenge_age:
                return True
            msg = "Challenge too old: %s (%ss)" % (self.fqdn, challenge_age)
            logger.warning(msg)
            return False
        msg = "Challenge verification failed: %s" % self.fqdn
        logger.warning(msg)
        return False

    @check_acls(['join'])
    @object_lock(full_lock=True)
    @backend.transaction
    def join_realm(self, finish=False, cert=None, cert_req=None, public_key=None,
        cert_valid=None, run_policies=True, verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Make host join the realm (e.g. create certs, gen LOTP etc.). """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("join",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Add cert if we got one.
        if cert:
            # Load cert.
            _cert = SSLCert(cert=cert)
            # Check CN.
            cert_cn = _cert.get_cn()
            if cert_cn != self.fqdn:
                msg = (_("Certificate error: CN does not match FQDN: %s: %s")
                        % (self.fqdn, cert_cn))
                logger.warning(msg)
                return callback.error(msg)
            # Check if its a revoked cert.
            issuer_cn = _cert.get_issuer()
            issuer_ca = Ca(path=issuer_cn)
            if not issuer_ca.exists():
                msg = (_("Certificate issued by unknown CA: %s: %s")
                            % (issuer_cn, cert_cn))
                raise CertVerifyFailed(msg)

            cert_serial = _cert.get_serial()
            if utils.check_crl(issuer_ca.crl, cert_serial):
                msg = (_("Certificate revoked by CA: %s: %s: %s")
                        % (issuer_cn, cert_cn, cert_serial))
                raise CertVerifyFailed(msg)

            # Set cert.
            self.cert = cert

        # Create new host cert if needed.
        if cert_req:
            try:
                host_key, \
                host_cert = self.renew_cert(cert_req=cert_req,
                                            cert_valid=cert_valid,
                                            verify_acls=False,
                                            callback=callback)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        self.join_date = time.time()
        self.join_node = config.uuid
        join_node = backend.get_object(uuid=config.uuid)
        self.join_node_cache = join_node.oid.read_oid
        if config.auth_token:
            self.join_token = config.auth_token.uuid
            self.join_token_cache = config.auth_token.oid.read_oid

        if finish:
            # Set host join status.
            self.joined = True
            # Remove JOTP from host.
            self.jotp = None
            # Add LOTP to host.
            self.lotp = self.gen_jotp()
            # Set hosts public key.
            if public_key:
                self.public_key = public_key
            # Write changes.
            return self._write(callback=callback)

        # Add JOTP to host.
        if not self.jotp:
            self.jotp = self.gen_jotp()

        # Write changes.
        return self._write(callback=callback)

    @check_acls(['leave'])
    @object_lock(full_lock=True)
    @backend.transaction
    def leave_realm(self, keep_cert=False, keep_auth_key=False,
        run_policies=True, callback=default_callback, verbose_level=0,
        _caller="API", **kwargs):
        """ Make host leave the realm (e.g. revoke certs, gen JOTP etc.). """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("leave",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        # Revoke host cert.
        if not keep_cert and self.cert:
            try:
                self.revoke_cert(verify_acls=False,
                                callback=callback)
            except CertAlreadyRevoked:
                pass
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Add new JOTP to host.
        self.jotp = self.gen_jotp()
        # Set host join status.
        self.joined = False
        # Remove LOTP.
        self.lotp = None
        # Remove host public key.
        self.public_key = None

        return self._write(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, gen_jotp=True, cert_req=None, cert_valid=None,
        public_key=None, enabled=False, callback=default_callback,
        verbose_level=0, **kwargs):
        """ Add a host. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(check_exists=False,
                                    callback=callback,
                                    **kwargs)
        if result is False:
            return callback.error()

        # Check if host/node with our name exists.
        result = []
        for x in ['host', 'node']:
            result += backend.search(attribute="name",
                                    value=self.name,
                                    object_type=x,
                                    return_type="oid",
                                    realm=self.realm,
                                    site=self.site)
        if result:
            for object_id in result:
                object_type = object_id.object_type
                if object_type in [ 'node', 'host' ]:
                    return callback.error(_("%(object_type)s already exists: "
                                            "%(object_id)s")
                                            % {"object_type":object_type,
                                            "object_id":object_id})
        # Set host auth key.
        self.public_key = public_key

        # Gen JOTP.
        if gen_jotp:
            self.jotp = self.gen_jotp()
            msg = ("You can use the following JOTP to join the %s: %s"
                    % (self.type, self.jotp))
            callback.send(msg)

        # Set FQDN etc.
        self.set_variables()

        # Create host cert.
        if cert_req:
            self.renew_cert(cert_req=cert_req,
                            valid=cert_valid,
                            verify_acls=False,
                            callback=callback)

        # Add join/leave ACLs to the user that creates this host.
        if config.auth_token:
            if not config.auth_token.is_admin():
                if not self.add_acl(acl="join", owner_uuid=config.auth_token.uuid,
                                    verify_acls=False, apply_default_acls=False,
                                    callback=callback, **kwargs):
                    msg = (_("Unable to add ACL 'join' to new %s.") % self.type)
                    callback.send(msg)
                if not self.add_acl(acl="leave", owner_uuid=config.auth_token.uuid,
                                    verify_acls=False, apply_default_acls=False,
                                    callback=callback, **kwargs):
                    msg = (_("Unable to add ACL 'leave' to new %s.") % self.type)
                    callback.send(msg)

        # Add object using parent class.
        return super(OTPmeHost, self).add(enabled=enabled,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, force=False, run_policies=True, verify_acls=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete host. """
        if not self.exists():
            return callback.error("Host does not exist exists.")

        if self.uuid == config.uuid and not force:
            return callback.error("Cannot delete ourselves.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if not force:
            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = "Please type '%s' to delete object: " % self.name
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    msg = (_("Delete %(object_type)s '%(object_name)s'?: ")
                            % { "object_type":self.type,
                            "object_name":self.name})
                    answer = callback.ask(msg)
                    if answer.lower() != "y":
                        return callback.abort()

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if config.get_master_node() == self.name:
            msg = "Cannot delete master node."
            return callback.error(msg)

        # Revoke host cert.
        if self.cert:
            try:
                self.revoke_cert(verify_acls=False,
                                callback=callback)
            except CertAlreadyRevoked:
                pass
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove sessions of this host/node.
        result = backend.search(object_type="session",
                                attribute="client",
                                value=self.name,
                                return_type="instance")
        for session in result:
            session.delete(callback=callback, force=True)

        # Delete object using parent class.
        return super(OTPmeHost, self).delete(verbose_level=verbose_level,
                                    force=force, callback=callback)

    @check_acls(['remove:orphans'])
    @object_lock()
    def remove_orphans(self, force=False, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Remove orphan UUIDs. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_orphans",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        acl_list = self.get_orphan_acls()
        policy_list = self.get_orphan_policies()

        token_list = []
        token_uuids = list(self.tokens) + list(self.token_options)
        token_uuids = list(set(token_uuids))
        for i in token_uuids:
            token_oid = backend.get_oid(object_type="token", uuid=i)
            if not token_oid:
                token_list.append(i)

        if not force:
            msg = ""
            if acl_list:
                msg = (_("%s|%s: Found the following orphan ACLs: %s\n")
                    % (msg, self.type, self.name, ",".join(acl_list)))

            if policy_list:
                msg = ""
                if policy_list:
                    msg = (_("%s|%s: Found the following orphan policies: %s\n")
                        % (msg, self.type, self.name, ",".join(policy_list)))

            if token_list:
                msg = (_("%s|%s: Found the following orphan token UUIDs: %s\n")
                    % (msg, self.type, self.name, ",".join(token_list)))

        object_changed = False
        if acl_list:
            if self.remove_orphan_acls(force=True, verbose_level=verbose_level,
                                                callback=callback, **kwargs):
                object_changed = True

        if policy_list:
            if self.remove_orphan_policies(force=True, verbose_level=verbose_level,
                                                callback=callback, **kwargs):
                object_changed = True

        for i in token_list:
            if verbose_level > 0:
                callback.send(_("Removing orphan token UUID: %s") % i)
            object_changed = True
            if i in self.tokens:
                self.tokens.remove(i)
            if i in self.token_options:
                self.token_options.pop(i)

        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = (_("No orphan objects found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def show_config(self, config_lines=[],
        callback=default_callback, **kwargs):
        lines = []
        lines += config_lines
        join_date = None
        if self.join_date:
            join_date = datetime.datetime.fromtimestamp(self.join_date)
        lines.append('JOIN_DATE="%s"' % join_date)
        join_node = None
        if self.join_node:
            join_node = backend.get_object(uuid=self.join_node)
            if not join_node:
                join_node = self.join_node_cache
        lines.append('JOIN_NODE="%s"' % join_node)
        join_token = None
        if self.join_token:
            join_token = backend.get_object(uuid=self.join_token)
            if not join_token:
                join_token = self.join_token_cache
        lines.append('JOIN_TOKEN="%s"' % join_token)
        return super(OTPmeHost, self).show_config(config_lines=lines,
                                    callback=callback, **kwargs)

    def show(self, **kwargs):
        """ Show host details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
