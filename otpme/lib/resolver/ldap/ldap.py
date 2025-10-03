# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import ldap3

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.resolver import Resolver
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.unit import register_subtype_add_acl
from otpme.lib.classes.unit import register_subtype_del_acl

from otpme.lib.classes.resolver \
            import get_acls \
            as _get_acls
from otpme.lib.classes.resolver \
            import get_value_acls \
            as _get_value_acls
from otpme.lib.classes.resolver \
            import get_default_acls \
            as _get_default_acls
from otpme.lib.classes.resolver \
            import get_recursive_default_acls \
            as _get_recursive_default_acls

from otpme.lib.exceptions import *

default_callback = config.get_callback()

logger = config.logger

RESOLVER_TYPE = "ldap"

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "ldap_server",
                            "ldap_base",
                            "login_dn",
                            "login_password",
                            ],
            }

write_value_acls = {
                "add"      : [
                            "ldap_server",
                            "ldap_filter",
                            "attribute_mapping",
                            ],
                "del"      : [
                            "ldap_server",
                            "ldap_filter",
                            "attribute_mapping",
                            ],
                "edit"      : [
                            "ldap_base",
                            "login_dn",
                            "login_password",
                            ],
                }

default_acls = [
                f'unit:add:resolver:{RESOLVER_TYPE}',
                f'unit:del:resolver:{RESOLVER_TYPE}',
            ]

recursive_default_acls = default_acls

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['ldap_template'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'key_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_attribute',
                    'args'              : ['object_type', 'key_attribute'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'ldap_base'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_ldap_base',
                    'args'              : ['ldap_base'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'login_dn'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_dn',
                    'args'              : ['login_dn'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'login_password'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_login_password',
                    'args'              : ['login_password'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_server'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_server',
                    'args'              : ['server_uri'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_server'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_server',
                    'args'               : ['server_uri'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_ldap_filter'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_filter',
                    'args'              : ['object_type', 'ldap_filter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_ldap_filter'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_filter',
                    'args'              : ['object_type', 'ldap_filter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_ldap_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_attribute_mapping',
                    'args'              : ['object_type', 'src_attr'],
                    'oargs'             : ['dst_attr'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'del_ldap_attribute'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_attribute_mapping',
                    'args'              : ['object_type', 'src_attr'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

templates = {
                'openldap' : {
                        'ldap_filters' : {
                                        'user'  : ['(&(objectclass=posixAccount)(objectclass=inetOrgPerson))'],
                                        'group' : ['(objectclass=posixGroup)'],
                                        'unit'  : ['(objectclass=organizationalUnit)'],
                                        },

                        'key_attributes' : {
                                        'user'  : 'entryUUID',
                                        'group' : 'entryUUID',
                                        'unit'  : 'entryUUID',
                                        },

                        'id_attributes' : ['uidNumber', 'gidNumber'],

                        'attribute_mappings' : {
                                        'user': {
                                                'name'          : 'uid',
                                                'uuid'          : 'entryUUID',
                                                'uidNumber'     : 'uidNumber',
                                                'gidNumber'     : 'gidNumber',
                                                'loginShell'    : 'loginShell',
                                                'givenName'     : 'givenName',
                                                'sn'            : 'sn',
                                                'cn'            : 'cn',
                                                'mail'          : 'mail',
                                                'description'   : 'description',
                                            },
                                        'group': {
                                                'name'          : 'cn',
                                                'uuid'          : 'entryUUID',
                                                'gidNumber'     : 'gidNumber',
                                                'description'   : 'description',
                                            },
                                        'unit': {
                                                'name'          : 'ou',
                                                'uuid'          : 'entryUUID',
                                            },
                                        },
                            },
                    }

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_resolver_read_acls, \
        otpme_resolver_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_resolver_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_resolver_write_acls)
        return _read_acls, _write_acls
    otpme_resolver_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_resolver_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_resolver_read_value_acls, \
        otpme_resolver_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_resolver_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(write_value_acls,
                                                        otpme_resolver_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_resolver_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_resolver_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    resolver_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, resolver_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    resolver_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                resolver_recursive_default_acls)
    return _acls

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    """ Registger resolver type. """
    register_hooks()
    register_commands("resolver",
                    commands,
                    sub_type="ldap",
                    sub_type_attribute="resolver_type")
    resolver_acl = f'resolver:{RESOLVER_TYPE}'
    register_subtype_add_acl(resolver_acl)
    register_subtype_del_acl(resolver_acl)

def register_hooks():
    config.register_auth_on_action_hook("resolver", "add_server")
    config.register_auth_on_action_hook("resolver", "del_server")
    config.register_auth_on_action_hook("resolver", "add_filter")
    config.register_auth_on_action_hook("resolver", "del_filter")
    config.register_auth_on_action_hook("resolver", "add_attribute_mapping")
    config.register_auth_on_action_hook("resolver", "del_attribute_mapping")
    config.register_auth_on_action_hook("resolver", "change_login_dn")
    config.register_auth_on_action_hook("resolver", "change_ldap_base")
    config.register_auth_on_action_hook("resolver", "change_login_password")

class LdapResolver(Resolver):
    """ Class that implements OTPme LDAP resolver. """
    def __init__(self, object_id=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(LdapResolver, self).__init__(object_id=object_id,
                                            realm=realm,
                                            site=site,
                                            name=name,
                                            path=path,
                                            **kwargs)
        # Set resolver type.
        self.resolver_type = RESOLVER_TYPE
        self.sub_type = RESOLVER_TYPE

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Set default values.
        self.object_types = [
                            'unit',
                            'group',
                            'user',
                            ]

        self.ldap_servers = []
        self.ldap_filters = {}
        self.ldap_base = None
        self.login_dn = None
        self.login_password = None
        self.id_attributes = []
        self.attribute_mappings = {}

        self.templates = templates

    def _get_object_config(self):
        """ Merge resolver config with config from parent class. """
        resolver_config = {
            'LDAP_SERVERS'              : {
                                            'var_name'      : 'ldap_servers',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'LDAP_FILTERS'              : {
                                            'var_name'      : 'ldap_filters',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            'LDAP_BASE'                 : {
                                            'var_name'      : 'ldap_base',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'LOGIN_DN'                  : {
                                            'var_name'      : 'login_dn',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'LOGIN_PASSWORD'            : {
                                            'var_name'      : 'login_password',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },
            'ID_ATTRIBUTES'             : {
                                            'var_name'      : 'id_attributes',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'ATTRIBUTE_MAPPINGS'        : {
                                            'var_name'      : 'attribute_mappings',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge resolver configs.
        return Resolver._get_object_config(self, resolver_config=resolver_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Resolver.set_variables(self)

    @check_acls(['add:ldap_server'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def add_server(self, server_uri, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add LDAP server. """
        if not server_uri:
            return callback.error(_("Got empty LDAP server."))
        if server_uri in self.ldap_servers:
            return callback.error(_("LDAP server already added to this resolver."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_server",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.ldap_servers.append(server_uri)
        return self._cache(callback=callback)

    @check_acls(['del:ldap_server'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def del_server(self, server_uri, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Delete LDAP server. """
        if not server_uri:
            return callback.error(_("Got empty LDAP server."))
        if server_uri not in self.ldap_servers:
            return callback.error(_("LDAP server not added to this resolver."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_server",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.ldap_servers.remove(server_uri)
        return self._cache(callback=callback)

    @check_acls(['add:ldap_filter'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def add_filter(self, object_type, ldap_filter, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add LDAP filter. """
        if object_type not in self.object_types:
            msg = _("Invalid object type for this resolver: {object_type}")
            msg = msg.format(object_type=object_type)
            return callback.error(msg)
        if not ldap_filter:
            return callback.error(_("Got empty LDAP filter."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_filter",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if object_type not in self.ldap_filters:
            self.ldap_filters[object_type] = []
        self.ldap_filters[object_type].append(ldap_filter)
        return self._cache(callback=callback)

    @check_acls(['del:ldap_filter'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def del_filter(self, object_type, ldap_filter, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Delete LDAP filter. """
        if not ldap_filter:
            return callback.error(_("Got empty LDAP filter."))
        if object_type not in self.ldap_filters:
            msg = _("No LDAP filter configured for object type: {object_type}.")
            msg = msg.format(object_type=object_type)
            return callback.error(msg)
        if ldap_filter not in self.ldap_filters[object_type]:
            return callback.error(_("Unknown LDAP filter."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_filter",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.ldap_filters[object_type].remove(ldap_filter)
        return self._cache(callback=callback)

    @check_acls(['add:attribute_mapping'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def add_attribute_mapping(self, object_type, src_attr, dst_attr=None,
        run_policies=True, _caller="API", callback=default_callback, **kwargs):
        """ Add LDAP attribute mapping. """
        if object_type not in self.object_types:
            msg = _("Invalid object type for this resolver: {object_type}")
            msg = msg.format(object_type=object_type)
            return callback.error(msg)
        if not src_attr:
            return callback.error(_("Got no source attribute."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_attribute_mapping",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not dst_attr:
            dst_attr = src_attr

        if object_type not in self.attribute_mappings:
            self.attribute_mappings[object_type] = {}

        self.attribute_mappings[object_type][dst_attr] = src_attr

        return self._cache(callback=callback)

    @check_acls(['del:attribute_mapping'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def del_attribute_mapping(self, object_type, src_attr,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete LDAP attribute mapping. """
        if not src_attr:
            return callback.error(_("Got no source attribute."))
        if object_type not in self.attribute_mappings:
            msg = _("No LDAP attribute configured for object type: {object_type}.")
            msg = msg.format(object_type=object_type)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_attribute_mapping",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        dst_attr = None
        for x in self.attribute_mappings[object_type]:
            x_src = self.attribute_mappings[object_type][x]
            if x_src == src_attr:
                dst_attr = x
                break

        if not dst_attr:
            return callback.error(_("Unknown attribute."))

        self.attribute_mappings[object_type].pop(dst_attr)
        return self._cache(callback=callback)

    @check_acls(['edit:ldap_base'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_ldap_base(self, ldap_base, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change LDAP base. """
        if not ldap_base:
            return callback.error(_("Got empty LDAP base."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_ldap_base",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        self.ldap_base = ldap_base
        return self._cache(callback=callback)

    @check_acls(['edit:login_dn'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_login_dn(self, login_dn, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change LDAP login DN. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_login_dn",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        if login_dn == "":
            self.login_dn = None
        else:
            self.login_dn = login_dn
        return self._cache(callback=callback)

    @check_acls(['edit:login_password'])
    @object_lock()
    @backend.transaction
    @audit_log(ignore_args=['login_password'])
    def change_login_password(self, login_password=None, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Change LDAP login passowrd. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_login_password",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        if login_password is None:
            login_password = callback.askpass("LDAP password: ")
        if login_password == "":
            self.login_password = None
        else:
            self.login_password = login_password
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, **kwargs):
        """ Add a resolver. """
        return callback.ok()

    def get_ldap_connection(self, server_uri):
        """ Get connection type and LDAP port from server URI. """
        use_ssl = False
        use_start_tls = False
        server_address = None
        server_port = None

        # Try to get server port from URI.
        ldap_re = re.compile(':[0-9]*$')
        if ldap_re.match(server_uri):
            try:
                server_port = int(server_uri.split(":")[-1:])
            except:
                msg = _("Invalid port in server URI: {server_uri}")
                msg = msg.format(server_uri=server_uri)
                raise Exception(msg)

        if server_uri.startswith("ldaps://"):
            if server_port is None:
                server_port = 636
            if server_port == 389:
                use_start_tls = True
            else:
                use_ssl = True

        elif server_uri.startswith("ldap://"):
            if server_port is None:
                server_port = 389

        # Try to get server address from URI.
        try:
            server_address = server_uri.split("/")[2]
        except:
            pass

        if server_address is None:
            msg = _("Invalid LDAP URI: {server_uri}")
            msg = msg.format(server_uri=server_uri)
            raise Exception(msg)

        # Bind to server.
        ldap_server = ldap3.Server(host=server_address,
                                port=server_port,
                                use_ssl=use_ssl,
                                get_info='ALL',
                                connect_timeout=3)
        login_dn = None
        login_password = None
        if self.login_password:
            if self.login_dn:
                login_dn = self.login_dn
                login_password = self.login_password
        try:
            conn = ldap3.Connection(ldap_server,
                                    user=login_dn,
                                    password=login_password)
            if not conn.bind():
                raise Exception(_("Bind failed."))
        except Exception as e:
            msg, log_msg = _("Error connecting to server: {server_uri}: {error}", log=True)
            msg = msg.format(server_uri=server_uri, error=e)
            log_msg = log_msg.format(server_uri=server_uri, error=e)
            logger.warning(log_msg)
            raise Exception(msg)

        if use_start_tls:
            conn.start_tls()

        return conn

    def _fetch_objects(self, ldap_conn, object_types, **kwargs):
        """ Get LDAP objects. """
        result = {}
        for object_type in object_types:
            # Skip object type without filters.
            if object_type not in self.ldap_filters:
                continue

            if object_type == "unit":
                if not self.sync_units:
                    continue

            result[object_type] = {}

            # Get attribute mappings.
            try:
                attr_list = list(self.attribute_mappings[object_type].values())
            except:
                attr_list = []

            return_attributes = attr_list

            # We need the resolver key attribute to identify the object (e.g.
            # when renamed)
            key_attribute = self.key_attributes[object_type]
            if not key_attribute in attr_list:
                attr_list.append(key_attribute)

            # Get attribute that will be mapped to the objects name.
            name_attribute = self.attribute_mappings[object_type]['name']

            for search_filter in self.ldap_filters[object_type]:
                ldap_conn.search(self.ldap_base,
                                search_filter,
                                attributes=attr_list)
                for x in ldap_conn.response:
                    result_attributes = {}
                    # Get object attributes.
                    x_attributes = x['raw_attributes']
                    # Get object DN.
                    x_dn = x['dn']
                    if isinstance(x_dn, bytes):
                        x_dn = x_dn.decode()
                    # Make sure we got the key attribute.
                    x_key_attribute = x_attributes[key_attribute]
                    if not x_key_attribute:
                        msg = _("Got no key attribute: {x_dn}")
                        msg = msg.format(x_dn=x_dn)
                        raise Exception(msg)
                    # Make sure we have just one key attribute.
                    if isinstance(x_key_attribute, list):
                        if len(x_key_attribute) > 1:
                            msg = _("Got more than one key attribute: {x_dn}: {key_attributes}")
                            msg = msg.format(x_dn=x_dn, key_attributes=','.join(x_key_attribute))
                            raise Exception(msg)
                        else:
                            x_key_attribute = x_key_attribute[0]
                            x_attributes[key_attribute] = x_key_attribute
                    # Make sure we have just one object name.
                    x_name = x_attributes.pop(name_attribute)
                    if isinstance(x_name, list):
                        x_name = x_name[0]
                    if isinstance(x_name, bytes):
                        x_name = x_name.decode()

                    x_path = []
                    for p in x_dn.split(","):
                        if not p.startswith("ou="):
                            continue
                        path_part = p.replace("ou=", "")
                        x_path.insert(0, path_part)
                    if object_type != "unit":
                        x_path.append(x_name)

                    for a in return_attributes:
                        if a in x_attributes:
                            x_attr = x_attributes[a]
                            if isinstance(x_attr, list):
                                converted_attr = []
                                for x_val in x_attr:
                                    if isinstance(x_val, bytes):
                                        x_val = x_val.decode()
                                    converted_attr.append(x_val)
                                x_attr = converted_attr
                            else:
                                if isinstance(x_attr, bytes):
                                    x_attr = x_attr.decode()
                            result_attributes[a] = x_attr
                        else:
                            result_attributes[a] = []

                    if object_type == "user":
                        try:
                            gid_number = x_attributes['gidNumber'][0]
                        except KeyError:
                            gid_number = None
                        if gid_number:
                            if isinstance(gid_number, bytes):
                                gid_number = gid_number.decode()
                            for group in result['group']:
                                x_gid_number = result['group'][group]['gidNumber'][0]
                                if x_gid_number == gid_number:
                                    result_attributes['object_group'] = group
                                    break

                    result_attributes['object_path'] = x_path
                    result[object_type][x_name] = result_attributes

        return result

    def fetch_objects(self, object_types=None, callback=default_callback, **kwargs):
        """ Get LDAP objects. """
        ldap_conn = None

        if not self.ldap_servers:
            raise Exception(_("No LDAP server configured."))

        for o_type in self.ldap_filters:
            try:
                self.key_attributes[o_type]
            except:
                msg = _("No key attribute configured for: {o_type}")
                msg = msg.format(o_type=o_type)
                raise Exception(msg)
            try:
                self.attribute_mappings[o_type]['name']
            except:
                msg = _("Please add a attribute mapping for 'name': {o_type}")
                msg = msg.format(o_type=o_type)
                raise Exception(msg)

        for server_uri in self.ldap_servers:
            try:
                ldap_conn = self.get_ldap_connection(server_uri)
                break
            except:
                pass

        if ldap_conn is None:
            raise Exception(_("Unable to connect to any LDAP server."))

        if not object_types:
            object_types = self.object_types

        msg = _("Fetching LDAP objects...")
        callback.send(msg)
        try:
            result = self._fetch_objects(ldap_conn, object_types)
        except Exception as e:
            msg = _("Failed to fetch objects: {error}")
            msg = msg.format(error=e)
            raise Exception(msg)
        finally:
            ldap_conn.unbind()

        return result

    def _test(self, verbose_level=0, callback=default_callback):
        """ Test the resolver. """
        if not self.ldap_servers:
            return callback.error(_("No LDAP server configured."))

        if not self.ldap_filters:
            return callback.error(_("No LDAP filters configured."))

        errors = []
        failed_servers = []
        object_counter = {}
        processed_servers = {}
        object_types = self.object_types

        for server_uri in self.ldap_servers:
            result = {}
            error_msg = None
            ldap_result = None

            try:
                ldap_conn = self.get_ldap_connection(server_uri)
            except Exception as e:
                ldap_conn = None
                error_msg = str(e)
                log_msg = error_msg
                logger.warning(log_msg)
                if verbose_level > 0:
                    callback.send(error_msg)

            if ldap_conn:
                # Fetch objects.
                try:
                    ldap_result = self._fetch_objects(ldap_conn, object_types)
                except Exception as e:
                    error_msg, log_msg = _("Failed to fetch objects: {error}", log=True)
                    error_msg = error_msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    logger.warning(log_msg)
                    if verbose_level > 0:
                        callback.send(error_msg)
                    config.raise_exception()
                finally:
                    ldap_conn.unbind()
                if ldap_result:
                    found_objects = 0
                    for object_type in ldap_result:
                        found_objects = len(ldap_result[object_type])
                        if object_type not in object_counter:
                            object_counter[object_type] = {}
                        object_counter[object_type][server_uri] = found_objects
                        if verbose_level > 0:
                            msg = _("LDAP server returned {found_objects} {object_type}: {server_uri}")
                            msg = msg.format(found_objects=found_objects, object_type=object_type, server_uri=server_uri)
                            callback.send(msg)
            if error_msg is not None:
                errors.append(_("Connection to one or more servers failed."))
                failed_servers.append(server_uri)

            result = {
                    'ldap_result'   : ldap_result,
                    'error_msg'     : error_msg,
                    }
            processed_servers[server_uri] = result

        # Check if all LDAP servers return the same objects.
        for object_type in object_counter:
            object_count = None
            for server_uri in object_counter[object_type]:
                found_objects = object_counter[object_type][server_uri]
                if object_count is None:
                    object_count = found_objects
                    continue
                if found_objects != object_count:
                    msg = _("LDAP search result for one or more servers differs.")
                    errors.append(msg)
                    break

        if errors:
            return callback.error("\n".join(errors))

        return callback.ok(_("All servers tested successful."))

    def show_config(self, callback=default_callback, **kwargs):
        """ Show resolver config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        ldap_base = ""
        if self.verify_acl("view:ldap_base") \
        or self.verify_acl("edit:ldap_base"):
            ldap_base = self.ldap_base
        lines.append(f'LDAP_BASE="{ldap_base}"')

        login_dn = ""
        if self.verify_acl("view:login_dn") \
        or self.verify_acl("edit:login_dn"):
            login_dn = self.login_dn
        lines.append(f'LOGIN_DN="{login_dn}"')

        login_password = ""
        if self.verify_acl("view:login_password") \
        or self.verify_acl("edit:login_password"):
            login_password = self.login_password
        lines.append(f'LOGIN_PASSWORD="{login_password}"')

        ldap_servers = []
        if self.verify_acl("view:ldap_server") \
        or self.verify_acl("add:ldap_server") \
        or self.verify_acl("del:ldap_server"):
            ldap_servers = self.ldap_servers
        lines.append(f'LDAP_SERVERS="{",".join(ldap_servers)}"')

        ldap_filters = []
        if self.verify_acl("view:ldap_filter") \
        or self.verify_acl("add:ldap_filter") \
        or self.verify_acl("del:ldap_filter"):
            for object_type in self.ldap_filters:
                filter_list = ",".join(self.ldap_filters[object_type])
                filter_string = f"{object_type}:[{filter_list}]"
                ldap_filters.append(filter_string)
        lines.append(f'LDAP_FILTERS="{",".join(ldap_filters)}"')

        attribute_mappings = []
        if self.verify_acl("view:ldap_attribute") \
        or self.verify_acl("add:ldap_attribute") \
        or self.verify_acl("del:ldap_attribute"):
            for object_type in self.attribute_mappings:
                attr_list = []
                for src_attr in self.attribute_mappings[object_type]:
                    dst_attr = self.attribute_mappings[object_type][src_attr]
                    attr_list.append(f"{src_attr}:{dst_attr}")
                attribute_list = ",".join(attr_list)
                attribute_string = f"{object_type}:[{attribute_list}]"
                attribute_mappings.append(attribute_string)
        lines.append(f'ATTRIBUTE_MAPPINGS="{",".join(attribute_mappings)}"')

        return Resolver.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        """ Show resolver details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
