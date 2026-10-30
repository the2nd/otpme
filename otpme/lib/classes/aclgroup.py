# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import denied_msg
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes import get_object_module_path
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
from otpme.lib.protocols.utils import register_commands
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

DEFAULT_UNIT = "aclgroups"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

read_acls = []

write_acls = []

read_value_acls = {
                    "view"      : [
                                    "entries",
                                    "aclgroups",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "entry",
                                    "aclgroup",
                                ],
                    "remove"    : [
                                    "entry",
                                    "aclgroup",
                                ],
            }

default_acls = []

recursive_default_acls = []

# The ACL groups every site has. They hold what the code says: it writes
# them when the site is added and on every upgrade (Site.upgrade()), so an
# update brings the ACLs they should have, and nobody can change their
# entries. <member_of> are the base groups each one inherits from.
BASE_ACLGROUPS = {
    # What every realm user may see: the role REALM_USER gets it on the
    # site and the whole tree below it (Site.add_acls()). The users,
    # groups, units and roles for an LDAP client, the hosts and nodes for
    # otpme-shell. Not more: a user has no business with the access
    # groups, clients or policies of a site.
    "realm_user"    : {
                        'entries'   : [
                                    "site:view_public",
                                    "site:view:attribute",
                                    "unit:view_public",
                                    "unit:view:attribute",
                                    "user:view_public",
                                    "user:view:attribute",
                                    "group:view_public",
                                    "group:view:attribute",
                                    "role:view_public",
                                    "host:view_public",
                                    "node:view_public",
                                    ],
                        'member_of' : [],
                    },
    "usermanager"   : {
                        'entries'   : [
                                    "unit:add:user",
                                    "unit:delete:user",
                                    "user:view",
                                    "user:edit:attribute",
                                    "user:add:attribute",
                                    "user:delete:attribute",
                                    "user:edit:description",
                                    "user:enable:object",
                                    "user:disable:object",
                                    "user:delete:object",
                                    "user:add:token",
                                    "token:view",
                                    "token:view:initial_secret",
                                    "token:view:initial_pin",
                                    ],
                        'member_of' : [],
                    },
    "useradmin"     : {
                        'entries'   : [
                                    "user:edit",
                                    "user:enable",
                                    "user:disable",
                                    "user:rename",
                                    "user:move",
                                    "user:assign:policy",
                                    "user:remove:policy",
                                    "user:gen_keys",
                                    "user:del_keys",
                                    "user:unblock",
                                    "user:set_temp_password",
                                    "user:add:photo",
                                    "user:delete:photo",
                                    "user:delete:token",
                                    "token:edit",
                                    "token:enable",
                                    "token:disable",
                                    "token:rename",
                                    "token:move",
                                    "token:delete:object",
                                    "token:assign:policy",
                                    "token:remove:policy",
                                    "token:set_temp_password",
                                    ],
                        'member_of' : ["usermanager"],
                    },
    "groupmanager"  : {
                        'entries'   : [
                                    "unit:add:group",
                                    "unit:delete:group",
                                    "group:view",
                                    "group:edit:description",
                                    "group:add:token",
                                    "group:remove:token",
                                    "group:add:role",
                                    "group:remove:role",
                                    ],
                        'member_of' : [],
                    },
    }

commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_entry'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_entry',
                    'args'              : ['entries'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_entry'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_entry',
                    'args'              : ['entries'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_entries',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'add_aclgroup'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_aclgroup',
                    'args'              : ['aclgroup_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_aclgroup'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_aclgroup',
                    'args'              : ['aclgroup_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'list_aclgroups'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_aclgroups',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'get_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_config_parameter',
                    'args'              : ['parameter'],
                    'dargs'             : {'verify_acls':True},
                    'job_type'          : 'process',
                    },
                },
            },
    'config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'set_config_param',
                    'args'              : ['parameter'],
                    'oargs'             : ['value', 'append', 'delete'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'             : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_changelog',
                    'job_type'          : 'process',
                    },
                },
            },
    'show_oid'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_oid',
                    'oargs'             : ['full'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_uuid'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_uuid',
                    'job_type'          : 'thread',
                    },
                },
            },
    'edit_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'edit_changelog',
                    'args'              : ['entry_id', 'comment'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_changelog',
                    'args'              : ['entry_id'],
                    'job_type'          : 'process',
                    },
                },
            },
    'clear_changelog'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'clear_changelog',
                    'job_type'          : 'process',
                    },
                },
            },
    'touch'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'touch',
                    'job_type'          : 'process',
                    },
                },
            },
    'auto_disable'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_auto_disable',
                    'args'              : ['auto_disable'],
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.show_getter("aclgroup"),
                    'args'              : ['realm'],
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'search_regex',
                                        'sort_by',
                                        'reverse',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'realm',
                                        'site',
                                        'max_policies',
                                        'limit',
                                        ],
                    'job_type'          : 'thread',
                    },
                'exists'    : {
                    'method'            : 'show',
                    'args'              : ['realm'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'list'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.list_getter("aclgroup"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
                                        'attribute',
                                        'search_regex',
                                        'sort_by',
                                        ],
                    'job_type'          : None,
                    },
                'exists'    : {
                    'method'            : cli.list_getter("aclgroup"),
                    'oargs'              : [
                                        'reverse',
                                        'show_all',
                                        'attribute',
                                        'search_regex',
                                        'sort_by',
                                        ],
                    'job_type'          : None,
                    },
                },
            },
    'del'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'oargs'             : ['add_to_trash'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'job_type'          : 'process',
                    },
                },
            },
    'rename'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'rename',
                    'args'              : ['new_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'move'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'move',
                    'args'              : ['new_unit'],
                    'oargs'             : ['keep_acls'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_acl_inheritance'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'enable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_acl_inheritance'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'disable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_policies'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_policies',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'add_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'cache_update_interval' : 30,
                    'args'              : ['owner_type', 'owner_name', 'acls', 'recursive_acls', 'apply_default_acls',],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'cache_update_interval' : 30,
                    'args'              : ['acls'],
                    'oargs'             : ['recursive_acls', 'apply_default_acls'],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'add_policy'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_policy'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'description'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_description',
                    'oargs'             : ['description'],
                    'job_type'          : 'process',
                    },
                },
            },
    'info'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_info',
                    'oargs'             : ['info', 'language'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'dump_info'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'dump_info',
                    'oargs'             : ['language'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'export'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'export_config',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_orphans'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_orphans',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    '_show_config'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_config',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_object_classes'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    'list_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_default_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_recursive_default_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'recursive_default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    }

REALM_USER_ACLGROUP = "realm_user"

def get_realm_user_object_types():
    """ The object types the role REALM_USER gets the base ACL group
    realm_user on: those it has entries for, and the site and the units,
    which hand it on. See Site.add_realm_user_acls(). """
    object_types = {"site", "unit"}
    for entry in BASE_ACLGROUPS[REALM_USER_ACLGROUP]['entries']:
        object_types.add(entry.split(":")[0])
    return sorted(object_types)

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(split=False, **kwargs):
    result = _get_value_acls(read_value_acls, write_value_acls, split=split, **kwargs)
    config_params = config.get_config_parameters("aclgroup")
    if split:
        read_acls = result[0]['view']
        set_acls = result[1]['set']
    else:
        read_acls = result['view']
        set_acls = result['set']
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        set_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("aclgroup")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("aclgroup")
    return acls

def get_type_acls(object_type):
    """ The ACLs an object of the given type supports, without owner.

    What an entry of an ACL group may name for that type. The same
    sources _get_supported_acls() reads for a "+type" default ACL: the
    module of the type, those of its sub types (the token types, the
    policy types) and the extensions.
    """
    from otpme.lib.extensions import utils
    modules = [importlib.import_module(get_object_module_path(object_type))]
    for sub_type in config.get_sub_object_types(object_type):
        sub_module_path = f"otpme.lib.{object_type}.{sub_type}.{sub_type}"
        modules.append(importlib.import_module(sub_module_path))
    acls = set(utils.get_acls(object_type))
    value_acls = [utils.get_value_acls(object_type)]
    for module in modules:
        acls.update(module.get_acls())
        value_acls.append(module.get_value_acls())
    for x_value_acls in value_acls:
        for acl in x_value_acls:
            for value in x_value_acls[acl]:
                acls.add(f"{acl}:{value}")
    return acls

def check_entry(entry):
    """ Make sure the given entry is <type>:<acl> with an ACL the type
    supports. Returns it as it is to be stored. """
    try:
        object_type, acl = entry.split(":", 1)
    except ValueError:
        msg = _("Entry must be <object_type>:<acl>: {entry}")
        msg = msg.format(entry=entry)
        raise OTPmeException(msg) from None
    if object_type not in config.tree_object_types:
        msg = _("Unknown object type: {object_type}")
        msg = msg.format(object_type=object_type)
        raise OTPmeException(msg)
    supported_acls = get_type_acls(object_type)
    if acl in supported_acls:
        return entry
    # A sub value narrows a supported ACL, edit:attribute:mail grants less
    # than edit:attribute. See OTPmeObject.check_supported_acl().
    acl_parts = acl.split(":")
    if len(acl_parts) > 2:
        if ":".join(acl_parts[:2]) in supported_acls:
            return entry
    msg = _("ACL not supported by object type {object_type}: {acl}")
    msg = msg.format(object_type=object_type, acl=acl)
    raise OTPmeException(msg)

def get_parent_aclgroups(aclgroup_uuid, recursive=False):
    """ The ACL groups the given one is a member of, and so inherits the
    entries of. Groups may come round to one seen before: every group
    is taken once. """
    parents = []
    check_uuids = [aclgroup_uuid]
    while check_uuids:
        x_parents = backend.search(object_type="aclgroup",
                                    attribute="aclgroup",
                                    values=check_uuids,
                                    return_type="uuid")
        check_uuids = []
        for x_uuid in x_parents:
            if x_uuid == aclgroup_uuid:
                continue
            if x_uuid in parents:
                continue
            parents.append(x_uuid)
            check_uuids.append(x_uuid)
        if not recursive:
            break
    return parents

def register():
    register_oid()
    config.register_config_parameter(name="max_aclgroup_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("aclgroup", commands)
    config.register_recursive_default_acl("site", "+aclgroup")
    config.register_default_acl("unit", "+aclgroup")
    config.register_recursive_default_acl("unit", "+aclgroup")
    # The groups a group is a member of are found by it, see
    # get_parent_aclgroups(). Every node checks ACLs, also on objects of
    # other sites, which may name our groups. Hosts check none: groups
    # are not synced to them (see register_sync_settings()).
    config.register_index_attribute("aclgroup", sync=["node:untrusted"],
                                    object_types=["aclgroup"])
    # The groups that hold an entry are found by it, and show lists them.
    config.register_index_attribute("entry", sync=["node:untrusted"],
                                    object_types=["aclgroup"])

def register_hooks():
    config.register_auth_on_action_hook("aclgroup", "add_entry")
    config.register_auth_on_action_hook("aclgroup", "remove_entry")
    config.register_auth_on_action_hook("aclgroup", "add_aclgroup")
    config.register_auth_on_action_hook("aclgroup", "remove_aclgroup")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("aclgroup", DEFAULT_UNIT)
    for aclgroup_name in BASE_ACLGROUPS:
        config.register_base_object("aclgroup", aclgroup_name)

def add_base_aclgroups(site, callback=default_callback):
    """ Add the base ACL groups the site does not have, and make the ones
    it has hold what BASE_ACLGROUPS says. Called when the site is added,
    and on upgrade, where the unit may be missing as well. """
    from otpme.lib.classes.unit import Unit
    unit_path = f"/{site.realm}/{site.name}/{DEFAULT_UNIT}"
    unit = Unit(path=unit_path)
    if not unit.exists():
        if not unit.add(verify_acls=False, callback=callback):
            msg = _("Problem adding base unit '{unit_path}'.")
            msg = msg.format(unit_path=unit_path)
            return callback.error(msg)
    aclgroups = {}
    for aclgroup_name in BASE_ACLGROUPS:
        aclgroup = Aclgroup(name=aclgroup_name,
                            realm=site.realm,
                            site=site.name)
        if not aclgroup.exists():
            if not aclgroup.add(verify_acls=False, callback=callback):
                msg = _("Problem adding base ACL group '{aclgroup}'.")
                msg = msg.format(aclgroup=aclgroup_name)
                return callback.error(msg)
        entries = BASE_ACLGROUPS[aclgroup_name]['entries']
        if not aclgroup.set_base_entries(entries, callback=callback):
            return callback.error()
        aclgroups[aclgroup_name] = aclgroup
    # Only adds: a member somebody else added stays.
    for aclgroup_name in BASE_ACLGROUPS:
        aclgroup = aclgroups[aclgroup_name]
        for parent_name in BASE_ACLGROUPS[aclgroup_name]['member_of']:
            parent = aclgroups[parent_name]
            if aclgroup.uuid in parent.aclgroups:
                continue
            if not parent.add_aclgroup(aclgroup_name,
                                    force=True,
                                    verify_acls=False,
                                    run_policies=False,
                                    callback=callback):
                return callback.error()
    return callback.ok()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    unit_name_re = oid.object_regex['unit']['name']
    aclgroup_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    aclgroup_path_re = f'{unit_path_re}[/]{aclgroup_name_re}'
    # An OID is not a path, see accessgroup.py: no leading slash, and
    # the unit part is optional because the read OID has none.
    aclgroup_oid_re = (f'aclgroup[|]{realm_name_re}[/]{site_name_re}'
                    f'([/]{unit_name_re})*[/]{aclgroup_name_re}')
    oid.register_oid_schema(object_type="aclgroup",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=aclgroup_name_re,
                            path_regex=aclgroup_path_re,
                            oid_regex=aclgroup_oid_re)
    # Everything after realm and site: the unit can be a sub unit.
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="aclgroup",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="aclgroup")

def register_backend():
    """ Register object for the file backend. """
    aclgroup_dir_extension = "aclgroup"
    def path_getter(aclgroup_oid, aclgroup_uuid):
        return backend.config_path_getter(aclgroup_oid, aclgroup_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                ]
        return backend.rebuild_object_index("aclgroup", objects, after)
    # Register object to config.
    config.register_object_type(object_type="aclgroup",
                            version=1,
                            tree_object=True,
                            uniq_name=True,
                            add_after=["unit"],
                            sync_after=["unit"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Aclgroup
    backend.register_object_type(object_type="aclgroup",
                                dir_name_extension=aclgroup_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

@match_class_typing
class Aclgroup(OTPmeObject):
    """ Class that implements OTPme ACL group object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        unit: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class).
        self.type = "aclgroup"
        # Call parent class init.
        super().__init__(object_id=object_id,
                            realm=realm,
                            site=site,
                            unit=unit,
                            name=name,
                            path=path,
                            **kwargs)
        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # <object_type>:<acl>, see check_entry().
        self.entries = []
        # The groups that are members of this one, and so inherit our
        # entries. The same way round as roles in a role.
        self.aclgroups = []

        # ACL groups should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'node'  : {
                        'untrusted'  : [
                            # An ACL on an object of another site may name
                            # one of our groups.
                            "ENTRIES",
                            "ACLGROUPS",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            ]
                        },
                    }

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()

    def set_variables(self):
        """ Set instance variables. """
        return True

    def _get_object_config(self, **kwargs):
        """ Get object config dict. """
        object_config = {
                        'ENTRIES'                   : {
                                                        'var_name'  : 'entries',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'ACLGROUPS'                 : {
                                                        'var_name'  : 'aclgroups',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    def get_aclgroup(self, aclgroup_name: str,
        callback: JobCallback=default_callback):
        """ The ACL group of the given name: <name> on our site, or
        <site>/<name>. """
        aclgroup_site = self.site
        if "/" in aclgroup_name:
            aclgroup_site, aclgroup_name = aclgroup_name.split("/", 1)
        result = backend.search(object_type="aclgroup",
                                attribute="name",
                                value=aclgroup_name,
                                realm=self.realm,
                                site=aclgroup_site,
                                return_type="instance")
        if not result:
            msg = _("Unknown ACL group: {site}/{name}")
            msg = msg.format(site=aclgroup_site, name=aclgroup_name)
            return callback.error(msg)
        return result[0]

    def check_base_aclgroup(self, callback: JobCallback=default_callback):
        """ Refuse to change a base ACL group. Its entries are what the
        code says, see BASE_ACLGROUPS. """
        if self.name not in BASE_ACLGROUPS:
            return True
        msg = _("Base ACL group cannot be changed: {aclgroup}")
        msg = msg.format(aclgroup=self.name)
        return callback.error(msg)

    @object_lock()
    def set_base_entries(self, entries: list,
        callback: JobCallback=default_callback):
        """ Make the entries of a base ACL group the given ones. """
        object_changed = False
        for entry in list(self.entries):
            if entry in entries:
                continue
            self.entries.remove(entry)
            self.del_index('entry', entry)
            object_changed = True
        for entry in entries:
            if entry in self.entries:
                continue
            self.entries.append(entry)
            self.add_index('entry', entry)
            object_changed = True
        if not object_changed:
            return True
        return self._cache(callback=callback)

    def get_member_aclgroups(self, recursive: bool=False):
        """ The UUIDs of the groups that are members of this one. Groups
        may come round to one seen before: every group is taken once. """
        members = []
        check_uuids = list(self.aclgroups)
        while check_uuids:
            x_uuid = check_uuids.pop(0)
            if x_uuid == self.uuid:
                continue
            if x_uuid in members:
                continue
            members.append(x_uuid)
            if not recursive:
                continue
            x_aclgroup = backend.get_object(object_type="aclgroup",
                                            uuid=x_uuid)
            if not x_aclgroup:
                continue
            check_uuids += x_aclgroup.aclgroups
        return members

    @object_lock()
    @audit_log()
    @object_changelog("add entry {entries}")
    def add_entry(
        self,
        entries: Union[str,list],
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add entries, <object_type>:<acl>, to the ACL group. """
        if verify_acls:
            if not self.verify_acl("add:entry"):
                msg = denied_msg(self, "add:entry")
                return callback.error(msg, exception=PermissionDenied)

        base_check = self.check_base_aclgroup(callback=callback)
        if base_check is not True:
            return base_check

        if isinstance(entries, str):
            entries = entries.split(",")

        new_entries = []
        for entry in entries:
            try:
                entry = check_entry(entry)
            except OTPmeException as e:
                return callback.error(str(e))
            if entry in self.entries:
                msg = _("Entry already in ACL group: {entry}")
                msg = msg.format(entry=entry)
                return callback.error(msg)
            if entry in new_entries:
                continue
            new_entries.append(entry)

        msg = _("Add entries to ACL group '{aclgroup}'?: {entries}")
        msg = msg.format(aclgroup=self.name, entries=", ".join(new_entries))
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_entry",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        for entry in new_entries:
            self.entries.append(entry)
            self.add_index('entry', entry)
        return self._cache(callback=callback)

    @object_lock()
    @audit_log()
    @object_changelog("remove entry {entries}")
    def remove_entry(
        self,
        entries: Union[str,list],
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Remove entries from the ACL group. Not checked against what
        the type supports: an entry that is not supported any more must
        be removable. """
        if verify_acls:
            if not self.verify_acl("remove:entry"):
                msg = denied_msg(self, "remove:entry")
                return callback.error(msg, exception=PermissionDenied)

        base_check = self.check_base_aclgroup(callback=callback)
        if base_check is not True:
            return base_check

        if isinstance(entries, str):
            entries = entries.split(",")

        for entry in entries:
            if entry not in self.entries:
                msg = _("Entry not in ACL group: {entry}")
                msg = msg.format(entry=entry)
                return callback.error(msg)

        msg = _("Remove entries from ACL group '{aclgroup}'?: {entries}")
        msg = msg.format(aclgroup=self.name, entries=", ".join(entries))
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_entry",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        for entry in entries:
            if entry in self.entries:
                self.entries.remove(entry)
                self.del_index('entry', entry)
        return self._cache(callback=callback)

    def get_entries(
        self,
        recursive: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ The entries of the ACL group. With <recursive> also those it
        inherits from the groups it is a member of, named with the group
        they come from. """
        if not self.verify_acl("view:entries"):
            msg = denied_msg(self, "view:entries")
            return callback.error(msg, exception=PermissionDenied)
        result = sorted(self.entries)
        if recursive:
            for x_uuid in get_parent_aclgroups(self.uuid, recursive=True):
                x_aclgroup = backend.get_object(object_type="aclgroup",
                                                uuid=x_uuid)
                if not x_aclgroup:
                    continue
                x_name = x_aclgroup.name
                if x_aclgroup.site != self.site:
                    x_name = f"{x_aclgroup.site}/{x_name}"
                for x_entry in sorted(x_aclgroup.entries):
                    result.append(f"{x_entry} ({x_name})")
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @object_lock()
    @audit_log()
    @object_changelog("add aclgroup {aclgroup_name}")
    def add_aclgroup(
        self,
        aclgroup_name: str,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Make the given ACL group a member of this one. It inherits our
        entries then, the same way round as a role in a role. """
        if verify_acls:
            if not self.verify_acl("add:aclgroup"):
                msg = denied_msg(self, "add:aclgroup")
                return callback.error(msg, exception=PermissionDenied)

        aclgroup = self.get_aclgroup(aclgroup_name, callback=callback)
        if not aclgroup:
            return aclgroup

        if aclgroup.uuid in self.aclgroups:
            msg = _("ACL group is already a member: {aclgroup}")
            msg = msg.format(aclgroup=aclgroup_name)
            return callback.error(msg)

        # A loop would make a group inherit from itself. Unlike roles we
        # refuse it: it says nothing a group does not say on its own.
        if aclgroup.uuid == self.uuid \
        or self.uuid in aclgroup.get_member_aclgroups(recursive=True):
            msg = _("ACL group would inherit from itself: {aclgroup}")
            msg = msg.format(aclgroup=aclgroup_name)
            return callback.error(msg)

        msg = _("Add ACL group '{member}' to ACL group '{aclgroup}'?: ")
        msg = msg.format(member=aclgroup_name, aclgroup=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_aclgroup",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.aclgroups.append(aclgroup.uuid)
        self.add_index('aclgroup', aclgroup.uuid)
        return self._cache(callback=callback)

    @object_lock()
    @audit_log()
    @object_changelog("remove aclgroup {aclgroup_name}")
    def remove_aclgroup(
        self,
        aclgroup_name: str,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Take the given ACL group out of this one. A UUID takes out a
        group that is gone. """
        if verify_acls:
            if not self.verify_acl("remove:aclgroup"):
                msg = denied_msg(self, "remove:aclgroup")
                return callback.error(msg, exception=PermissionDenied)

        if aclgroup_name in self.aclgroups:
            aclgroup_uuid = aclgroup_name
        else:
            aclgroup = self.get_aclgroup(aclgroup_name, callback=callback)
            if not aclgroup:
                return aclgroup
            aclgroup_uuid = aclgroup.uuid

        if aclgroup_uuid not in self.aclgroups:
            msg = _("ACL group is not a member: {aclgroup}")
            msg = msg.format(aclgroup=aclgroup_name)
            return callback.error(msg)

        msg = _("Remove ACL group '{member}' from ACL group '{aclgroup}'?: ")
        msg = msg.format(member=aclgroup_name, aclgroup=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_aclgroup",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.aclgroups.remove(aclgroup_uuid)
        self.del_index('aclgroup', aclgroup_uuid)
        return self._cache(callback=callback)

    def list_aclgroups(
        self,
        recursive: bool=False,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ The groups that are members of this one. """
        if not self.verify_acl("view:aclgroups"):
            msg = denied_msg(self, "view:aclgroups")
            return callback.error(msg, exception=PermissionDenied)
        result = []
        for x_uuid in self.get_member_aclgroups(recursive=recursive):
            x_oid = backend.get_oid(uuid=x_uuid,
                                    object_type="aclgroup",
                                    instance=True)
            # Show the UUID of an orphan member instead of hiding it.
            if not x_oid:
                result.append(x_uuid)
                continue
            x_name = x_oid.name
            if x_oid.site != self.site:
                x_name = f"{x_oid.site}/{x_name}"
            result.append(x_name)
        result.sort()
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog("add")
    def add(
        self,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add an ACL group. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Add object using parent class.
        return super().add(verify_acls=verify_acls,
                            verbose_level=verbose_level,
                            callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("delete")
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete ACL group. """
        if not self.exists():
            msg = _("ACL group does not exist.")
            return callback.error(msg)

        base_check = self.check_base_aclgroup(callback=callback)
        if base_check is not True:
            return base_check

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = denied_msg(self, "delete:object",
                                    others=[(parent_object, del_acl)])
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception:
                return callback.error()

        # The groups that are members of us lose what they inherit from
        # us, and the objects we are given on lose what we grant there,
        # which is worth saying. Their ACLs are left as orphans, see
        # OTPmeObject.get_orphan_acls().
        msgs = []
        if self.aclgroups:
            msg = _("The ACL group has {member_count} member(s) which will lose its entries.")
            msg = msg.format(member_count=len(self.aclgroups))
            msgs.append(msg)
        used_by = backend.search(attribute="acl",
                                value=f"*@{self.uuid}",
                                return_type="uuid")
        if used_by:
            msg = _("The ACL group is given on {object_count} object(s), which will keep an orphan ACL.")
            msg = msg.format(object_count=len(used_by))
            msgs.append(msg)
        msg = None
        if msgs:
            msg = " ".join(msgs)
        if not self.ask_delete_confirmation(force=force,
                                            exception=msg,
                                            callback=callback):
            return callback.abort()

        # Take us out of the groups we are a member of, so they hold no
        # UUID of a group that is gone.
        for x_uuid in get_parent_aclgroups(self.uuid):
            x_aclgroup = backend.get_object(object_type="aclgroup",
                                            uuid=x_uuid)
            if not x_aclgroup:
                continue
            x_aclgroup.remove_aclgroup(self.uuid,
                                    force=True,
                                    verify_acls=False,
                                    callback=callback)

        # Delete object using parent class.
        return super().delete(verbose_level=verbose_level,
                            force=force,
                            callback=callback,
                            **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("rename from {self.name} to {new_name}")
    def rename(
        self,
        new_name: str,
        force: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename ACL group. """
        base_check = self.check_base_aclgroup(callback=callback)
        if base_check is not True:
            return base_check

        msg = _("Rename ACL group '{aclgroup}' to '{new_name}'?: ")
        msg = msg.format(aclgroup=self.name, new_name=new_name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        # Build new OID.
        new_oid = oid.get(object_type="aclgroup",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    def remove_orphans(
        self,
        force: bool=False,
        run_policies: bool=True,
        verbose_level: int=0,
        recursive: bool=False,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Remove orphan UUIDs. """
        extra_ref_lists = [
                ('aclgroups', 'aclgroup', None),
                ]
        return super().remove_orphans(force=force,
                                    run_policies=run_policies,
                                    verbose_level=verbose_level,
                                    recursive=recursive,
                                    extra_ref_lists=extra_ref_lists,
                                    callback=callback,
                                    _caller=_caller,
                                    **kwargs)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show ACL group config. """
        if not self.verify_acl("view_public:object"):
            msg = denied_msg(self, "view_public:object")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:entries") \
        or self.verify_acl("add:entry") \
        or self.verify_acl("remove:entry"):
            entries = ",".join(sorted(self.entries))
            lines.append(f'ENTRIES="{entries}"')
        else:
            lines.append('ENTRIES=""')

        if self.verify_acl("view:aclgroups") \
        or self.verify_acl("add:aclgroup") \
        or self.verify_acl("remove:aclgroup"):
            members = []
            for x_uuid in self.aclgroups:
                x_oid = backend.get_oid(uuid=x_uuid,
                                        object_type="aclgroup",
                                        instance=True)
                # Show the UUID of an orphan member instead of hiding it.
                if not x_oid:
                    members.append(x_uuid)
                    continue
                members.append(x_oid.name)
            members = ",".join(sorted(members))
            lines.append(f'ACLGROUPS="{members}"')
        else:
            lines.append('ACLGROUPS=""')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show ACL group details. """
        return self.show_config(**kwargs)
