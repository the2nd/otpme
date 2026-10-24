# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
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
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import run_pre_post_add_policies
from otpme.lib.pass_crypt import members_tag
from otpme.lib.pass_crypt import members_sign_data
from otpme.lib.pass_crypt import MEMBERS_PARAMETER

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

# The command is otpme-pass, and the command is the object type.
DEFAULT_UNIT = "passwords"
# The hosts that may keep passwords for offline use, see get_pass_cache().
OFFLINE_CACHE_PARAMETER = "password_offline_cache"
# Named there directly, or by a group or role they are in.
OFFLINE_CACHE_TYPES = ["host", "group", "role"]
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

read_acls = []

write_acls = []

read_value_acls = {
                    "view"      : [
                                    "entries",
                                    "nodes",
                                    "hosts",
                                    "devices",
                                    "clients",
                                ],
            }

write_value_acls = {
                    "add"       : [
                                    "entry",
                                    "node",
                                    "host",
                                    "device",
                                    "client",
                                ],
                    "edit"      : [
                                    "entry",
                                    "keys",
                                ],
                    "delete"    : [
                                    "entry",
                                ],
                    "remove"    : [
                                    "node",
                                    "host",
                                    "device",
                                    "client",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'node', 'host', 'device', 'client', 'with_entry'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add_entry',
                    'oargs'             : ['with_entry'],
                    'job_type'          : 'process',
                    },
                },
            },
    'change_entry'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_entry',
                    'job_type'          : 'process',
                    },
                },
            },
    'del_entry'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_entry',
                    'job_type'          : 'process',
                    },
                },
            },
    'show_password'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_password',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_entries'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_entries',
                    'job_type'          : 'process',
                    },
                },
            },
    'update_keys'   : {
            'default'    : {
                'missing'    : {
                    # Looked up when called: it is defined further down.
                    'method'            : lambda *args, **kwargs: \
                                            update_keys_of_all(*args, **kwargs),
                    'oargs'             : ['all_passwords', 'unit'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'update_keys',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_node'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_node',
                    'args'              : ['node_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_node'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_node',
                    'args'              : ['node_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_host'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_host'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_host',
                    'args'              : ['host_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_device'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_device'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_device',
                    'args'              : ['device_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_client'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_client',
                    'args'              : ['client_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_client'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_client',
                    'args'              : ['client_name'],
                    'job_type'          : 'process',
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
    'show'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.show_getter("pass"),
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
                    'method'            : cli.list_getter("pass"),
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
                    'method'            : cli.list_getter("pass"),
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

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(split=False, **kwargs):
    result = _get_value_acls(read_value_acls, write_value_acls, split=split, **kwargs)
    config_params = config.get_config_parameters("pass")
    if split:
        read_acls = result[0]['view']
        set_acls = result[1]['set']
        enable_acls = result[1]['enable']
        disable_acls = result[1]['disable']
    else:
        read_acls = result['view']
        set_acls = result['set']
        enable_acls = result['enable']
        disable_acls = result['disable']
    # A password has no status: nothing would read it. Who may read one
    # is said by view:entries and the keys.
    read_acls.remove("status")
    enable_acls.remove("object")
    disable_acls.remove("object")
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        set_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("pass")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("pass")
    return acls

def load_members(value):
    """ What password_store_members holds: members and signatures.

    One JSON string, {"members": [...], "signatures": {...}}: the
    signatures belong to the members they were made for, and go when
    the members go. A string, because a dict with lists in it is stored
    as a series of appends (incremental_objects) and writing it again
    appended the new lists to the old ones; a string is replaced. A
    plain list is from before and has no signatures.
    """
    data = {'members': [], 'signatures': {}}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return data
    if isinstance(value, dict):
        data['members'] = list(value.get('members', []))
        data['signatures'] = dict(value.get('signatures', {}))
    elif isinstance(value, list):
        data['members'] = list(value)
    return data

def dump_members(member_uuids, signatures):
    """ The value of password_store_members, see load_members(). """
    data = {
            'members'       : list(member_uuids),
            'signatures'    : signatures,
            }
    return json.dumps(data, sort_keys=True)

def members_setter(object_ids, config_object=None, append=False,
    delete=False, callback=default_callback, **kwargs):
    """ Resolve password_store_members to UUIDs and build the new value.

    Given as OIDs of tokens and roles, e.g. token|<realm>/<user>/<token>
    or role|<realm>/<site>/<role>, the way site_admin_blacklist takes
    them. Stored as UUIDs: a renamed token or role stays a member, and
    a new one does not become one by taking over the name.

    Registered with merging_setter: with <append> the given members are
    added, with <delete> taken out, else they replace the members. The
    signatures stay either way. A change makes them outdated, and the
    client then encrypts for the users that are signed and still
    members (pass_crypt.handle_request()).
    """
    current = {'members': [], 'signatures': {}}
    if config_object is not None:
        x_value = config_object.config_params.get(MEMBERS_PARAMETER)
        current = load_members(x_value)
    given_uuids = resolve_member_oids(object_ids)
    if delete:
        missing = [x for x in given_uuids if x not in current['members']]
        if missing:
            msg = _("Config parameter does not have value: {value}")
            msg = msg.format(value=", ".join(members_getter(missing)))
            raise ValueError(msg)
        member_uuids = [x for x in current['members']
                        if x not in given_uuids]
    elif append:
        member_uuids = list(current['members'])
        for x_uuid in given_uuids:
            if x_uuid in member_uuids:
                continue
            member_uuids.append(x_uuid)
    else:
        member_uuids = given_uuids
    return dump_members(member_uuids, current['signatures'])

def resolve_member_oids(object_ids):
    """ The UUIDs of the given token and role OIDs. """
    if isinstance(object_ids, str):
        object_ids = object_ids.split(",")
    member_uuids = []
    for x_object_id in object_ids:
        x_object_id = x_object_id.strip()
        if not x_object_id:
            continue
        # Verifies the OID itself and raises on a malformed one.
        x_oid = oid.get(x_object_id)
        if x_oid.object_type not in ['token', 'role']:
            msg = _("Member must be a token or a role: {object_id}")
            msg = msg.format(object_id=x_object_id)
            raise ValueError(msg)
        x_uuid = backend.get_uuid(x_oid)
        if not x_uuid:
            msg = _("Unknown object: {object_id}")
            msg = msg.format(object_id=x_object_id)
            raise ValueError(msg)
        if x_uuid in member_uuids:
            continue
        member_uuids.append(x_uuid)
    return member_uuids

def members_getter(value, callback=default_callback, **kwargs):
    """ The members as OIDs, without the signatures. """
    if isinstance(value, list):
        member_uuids = value
    else:
        member_uuids = load_members(value)['members']
    object_ids = []
    for x_uuid in member_uuids:
        x_object_id = backend.get_oid(uuid=x_uuid, full=False)
        if not x_object_id:
            # Show the unresolvable entry instead of hiding it.
            object_ids.append(x_uuid)
            continue
        object_ids.append(x_object_id)
    return object_ids

def get_members_object(o):
    """ The object that sets password_store_members for <o>.

    The object itself, its units upwards, the site. The signatures of
    the members are kept on the same object, so the members and the
    signatures of one object go together and never the members of one
    with the signatures of another.
    """
    x_object = o
    while x_object:
        if MEMBERS_PARAMETER in x_object.config_params:
            return x_object
        if x_object.type == "site":
            return None
        x_object = x_object.get_parent_object(run_policies=False)
    return None

def get_member_user_uuids(member_uuids):
    """ The users the given members stand for.

    A token stands for its owner, a role for the owners of its tokens
    and of the tokens of the roles in it.
    """
    user_uuids = []
    for x_uuid in member_uuids:
        x_object = backend.get_object(uuid=x_uuid)
        if not x_object:
            continue
        if x_object.type == "token":
            x_users = [x_object.owner_uuid]
        elif x_object.type == "role":
            x_users = x_object.get_token_users(return_type="uuid",
                                            include_roles=True)
        else:
            continue
        for x_user in x_users:
            if x_user in user_uuids:
                continue
            user_uuids.append(x_user)
    return user_uuids

def get_member_uuids(o):
    """ The members set on <o>. """
    return load_members(o.config_params.get(MEMBERS_PARAMETER))['members']

def get_signatures(o):
    """ The signatures of the members set on <o>. """
    return load_members(o.config_params.get(MEMBERS_PARAMETER))['signatures']

def set_signatures(o, signatures):
    """ Keep the signatures with the members on <o>. """
    member_uuids = get_member_uuids(o)
    # Popped first, as set_config_param() does it.
    o.config_params.pop(MEMBERS_PARAMETER)
    o.config_params[MEMBERS_PARAMETER] = dump_members(member_uuids,
                                                    signatures)

def get_members_request(o):
    """ What the client gets to check the members: their signatures. """
    members_object = get_members_object(o)
    if not members_object:
        return None
    signatures = get_signatures(members_object)
    members = {
            'object_uuid'   : members_object.uuid,
            'signatures'    : dict(signatures),
            }
    return members

def get_member_users(member_uuids):
    """ The users of the given members, with their encrypt public key.

    A user without an encrypt public key cannot be given a key and is
    returned apart.
    """
    user_uuids = get_member_user_uuids(member_uuids)
    recipients = {}
    no_key = []
    for x_uuid in user_uuids:
        x_user = backend.get_object(object_type="user", uuid=x_uuid)
        if not x_user:
            continue
        if not x_user.encrypt_public_key:
            no_key.append(x_user.name)
            continue
        recipients[x_uuid] = {
                        'name'          : x_user.name,
                        'public_key'    : x_user.encrypt_public_key,
                        }
    return recipients, no_key

def get_caller(callback=default_callback):
    """ The user we act for, whose key opens the passwords. """
    if not config.auth_token:
        msg = _("Passwords are encrypted on the client: no login user.")
        raise OTPmeException(msg)
    user = backend.get_object(object_type="user",
                            uuid=config.auth_token.owner_uuid)
    if not user:
        msg = _("Unknown login user.")
        raise OTPmeException(msg)
    return user

def offline_cache_setter(object_ids, config_object=None, append=False,
    delete=False, callback=default_callback, **kwargs):
    """ Resolve password_offline_cache to UUIDs and build the value.

    Set as OIDs of hosts, groups and roles of our site, e.g.
    host|<realm>/<site>/<host>, role|<realm>/<site>/<role> or
    group|<realm>/<group>. A name without a type is a host. Stored as UUIDs: a renamed object stays
    allowed, and a new one does not become allowed by taking over the
    name. One that is gone is removed by the UUID the getter shows for
    it.

    Registered with merging_setter, so it is here for -a and -d <oid>
    as well, with the object: what the hosts keep below it changes, and
    the users whose passwords those are are told to fetch them again.
    """
    current = []
    if config_object is not None:
        current = list(config_object.config_params.get(OFFLINE_CACHE_PARAMETER) or [])
    if isinstance(object_ids, str):
        object_ids = object_ids.split(",")
    given_uuids = []
    for x_object_id in object_ids:
        x_object_id = x_object_id.strip()
        if not x_object_id:
            continue
        if delete and x_object_id in current:
            x_uuid = x_object_id
        else:
            x_uuid = resolve_offline_cache_oid(x_object_id)
        if x_uuid in given_uuids:
            continue
        given_uuids.append(x_uuid)
    if delete:
        missing = [x for x in given_uuids if x not in current]
        if missing:
            msg = _("Config parameter does not have value: {value}")
            msg = msg.format(value=", ".join(offline_cache_getter(missing)))
            raise ValueError(msg)
        object_uuids = [x for x in current if x not in given_uuids]
    elif append:
        object_uuids = list(current)
        for x_uuid in given_uuids:
            if x_uuid in object_uuids:
                continue
            object_uuids.append(x_uuid)
    else:
        object_uuids = given_uuids
    if config_object is not None:
        notify_users_below(config_object, callback=callback)
    return object_uuids

def resolve_offline_cache_oid(object_id):
    """ The UUID of a host, group or role of password_offline_cache. """
    if "|" not in object_id:
        # The name finds a host of any site (see host.py), and only
        # the hosts of our site are asked about.
        x_host = backend.get_object(object_type="host",
                                    realm=config.realm,
                                    site=config.site,
                                    name=object_id)
        if not x_host or x_host.site != config.site:
            msg = _("Unknown host: {host_name}")
            msg = msg.format(host_name=object_id)
            raise ValueError(msg)
        return x_host.uuid
    # Verifies the OID itself and raises on a malformed one.
    x_oid = oid.get(object_id)
    if x_oid.object_type not in OFFLINE_CACHE_TYPES:
        msg = _("Must be a host, group or role: {object_id}")
        msg = msg.format(object_id=object_id)
        raise ValueError(msg)
    x_uuid = backend.get_uuid(x_oid)
    if not x_uuid:
        msg = _("Unknown object: {object_id}")
        msg = msg.format(object_id=object_id)
        raise ValueError(msg)
    # The passwords are synced to the nodes of our site alone, and it
    # is mgmtd there that asks. Asked of the full OID: the one of a
    # group has no site (group|<realm>/<group>).
    x_full_oid = backend.get_oid(uuid=x_uuid, instance=True)
    if x_full_oid.realm != config.realm or x_full_oid.site != config.site:
        msg = _("Not of this site: {object_id}")
        msg = msg.format(object_id=object_id)
        raise ValueError(msg)
    return x_uuid

def offline_cache_deller(o, callback=default_callback, **kwargs):
    """ password_offline_cache removed from <o>: tell its users. """
    notify_users_below(o, callback=callback)

def notify_users_below(o, callback=default_callback):
    """ Tell the users of the passwords below the unit or site <o> to
    fetch them again: which a host may keep is decided there.

    Every user that holds a key of one of them. More than need it, where
    a unit below sets the parameter itself -- they fetch once more, and
    what they keep is decided by mgmtd anyway (get_pass_cache()).
    """
    # Not without a job, see notify_cache_users(), and then without
    # loading every password first.
    if callback is default_callback:
        return
    passwords = backend.search(object_type="pass",
                            attribute="uuid",
                            value="*",
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    user_uuids = set()
    for x_pass in passwords:
        if o.type == "unit" \
        and not x_pass.rel_path.startswith(f"{o.rel_path}/"):
            continue
        user_uuids.update(x_pass.fernet_keys)
    notify_cache_users(user_uuids, callback=callback)

def offline_cache_getter(object_uuids, callback=default_callback, **kwargs):
    """ The hosts, groups and roles of password_offline_cache as OIDs. """
    if isinstance(object_uuids, str):
        object_uuids = object_uuids.split(",")
    object_ids = []
    for x_uuid in object_uuids:
        x_object_id = backend.get_oid(uuid=x_uuid,
                                    object_types=OFFLINE_CACHE_TYPES,
                                    full=False)
        if not x_object_id:
            # Show the unresolvable entry instead of hiding it.
            object_ids.append(x_uuid)
            continue
        object_ids.append(x_object_id)
    return object_ids

def get_offline_hosts(o):
    """ The UUIDs of the hosts, groups and roles whose hosts may keep
    <o> for offline use.

    The nearest unit that sets password_offline_cache wins, or the site
    (or the site alone, where it enforces the parameter). A unit that
    sets it empty keeps its passwords off every host. Not set anywhere,
    no host may.
    """
    object_uuids = o.get_config_parameter(OFFLINE_CACHE_PARAMETER,
                                          apply_getter=False)
    return list(object_uuids or [])

def is_offline_host(host_uuid, object_uuids, checked=None):
    """ Whether <host_uuid> is one of <object_uuids>, or in one of the
    groups and roles of it. A group or role that is disabled counts
    for nothing, the same as for shares.

    <checked> keeps what one group or role said, for the next password
    that names it.
    """
    if checked is None:
        checked = {}
    for x_uuid in object_uuids:
        if x_uuid == host_uuid:
            return True
        try:
            x_assigned = checked[x_uuid]
        except KeyError:
            x_assigned = False
            x_object = backend.get_object(uuid=x_uuid)
            if x_object and x_object.type in ("group", "role") \
            and x_object.enabled:
                x_assigned = bool(x_object.is_assigned_host(host_uuid))
            checked[x_uuid] = x_assigned
        if x_assigned:
            return True
    return False

def get_pass_cache(user, host_uuid):
    """ The passwords <user> may keep on the host <host_uuid>, to read
    them when no node can be reached.

    Only what the client gets anyway to read them, which is ciphertext
    (see get_cache_object()), and of that only the passwords the host
    is allowed to keep (password_offline_cache), the user may see the
    entries of (view:entries) and holds a key for. Nothing for a user
    whose private key is kept on the server: it decrypts there, and
    there is nothing to read offline with.
    """
    cache = {
            'realm'         : config.realm,
            'site'          : config.site,
            'user_uuid'     : user.uuid,
            'key_mode'      : user.key_mode,
            'objects'       : [],
            }
    if user.key_mode == "server":
        return cache
    passwords = backend.search(object_type="pass",
                            attribute="uuid",
                            value="*",
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    checked = {}
    for x_pass in sorted(passwords, key=lambda x: x.rel_path):
        if user.uuid not in x_pass.fernet_keys:
            continue
        if not is_offline_host(host_uuid, get_offline_hosts(x_pass),
                            checked=checked):
            continue
        if not x_pass.verify_acl("view:entries"):
            continue
        cache['objects'].append(x_pass.get_cache_object(user.uuid))
    return cache

def notify_cache_users(user_uuids, callback=default_callback):
    """ Tell the agents of <user_uuids> to fetch their passwords again.

    Through idled, once the job has written everything: told earlier,
    an agent could fetch what is about to be replaced. One message per
    user and job however many passwords it changed.

    Not without a job: the default callback runs no post methods, and
    what is put there would stay for the life of the process.
    """
    if callback is default_callback:
        return
    try:
        pending = callback._pass_cache_users
    except AttributeError:
        pending = set()
        callback._pass_cache_users = pending
        def post_method():
            from otpme.lib import idle
            for x_uuid in sorted(pending):
                x_user = backend.get_object(object_type="user",
                                            uuid=x_uuid)
                if not x_user:
                    continue
                idle.notify(username=x_user.name,
                            event_type="pass_changed",
                            data={})
        callback.post_methods.append(post_method)
    pending.update(user_uuids)

def show_passwords_of(o, callback=default_callback, **kwargs):
    """ Show the passwords that belong to the given object.

    For "otpme-node show_password <node> [entry]" and the same of hosts,
    devices and clients. The entry name stays on the client, so all
    passwords of the object we may read go there and the client picks.

    What may be read is said by each password (view:entries), not by
    the object it belongs to: an ACL there would only add a second
    door to a room that has one.
    """
    try:
        user = get_caller(callback=callback)
    except OTPmeException as e:
        return callback.error(str(e))
    passwords = backend.search(object_type="pass",
                            attribute=o.type,
                            value=o.uuid,
                            return_type="instance")
    objects = []
    for x_pass in sorted(passwords, key=lambda x: x.name):
        if not x_pass.verify_acl("view:entries"):
            continue
        objects.append(x_pass.get_request_object(user.uuid))
    if not objects:
        msg = _("No password belongs to {object_type} {object_name}.")
        msg = msg.format(object_type=o.type, object_name=o.name)
        return callback.error(msg)
    pass_request = {
                'action'        : "show",
                'key_mode'      : user.key_mode,
                'objects'       : objects,
                'recipients'    : {},
                }
    callback.pass_crypt(pass_request)
    return callback.ok()

def update_keys_of_all(all_passwords=False, unit=None,
    callback=default_callback, _caller="API", **kwargs):
    """ update_keys() for every password the login user may give keys of.

    "otpme-pass update_keys --all [--unit <unit>]": after
    password_store_members was signed anew, every password below has to
    be brought in line, and one at a time that is a command for each.
    Each password is done on its own, by its update_keys(), with its
    own members, lock and changelog -- the members of two passwords can
    differ (the parameter is inherited down the units). The ones without
    edit:keys are left out without a word, as a search leaves them out.
    """
    if not all_passwords:
        msg = _("Give a password, or --all for all you may give keys of.")
        return callback.error(msg)
    unit_path = None
    if unit:
        result = backend.search(object_type="unit",
                                attribute="rel_path",
                                value=unit,
                                realm=config.realm,
                                site=config.site,
                                return_attributes=['path'])
        if not result:
            msg = _("Unknown unit: {unit}")
            msg = msg.format(unit=unit)
            return callback.error(msg)
        unit_path = list(result)[0]
        unit_path = result[unit_path]['path']
    passwords = backend.search(object_type="pass",
                            attribute="uuid",
                            value="*",
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    done = []
    failed = []
    for x_pass in sorted(passwords, key=lambda x: x.path):
        if unit_path and not x_pass.path.startswith(f"{unit_path}/"):
            continue
        if not x_pass.verify_acl("edit:keys"):
            continue
        msg = _("Updating keys: {pass_path}")
        msg = msg.format(pass_path=x_pass.rel_path)
        callback.send(msg)
        try:
            result = x_pass.update_keys(callback=callback, _caller=_caller)
        except Exception as e:
            result = False
            msg = _("Failed to update keys: {pass_path}: {error}")
            msg = msg.format(pass_path=x_pass.rel_path, error=e)
            callback.send(msg, error=True)
        if result is False:
            failed.append(x_pass.rel_path)
            continue
        done.append(x_pass.rel_path)
    if not done and not failed:
        msg = _("No password you may give keys of.")
        return callback.error(msg)
    msg = _("Keys updated: {done}, failed: {failed}")
    msg = msg.format(done=len(done), failed=len(failed))
    if failed:
        msg = f"{msg}\n" + "\n".join(failed)
        return callback.error(msg)
    return callback.ok(msg)

def get_user_names(user_uuids):
    """ User names for the terminal, the UUID where there is no user. """
    names = []
    for x_uuid in user_uuids:
        x_oid = backend.get_oid(uuid=x_uuid, object_type="user",
                                instance=True)
        if not x_oid:
            names.append(x_uuid)
            continue
        names.append(x_oid.name)
    return sorted(names)

def sign_members_of(o, force=False, callback=default_callback):
    """ Sign password_store_members of a unit or site.

    The login user signs the members and the users they stand for now,
    with their own key (the key script does it, as for every signature
    of OTPme). What changed since their last signature is shown first.
    Whether the signature counts is up to the hosts: only a signer of
    type "password" configured there makes it count, see
    pass_crypt.verify_members().
    """
    if not o.verify_acl(f"set:config:{MEMBERS_PARAMETER}"):
        msg = _("Permission denied: {object_path}")
        msg = msg.format(object_path=o.path)
        return callback.error(msg, exception=PermissionDenied)
    if MEMBERS_PARAMETER not in o.config_params:
        msg = _("password_store_members is not set on {object_type} {object_name}.")
        msg = msg.format(object_type=o.type, object_name=o.name)
        return callback.error(msg)
    try:
        signer = get_caller(callback=callback)
    except OTPmeException as e:
        return callback.error(str(e))
    if not signer.sign_public_key:
        msg = _("User has no sign public key: {user_name}")
        msg = msg.format(user_name=signer.name)
        return callback.error(msg)
    member_uuids = sorted(get_member_uuids(o))
    user_uuids = sorted(get_member_user_uuids(member_uuids))
    signatures = get_signatures(o)

    # What changed since the last signature of this signer.
    try:
        signed_users = signatures[signer.uuid]['users']
    except KeyError:
        signed_users = []
    added = [x for x in user_uuids if x not in signed_users]
    removed = [x for x in signed_users if x not in user_uuids]
    lines = []
    for x_name in get_user_names(added):
        lines.append(f"+ {x_name}")
    for x_name in get_user_names(removed):
        lines.append(f"- {x_name}")
    if signer.uuid in signatures and not lines:
        msg = _("Signature is up to date.")
        return callback.ok(msg)
    if not lines:
        lines.append(", ".join(get_user_names(user_uuids)))
    if not force:
        msg = _("Sign password_store_members of {object_type} {object_name}?")
        msg = msg.format(object_type=o.type, object_name=o.name)
        msg = f"{msg}\n" + "\n".join(lines) + "\n(y/n): "
        answer = callback.ask(msg)
        if str(answer).lower() != "y":
            return callback.abort()

    from otpme.lib.classes.signing import OTPmeSignature
    sign_data = members_sign_data(o.uuid, member_uuids, user_uuids)
    sign_tags = [members_tag(o.uuid)]
    # Reload user (e.g. new keys).
    signer._load()
    sig = OTPmeSignature(signer_uuid=signer.uuid,
                        signer_oid=signer.oid.full_oid,
                        sign_obj=o.uuid,
                        sign_data=sign_data,
                        sign_ref=MEMBERS_PARAMETER,
                        tags=sign_tags)
    sign_request = {
                    'stdin_pass'    : False,
                    'key_mode'      : signer.key_mode,
                    'sign_key_type' : signer.sign_key_type,
                    'sign_info'     : sig.get_sign_info(),
                    'sign_data'     : sig.get_sign_template(),
                }
    signature = callback.sign(sign_request)
    if not signature:
        msg = _("Got empty signature.")
        return callback.error(msg)
    sig.add_sign(signature)
    # What the hosts will do, done here as well.
    try:
        sig.verify(signer.sign_public_key, sign_data, tags=sign_tags)
    except Exception as e:
        msg = _("Signature does not verify: {error}")
        msg = msg.format(error=e)
        return callback.error(msg)
    signatures[signer.uuid] = {
                        'members'   : member_uuids,
                        'users'     : user_uuids,
                        'signature' : sig.dumps(),
                        }
    set_signatures(o, signatures)
    o.set_changelog(f"signed '{MEMBERS_PARAMETER}'")
    return o._cache(callback=callback)

def show_members_of(o, callback=default_callback, **kwargs):
    """ The members, and what each signature says about them. """
    if not o.verify_acl(f"view:config:{MEMBERS_PARAMETER}"):
        msg = _("Permission denied: {object_path}")
        msg = msg.format(object_path=o.path)
        return callback.error(msg, exception=PermissionDenied)
    if MEMBERS_PARAMETER not in o.config_params:
        msg = _("password_store_members is not set on {object_type} {object_name}.")
        msg = msg.format(object_type=o.type, object_name=o.name)
        return callback.error(msg)
    member_uuids = sorted(get_member_uuids(o))
    user_uuids = sorted(get_member_user_uuids(member_uuids))
    lines = []
    lines.append(_("Members: {members}").format(
                members=", ".join(members_getter(member_uuids))))
    lines.append(_("Users: {users}").format(
                users=", ".join(get_user_names(user_uuids))))
    signatures = get_signatures(o)
    if not signatures:
        lines.append(_("Not signed."))
    for x_signer_uuid in sorted(signatures):
        x_entry = signatures[x_signer_uuid]
        x_signer = get_user_names([x_signer_uuid])[0]
        x_users = x_entry['users']
        added = [x for x in user_uuids if x not in x_users]
        removed = [x for x in x_users if x not in user_uuids]
        if sorted(x_entry['members']) == member_uuids \
        and not added and not removed:
            lines.append(_("Signed by {signer}: up to date").format(
                        signer=x_signer))
            continue
        lines.append(_("Signed by {signer}: signature outdated").format(
                    signer=x_signer))
        for x_name in get_user_names(added):
            lines.append(f"    + {x_name}")
        for x_name in get_user_names(removed):
            lines.append(f"    - {x_name}")
    return callback.ok("\n".join(lines))

def unsign_members_of(o, signer=None, force=False, callback=default_callback):
    """ Remove a signature of password_store_members of a unit or site.

    The login user's own one, or the one of <signer>: a user name, or the
    UUID show_members_of() prints for a signer that is gone. Removing
    needs what signing needs, the right to set the parameter.
    """
    if not o.verify_acl(f"set:config:{MEMBERS_PARAMETER}"):
        msg = _("Permission denied: {object_path}")
        msg = msg.format(object_path=o.path)
        return callback.error(msg, exception=PermissionDenied)
    if MEMBERS_PARAMETER not in o.config_params:
        msg = _("password_store_members is not set on {object_type} {object_name}.")
        msg = msg.format(object_type=o.type, object_name=o.name)
        return callback.error(msg)
    signatures = get_signatures(o)
    if signer is None:
        try:
            signer_uuid = get_caller(callback=callback).uuid
        except OTPmeException as e:
            return callback.error(str(e))
    elif signer in signatures:
        signer_uuid = signer
    else:
        result = backend.search(object_type="user",
                                attribute="name",
                                value=signer,
                                realm=config.realm,
                                return_type="uuid")
        if not result:
            msg = _("Unknown user: {user_name}")
            msg = msg.format(user_name=signer)
            return callback.error(msg)
        signer_uuid = result[0]
    signer_name = get_user_names([signer_uuid])[0]
    if signer_uuid not in signatures:
        msg = _("No signature of {signer} on {object_type} {object_name}.")
        msg = msg.format(signer=signer_name,
                        object_type=o.type,
                        object_name=o.name)
        return callback.error(msg)
    if not force:
        msg = _("Remove the signature of {signer} from {object_type} {object_name}? (y/n): ")
        msg = msg.format(signer=signer_name,
                        object_type=o.type,
                        object_name=o.name)
        answer = callback.ask(msg)
        if str(answer).lower() != "y":
            return callback.abort()
    signatures.pop(signer_uuid)
    set_signatures(o, signatures)
    o.set_changelog(f"removed signature of '{signer_name}' from '{MEMBERS_PARAMETER}'")
    return o._cache(callback=callback)

def register():
    register_oid()
    config.register_config_parameter(name="max_pass_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    # Whose users get the key of a new password, see get_member_users().
    # The members and their signatures in one value, see load_members().
    config.register_config_parameter(name=MEMBERS_PARAMETER,
                                    ctype=str,
                                    setter=members_setter,
                                    getter=members_getter,
                                    merging_setter=True,
                                    object_types=['site', 'unit'])
    # The hosts that may keep the passwords below for offline use, see
    # get_pass_cache().
    config.register_config_parameter(name=OFFLINE_CACHE_PARAMETER,
                                    ctype=list,
                                    setter=offline_cache_setter,
                                    getter=offline_cache_getter,
                                    deller=offline_cache_deller,
                                    merging_setter=True,
                                    object_types=['site', 'unit'])
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("pass", commands)
    # Who may see a password is said on its unit and on nothing above
    # it: no "+pass" for the site, so a recursive ACL of the site does
    # not reach the password objects, see Site.add_acls().
    config.register_default_acl("unit", "+pass")
    config.register_recursive_default_acl("unit", "+pass")
    # Which objects a password belongs to. Asked by the find_passwords
    # of these objects, on the site that owns the password.
    pass_types = ["pass"]
    config.register_index_attribute("node", sync=[],
                                    object_types=pass_types)
    config.register_index_attribute("host", sync=[],
                                    object_types=pass_types)
    config.register_index_attribute("device", sync=[],
                                    object_types=pass_types)
    config.register_index_attribute("client", sync=[],
                                    object_types=pass_types)

def register_object_unit():
    """ Register default unit for this object type. """
    # Its ACLs are set by hand: the site gives it none, see
    # Site.add_base_objects() and Site.add_acls().
    config.register_base_object("unit", DEFAULT_UNIT, no_acls=True)
    config.register_default_unit("pass", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    unit_name_re = oid.object_regex['unit']['name']
    pass_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    pass_path_re = f'{unit_path_re}[/]{pass_name_re}'
    # An OID is not a path, see accessgroup.py: no leading slash, and
    # the unit part is optional because the read OID has none.
    pass_oid_re = (f'pass[|]{realm_name_re}[/]{site_name_re}'
                f'([/]{unit_name_re})*[/]{pass_name_re}')
    oid.register_oid_schema(object_type="pass",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=pass_name_re,
                            path_regex=pass_path_re,
                            oid_regex=pass_oid_re)
    # Everything after realm and site: the unit path can be more than
    # one unit deep (passwords/<team>/<name>).
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="pass",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    # Not to the hosts: users get the passwords they may read through
    # their own login, not through the host they sit at.
    config.register_object_sync(host_type="node", object_type="pass")

def register_backend():
    """ Register object for the file backend. """
    pass_dir_extension = "pass"
    def path_getter(pass_oid, pass_uuid):
        return backend.config_path_getter(pass_oid, pass_dir_extension)
    def index_rebuild(objects):
        after = [
                'realm',
                'site',
                'unit',
                'group',
                'ca',
                'node',
                'host',
                'user',
                'token',
                'accessgroup',
                'client',
                'device',
                ]
        return backend.rebuild_object_index("pass", objects, after)
    # Register object to config.
    config.register_object_type(object_type="pass",
                            version=1,
                            tree_object=True,
                            uniq_name=True,
                            add_after=["node", "host", "device", "client"],
                            sync_after=["user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: OTPmePassword
    backend.register_object_type(object_type="pass",
                                dir_name_extension=pass_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

@match_class_typing
class OTPmePassword(OTPmeObject):
    """ Class that implements the OTPme password object. """
    commands = commands

    @classmethod
    def restore_object_data(cls, object_id, object_uuid, object_data, callback):
        """ Back from the trash or a backup: the users with a key fetch
        it, as after any other write (see _write()). The restore writes
        the config itself and not through us. """
        x_pass = backend.get_object(uuid=object_uuid)
        if not x_pass:
            return
        notify_cache_users(set(x_pass.fernet_keys), callback=callback)

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
        self.type = "pass"
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

        # Who may read a password is said on its unit, so a password
        # follows the ACLs of its unit.
        self.acl_inheritance_enabled = True

        # The objects this password belongs to.
        self.nodes = []
        self.hosts = []
        self.devices = []
        self.clients = []

        # The entries, as a Fernet token the client made, and per user
        # UUID the Fernet key encrypted with the encrypt public key of
        # that user. Nothing of an entry is held in the clear, see
        # otpme.lib.pass_crypt.
        self.payload = None
        self.fernet_keys = {}
        # Counted up on every write, so a copy can tell it is old.
        self.payload_revision = 0
        # Users that lost their key with a change: their hosts keep the
        # password for offline use and have to hear of it as well, see
        # _write().
        self._cache_notify_users = set()

        # Nodes of other sites get the name and nothing more.
        self._sync_fields = {}

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
                        'NODES'                     : {
                                                        'var_name'  : 'nodes',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'HOSTS'                     : {
                                                        'var_name'  : 'hosts',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'DEVICES'                   : {
                                                        'var_name'  : 'devices',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'CLIENTS'                   : {
                                                        'var_name'  : 'clients',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'PAYLOAD'                   : {
                                                        'var_name'  : 'payload',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        'FERNET_KEYS'               : {
                                                        'var_name'      : 'fernet_keys',
                                                        'type'          : dict,
                                                        'incremental'   : False,
                                                        'required'      : False,
                                                    },

                        'PAYLOAD_REVISION'          : {
                                                        'var_name'  : 'payload_revision',
                                                        'type'      : int,
                                                        'required'  : False,
                                                    },

                        }

        return object_config

    def _get_members(self, member_type):
        """ The objects of the given type this password belongs to. """
        if member_type == "node":
            return self.nodes
        if member_type == "host":
            return self.hosts
        if member_type == "device":
            return self.devices
        if member_type == "client":
            return self.clients
        msg = _("Unknown member type: {member_type}")
        msg = msg.format(member_type=member_type)
        raise OTPmeException(msg)

    def get_client_uuid(self, client_name: str):
        """ Get the UUID of a client of our site. """
        client = backend.get_object(object_type="client",
                                    realm=self.realm,
                                    site=self.site,
                                    name=client_name)
        if not client:
            return
        return client.uuid

    @check_acls(['add:client'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("add client {client_name}")
    def add_client(
        self,
        client_name: str=None,
        client_uuid: str=None,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Adds a client to this password. """
        if not client_uuid:
            client_uuid = self.get_client_uuid(client_name)
            if not client_uuid:
                msg = _("Client does not exist: {client_name}")
                msg = msg.format(client_name=client_name)
                return callback.error(msg)

        if client_uuid in self.clients:
            msg = _("Client is already assigned to {obj_type} '{obj_name}'.")
            msg = msg.format(obj_type=self.type, obj_name=self.name)
            return callback.error(msg)

        msg = _("Add client '{client_name}' to {object_type} '{object_name}'?: ")
        msg = msg.format(client_name=client_name or client_uuid,
                        object_type=self.type,
                        object_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_client",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.clients.append(client_uuid)
        # Update index.
        self.add_index("client", client_uuid)
        return self._cache(callback=callback)

    @check_acls(['remove:client'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("remove client {client_name}")
    def remove_client(
        self,
        client_name: str=None,
        client_uuid: str=None,
        force: bool=False,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Removes a client from this password. """
        if not client_uuid:
            client_uuid = self.get_client_uuid(client_name)
            if not client_uuid:
                msg = _("Client does not exist: {client_name}")
                msg = msg.format(client_name=client_name)
                return callback.error(msg)

        if client_uuid not in self.clients:
            msg = _("Client is not assigned to {obj_type} '{obj_name}'.")
            msg = msg.format(obj_type=self.type, obj_name=self.name)
            return callback.error(msg)

        msg = _("Remove client '{client_name}' from {object_type} '{object_name}'?: ")
        msg = msg.format(client_name=client_name or client_uuid,
                        object_type=self.type,
                        object_name=self.name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_client",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.clients.remove(client_uuid)
        # Update index.
        self.del_index("client", client_uuid)
        return self._cache(callback=callback)

    def get_request_object(self, user_uuid):
        """ What the client gets of us to read or write the entries. """
        request_object = {
                    'name'          : self.name,
                    'uuid'          : self.uuid,
                    'payload'       : self.payload,
                    'fernet_key'    : self.fernet_keys.get(user_uuid),
                    'key_users'     : list(self.fernet_keys),
                    }
        return request_object

    def get_cache_object(self, user_uuid):
        """ What a host keeps of us for offline use, see get_pass_cache().

        What the client gets to read the entries, and what "otpme-pass
        show" shows of us: where we are and whom we belong to. No more,
        it is on a host for as long as nobody fetches it again.
        """
        cache_object = self.get_request_object(user_uuid)
        cache_object['rel_path'] = self.rel_path
        cache_object['unit'] = os.path.dirname(self.rel_path)
        cache_object['description'] = self.description
        cache_object['payload_revision'] = self.payload_revision
        for x_type in ("node", "host", "device", "client"):
            x_names = []
            for x_uuid in self._get_members(x_type):
                x_oid = backend.get_oid(uuid=x_uuid,
                                        object_type=x_type,
                                        instance=True)
                if not x_oid:
                    continue
                x_names.append(x_oid.name)
            cache_object[f"{x_type}s"] = sorted(x_names)
        return cache_object

    def get_recipients(self, callback=default_callback):
        """ The users of password_store_members. """
        members_object = get_members_object(self)
        member_uuids = []
        if members_object:
            member_uuids = get_member_uuids(members_object)
        recipients, no_key = get_member_users(member_uuids)
        if no_key:
            msg = _("Users without an encrypt public key get no key: {users}")
            msg = msg.format(users=", ".join(sorted(no_key)))
            callback.send(msg)
        return recipients

    def _crypt(self, action, callback=default_callback):
        """ Have the client do <action> on our entries.

        The client decrypts with the key of the login user, changes and
        encrypts again, and hands back the payload and the keys of the
        members that had none. A new key ("rotated") replaces all keys.
        Keys only go to members.
        """
        try:
            user = get_caller(callback=callback)
        except OTPmeException as e:
            return callback.error(str(e))
        recipients = self.get_recipients(callback=callback)
        pass_request = {
                    'action'        : action,
                    'key_mode'      : user.key_mode,
                    'objects'       : [self.get_request_object(user.uuid)],
                    'recipients'    : recipients,
                    # The client checks these against the signers it
                    # knows, see pass_crypt.verify_members().
                    'members'       : get_members_request(self),
                    }
        try:
            response = callback.pass_crypt(pass_request)
        except Exception as e:
            msg = _("Client failed: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        try:
            payload = response['payload']
            fernet_keys = response['fernet_keys']
            rotated = response['rotated']
        except Exception:
            msg = _("Invalid answer from client.")
            return callback.error(msg)
        for x_uuid in fernet_keys:
            if x_uuid in recipients:
                continue
            msg = _("Client returned a key for a non-member: {uuid}")
            msg = msg.format(uuid=x_uuid)
            return callback.error(msg)
        if rotated:
            self._cache_notify_users.update(self.fernet_keys)
            self.fernet_keys = dict(fernet_keys)
        else:
            new_keys = dict(self.fernet_keys)
            new_keys.update(fernet_keys)
            self.fernet_keys = new_keys
        self.payload = payload
        self.payload_revision += 1
        return self._cache(callback=callback)

    def _run_entry_policies(self, method, callback=default_callback,
        _caller="API"):
        try:
            self.run_policies("modify", callback=callback, _caller=_caller)
            self.run_policies(method, callback=callback, _caller=_caller)
        except Exception:
            return False
        return True

    @check_acls(['add:entry'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("add entry")
    def add_entry(
        self,
        with_entry: bool=True,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add an entry. Its name and fields stay on the client. """
        if not with_entry:
            msg = _("Password already exists: {pass_name}")
            msg = msg.format(pass_name=self.name)
            return callback.error(msg, exception=AlreadyExists)
        if run_policies:
            if not self._run_entry_policies("add_entry",
                                            callback=callback,
                                            _caller=_caller):
                return callback.error()
        return self._crypt("add_entry", callback=callback)

    @check_acls(['edit:entry'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("change entry")
    def change_entry(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change an entry. """
        if run_policies:
            if not self._run_entry_policies("change_entry",
                                            callback=callback,
                                            _caller=_caller):
                return callback.error()
        return self._crypt("change_entry", callback=callback)

    @check_acls(['delete:entry'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("delete entry")
    def del_entry(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Delete an entry. """
        if run_policies:
            if not self._run_entry_policies("del_entry",
                                            callback=callback,
                                            _caller=_caller):
                return callback.error()
        return self._crypt("del_entry", callback=callback)

    @check_acls(['edit:keys'])
    @object_lock()
    @backend.transaction
    @audit_log()
    @object_changelog("update keys")
    def update_keys(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Give the members the key, take it from the ones that left.

        Somebody who left may still hold the key from an earlier read,
        so then the client makes a new one and encrypts the entries with
        it. What they read before stays read: change those passwords.
        """
        if run_policies:
            if not self._run_entry_policies("update_keys",
                                            callback=callback,
                                            _caller=_caller):
                return callback.error()
        return self._crypt("update_keys", callback=callback)

    def _read(self, action, callback=default_callback):
        """ Have the client show or list our entries. """
        try:
            user = get_caller(callback=callback)
        except OTPmeException as e:
            return callback.error(str(e))
        if not self.payload:
            msg = _("Password has no entries.")
            return callback.error(msg)
        pass_request = {
                    'action'        : action,
                    'key_mode'      : user.key_mode,
                    'objects'       : [self.get_request_object(user.uuid)],
                    'recipients'    : {},
                    }
        try:
            callback.pass_crypt(pass_request)
        except Exception as e:
            msg = _("Client failed: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        return callback.ok()

    @check_acls(['view:entries'])
    @audit_log()
    def show_password(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Show the entries, the passwords too. """
        return self._read("show", callback=callback)

    @check_acls(['view:entries'])
    def list_entries(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ List the entries, without their passwords. """
        return self._read("list", callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog("add")
    def add(
        self,
        node: Union[str,None]=None,
        host: Union[str,None]=None,
        device: Union[str,None]=None,
        client: Union[str,None]=None,
        with_entry: bool=False,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a password object.

        <node>, <host>, <device> and <client> name the object the
        password belongs to, e.g. the node whose iDRAC it opens. With
        <with_entry> its first entry is added as well; the entry itself
        comes from the client, see add_entry().
        """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Add object using parent class.
        add_result = super().add(verify_acls=verify_acls,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs)
        if not add_result:
            msg = _("Failed to add password.")
            return callback.error(msg)
        # Part of adding it: the ACL to add the password covers these,
        # and no policy is asked twice.
        add_kwargs = {
                    'force'         : True,
                    'run_policies'  : False,
                    'verify_acls'   : False,
                    'callback'      : callback,
                    }
        if node and not self.add_node(node_name=node, **add_kwargs):
            return callback.error()
        if host and not self.add_host(host_name=host, **add_kwargs):
            return callback.error()
        if device and not self.add_device(device_name=device, **add_kwargs):
            return callback.error()
        if client and not self.add_client(client_name=client, **add_kwargs):
            return callback.error()
        if with_entry:
            return self.add_entry(run_policies=False,
                                verify_acls=False,
                                callback=callback)
        return callback.ok()

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
        """ Delete password object. """
        if not self.exists():
            msg = _("Password does not exist.")
            return callback.error(msg)

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {pass_name}")
                    msg = msg.format(pass_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception:
                return callback.error()

        if not self.ask_delete_confirmation(force=force, callback=callback):
            return callback.abort()

        key_users = set(self.fernet_keys)
        # Delete object using parent class.
        result = super().delete(verbose_level=verbose_level,
                            force=force,
                            callback=callback,
                            **kwargs)
        if result is not False:
            # Gone here, so gone from the hosts that kept it as well.
            notify_cache_users(key_users, callback=callback)
        return result

    def _write(self, *args, callback: JobCallback=default_callback, **kwargs):
        """ Write the password, and tell the hosts that keep it.

        Every user that holds a key, and every one that lost it with
        this change: a host keeps what such a user may read offline
        (get_pass_cache()), and what it keeps must not stay behind what
        we hold -- least of all for somebody whose key was taken away.
        """
        result = super()._write(*args, callback=callback, **kwargs)
        # None is an object that had nothing to write.
        if not result:
            return result
        notify_users = set(self.fernet_keys) | self._cache_notify_users
        self._cache_notify_users = set()
        notify_cache_users(notify_users, callback=callback)
        return result

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
        """ Rename password object. """
        msg = _("Rename password '{pass_name}' to '{new_name}'?: ")
        msg = msg.format(pass_name=self.name, new_name=new_name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        # Build new OID.
        new_oid = oid.get(object_type="pass",
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
                ('nodes', 'node', None),
                ('hosts', 'host', None),
                ('devices', 'device', None),
                ('clients', 'client', None),
                ('fernet_keys', 'user', None, 'dict_keys'),
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
        """ Show password config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        for x_type, x_field in (('node', 'NODES'), ('host', 'HOSTS'),
                                ('device', 'DEVICES'), ('client', 'CLIENTS')):
            if not self.verify_acl(f"view:{x_field.lower()}") \
            and not self.verify_acl(f"add:{x_type}") \
            and not self.verify_acl(f"remove:{x_type}"):
                lines.append(f'{x_field}=""')
                continue
            x_members = []
            for x_uuid in self._get_members(x_type):
                x_oid = backend.get_oid(uuid=x_uuid,
                                        object_type=x_type,
                                        instance=True)
                # Show the UUID of an orphan instead of hiding it.
                if not x_oid:
                    x_members.append(x_uuid)
                    continue
                x_members.append(x_oid.name)
            x_members.sort()
            x_members = ",".join(x_members)
            lines.append(f'{x_field}="{x_members}"')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show password details. """
        return self.show_config(**kwargs)
