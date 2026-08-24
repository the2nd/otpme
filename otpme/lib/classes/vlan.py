# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
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

DEFAULT_UNIT = "vlans"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

# Lowest/highest 802.1Q VLAN ID. 0 and 4095 are reserved.
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094

read_acls = []

# Permission to assign this VLAN to an object (e.g. a token or a host) via
# the "vlans" config parameter. This is what makes VLAN assignment delegable
# per VLAN instead of realm wide.
write_acls = ["assign"]

read_value_acls = {
                    "view"      : [
                                    "vlan_id",
                                    "tokens",
                                    "roles",
                                    "hosts",
                                    "devices",
                                ],
            }

write_value_acls = {
                    "edit"      : [
                                    "vlan_id",
                                ],
                    "add"       : [
                                    "token",
                                    "role",
                                    "host",
                                    "device",
                                ],
                    "remove"    : [
                                    "token",
                                    "role",
                                    "host",
                                    "device",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'vlan_id'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'oargs'             : ['unit', 'vlan_id'],
                    'job_type'          : 'process',
                    },
                },
            },
    'vlan_id'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'change_vlan_id',
                    'oargs'             : ['vlan_id'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_token'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_token'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_token',
                    'args'              : ['token_path'],
                    'job_type'          : 'process',
                    },
                },
            },
    'add_role'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_role',
                    'args'              : ['role_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_role'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'remove_role',
                    'args'              : ['role_name'],
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
                    'method'            : cli.show_getter("vlan"),
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
                    'method'            : cli.list_getter("vlan"),
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
                    'method'            : cli.list_getter("vlan"),
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
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls',],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl'],
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
    'show_acls'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_acls',
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
    config_params = config.get_config_parameters("vlan")
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
    acls += config.get_default_acls("vlan")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("vlan")
    return acls

def pick_member_vlan(vlans, object_uuid):
    """ Pick one of the VLANs that name the object at the same distance.

    There is nothing to tell them apart, so the choice is by name --
    an arbitrary rule, but the same one every time, which the order the
    backend returns them in is not. Says so, because a VLAN that
    depends on nothing anybody configured is worth noticing.
    """
    if len(vlans) == 1:
        return vlans[0]
    object_id = backend.get_oid(uuid=object_uuid)
    vlans = sorted(vlans, key=lambda x: x.name)
    log_msg = _("Object is in more than one VLAN at the same distance, using '{vlan}': {object_id}: {vlans}", log=True)[1]
    log_msg = log_msg.format(vlan=vlans[0].name,
                            object_id=object_id.read_oid,
                            vlans=", ".join(x.name for x in vlans))
    logger.warning(log_msg)
    return vlans[0]

def get_member_vlan(object_uuid, object_type, site_uuid=None):
    """ Get the VLAN of our site the given object is a member of.

    Only VLANs of our own site: a VLAN is a network we run, and who is
    in it is ours to say. What another site puts into its VLANs is its
    own business, and it cannot put anything into ours -- the member
    lists live on the VLAN object, which only we can edit. That is what
    makes this the direct way to assign VLANs and the reason it needs
    none of the trust checks the "vlans" config parameter needs.

    The more specific assignment wins: the object named itself, then
    the role it is in, then the role that role is in, and so on. So a
    single token can be moved out of the VLAN of its role, and a role
    nested in another can have a VLAN of its own -- the same rule all
    the way up, instead of whichever VLAN the backend happened to
    return first.
    """
    if site_uuid is None:
        site_uuid = config.site_uuid
    site = backend.get_object(object_type="site", uuid=site_uuid)
    if not site:
        return
    vlans = []
    for vlan in backend.search(object_type="vlan",
                            attribute="uuid",
                            value="*",
                            realm=site.realm,
                            site=site.name,
                            return_type="instance"):
        if not vlan.enabled:
            continue
        vlans.append(vlan)
    if not vlans:
        return

    # Named by a VLAN itself.
    x_vlans = [x for x in vlans if object_uuid in x.get_members(object_type)]
    if x_vlans:
        return pick_member_vlan(x_vlans, object_uuid)

    # Through its roles, closest first. One step per round: the roles
    # holding the object, then the roles holding those, until a VLAN
    # names one of them or there are no roles left above.
    check_uuids = backend.search(object_type="role",
                                attribute=object_type,
                                value=object_uuid,
                                return_type="uuid")
    seen_uuids = list(check_uuids)
    while check_uuids:
        x_vlans = [x for x in vlans
                if [y for y in check_uuids if y in x.roles]]
        if x_vlans:
            return pick_member_vlan(x_vlans, object_uuid)
        # The roles above the ones we just checked. Roles can be nested
        # into each other in a loop, so anything seen before is done.
        parent_uuids = backend.search(object_type="role",
                                    attribute="role",
                                    values=check_uuids,
                                    return_type="uuid")
        check_uuids = [x for x in parent_uuids if x not in seen_uuids]
        seen_uuids += check_uuids
    return

def get_vlan_trusts(site_uuid, object_site_uuid):
    """ Get our VLAN trusts that apply to objects of the given site.

    Returns them in the configured order, as (vlan_site_uuid, vlan_uuid)
    tuples, where None means "any".
    """
    site = backend.get_object(object_type="site", uuid=site_uuid)
    if not site:
        return []
    try:
        trusts = site.get_config_parameter("vlan_trusts", apply_getter=False)
    except Exception:
        trusts = None
    if not trusts:
        return []
    vlan_trusts = []
    for entry in trusts:
        trust_vlan_site_uuid = None
        trust_vlan_uuid = None
        if ":" in entry:
            trust_site_uuid, trust_vlan_site_uuid = entry.split(":", 1)
            if "/" in trust_vlan_site_uuid:
                trust_vlan_site_uuid, trust_vlan_uuid = \
                                    trust_vlan_site_uuid.split("/", 1)
        else:
            trust_site_uuid = entry
        if trust_site_uuid != object_site_uuid:
            continue
        vlan_trusts.append((trust_vlan_site_uuid, trust_vlan_uuid))
    return vlan_trusts

def site_allows_vlan(site_uuid, object_site_uuid, vlan_site_uuid, vlan_uuid):
    """ May we hand out the given VLAN for an object of the given site?

    The VLAN we hand out is switched in the network of the site serving
    the RADIUS request, whichever site owns the VLAN object. So that site,
    and only that site, decides, via its "vlan_trusts" config parameter.
    Without this a site holding the users (e.g. the master site) could put
    them into any VLAN of our network. Assigning a VLAN also needs the
    "assign" ACL on it, but that ACL is checked by the site making the
    assignment, against its own copy of the VLAN, so it is not our consent.

    Our own VLANs assigned to our own objects need no entry.
    """
    if object_site_uuid == site_uuid and vlan_site_uuid == site_uuid:
        return True
    for trust_vlan_site_uuid, trust_vlan_uuid in get_vlan_trusts(site_uuid,
                                                        object_site_uuid):
        if trust_vlan_site_uuid is None:
            return True
        if trust_vlan_site_uuid != vlan_site_uuid:
            continue
        if trust_vlan_uuid is None:
            return True
        if trust_vlan_uuid == vlan_uuid:
            return True
    return False

def check_vlan_id(vlan_id):
    """ Make sure the given VLAN ID is a valid 802.1Q tag. """
    try:
        _vlan_id = int(vlan_id)
    except (TypeError, ValueError) as err:
        msg = _("VLAN ID must be a number: {vlan_id}")
        msg = msg.format(vlan_id=vlan_id)
        raise OTPmeException(msg) from err
    if _vlan_id < MIN_VLAN_ID or _vlan_id > MAX_VLAN_ID:
        msg = _("VLAN ID out of range ({min_id}-{max_id}): {vlan_id}")
        msg = msg.format(min_id=MIN_VLAN_ID,
                        max_id=MAX_VLAN_ID,
                        vlan_id=vlan_id)
        raise OTPmeException(msg)
    return str(_vlan_id)

def register():
    register_oid()
    config.register_config_parameter(name="max_vlan_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("vlan", commands)
    config.register_recursive_default_acl("site", "+vlan")
    config.register_default_acl("unit", "+vlan")
    config.register_recursive_default_acl("unit", "+vlan")
    config.register_index_attribute("vlan_id")

def register_hooks():
    config.register_auth_on_action_hook("vlan", "change_vlan_id")
    config.register_auth_on_action_hook("vlan", "set_config_parameter")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("vlan", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    vlan_name_re = '([0-9A-Za-z]([0-9A-Za-z_.-]*[0-9A-Za-z]){0,})'
    vlan_path_re = f'{unit_path_re}[/]{vlan_name_re}'
    vlan_oid_re = f'vlan|{vlan_path_re}'
    oid.register_oid_schema(object_type="vlan",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=vlan_name_re,
                            path_regex=vlan_path_re,
                            oid_regex=vlan_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="vlan",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="vlan")

def register_backend():
    """ Register object for the file backend. """
    vlan_dir_extension = "vlan"
    def path_getter(vlan_oid, vlan_uuid):
        return backend.config_path_getter(vlan_oid, vlan_dir_extension)
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
                ]
        return backend.rebuild_object_index("vlan", objects, after)
    # Register object to config.
    config.register_object_type(object_type="vlan",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["host"],
                            sync_after=["user", "token"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Vlan
    backend.register_object_type(object_type="vlan",
                                dir_name_extension=vlan_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

@match_class_typing
class Vlan(OTPmeObject):
    """ Class that implements OTPme VLAN object. """
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
        self.type = "vlan"
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

        # The 802.1Q tag. Optional: switches that are configured with named
        # VLANs (e.g. Cisco) accept the VLAN name in Tunnel-Private-Group-Id,
        # so without a VLAN ID we hand out the object name.
        self.vlan_id = None

        # VLANs should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            # A site may hand out a VLAN of an other site
                            # (see the "vlan_trusts" config parameter), so
                            # nodes of other sites need the VLAN ID. Without
                            # it they would send the VLAN name to the switch.
                            "VLAN_ID",
                            "EXTENSIONS",
                            "OBJECT_CLASSES",
                            "EXTENSION_ATTRIBUTES",
                            ]
                        },
                    }

    def _set_name(self, name: str):
        """ Set object name. """
        # VLAN names are passed to the switch as is, so keep the case.
        self.name = str(name)

    def set_variables(self):
        """ Set instance variables. """
        return True

    def _get_object_config(self, **kwargs):
        """ Get object config dict. """
        object_config = {
                        'VLAN_ID'                   : {
                                                        'var_name'  : 'vlan_id',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        # Members. The other way round to assign a VLAN:
                        # instead of naming the VLAN on the object (its
                        # "vlans" config parameter), name the object on
                        # the VLAN. The assignment then belongs to the
                        # site running the network, which is the site
                        # that has to answer for it, and a site can make
                        # all of its assignments without touching
                        # objects owned somewhere else.
                        'TOKENS'                    : {
                                                        'var_name'  : 'tokens',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },

                        'ROLES'                     : {
                                                        'var_name'  : 'roles',
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

                        }

        return object_config

    def get_vlan(self):
        """ Get the value to hand out via RADIUS (Tunnel-Private-Group-Id).

        The VLAN ID wins if one is configured. Without it the object name is
        used, which is what named-VLAN switch configs expect.
        """
        if self.vlan_id:
            return self.vlan_id
        return self.name

    def get_members(self, member_type):
        """ Members of the given type. """
        if member_type == "token":
            return self.tokens
        if member_type == "role":
            return self.roles
        if member_type == "host":
            return self.hosts
        if member_type == "device":
            return self.devices
        msg = _("Unknown member type: {member_type}")
        msg = msg.format(member_type=member_type)
        raise OTPmeException(msg)

    def check_member_vlan(self, member_type, member_uuid,
        callback: JobCallback=default_callback):
        """ Make sure the object is not a member of another VLAN.

        One VLAN per site, the same rule the "vlans" config parameter
        enforces: an object can only be in one of the VLANs of a network.
        Only direct membership counts -- being in a VLAN through a role
        is what a direct entry is meant to override.
        """
        for x_vlan in backend.search(object_type="vlan",
                                    attribute="uuid",
                                    value="*",
                                    realm=self.realm,
                                    site=self.site,
                                    return_type="instance"):
            if x_vlan.uuid == self.uuid:
                continue
            if member_uuid not in x_vlan.get_members(member_type):
                continue
            msg = _("Object is already a member of VLAN: {vlan}")
            msg = msg.format(vlan=x_vlan.rel_path)
            return callback.error(msg)
        return True

    def add_token(self, token_path: str,
        callback: JobCallback=default_callback, **kwargs):
        """ Add token to VLAN. """
        if "/" not in token_path:
            msg = _("Invalid token path: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        token_user = token_path.split("/")[0]
        token_name = token_path.split("/")[1]
        token = backend.get_object(object_type="token",
                                    realm=config.realm,
                                    user=token_user,
                                    name=token_name)
        if not token:
            msg = _("Unknown token: {token_path}")
            msg = msg.format(token_path=token_path)
            return callback.error(msg)
        check_result = self.check_member_vlan("token", token.uuid,
                                            callback=callback)
        if check_result is not True:
            return check_result
        return super().add_token(token_path=token_path,
                                callback=callback, **kwargs)

    def add_role(self, role_name: str=None, role_uuid: str=None,
        callback: JobCallback=default_callback, **kwargs):
        """ Add role to VLAN. """
        if role_name:
            role_uuid = self.get_role_uuid(role_name, callback=callback)
        if not role_uuid:
            msg = "Need <role_name> or <role_uuid>."
            raise OTPmeException(msg)
        check_result = self.check_member_vlan("role", role_uuid,
                                            callback=callback)
        if check_result is not True:
            return check_result
        return super().add_role(role_name=role_name,
                                role_uuid=role_uuid,
                                callback=callback, **kwargs)

    def add_host(self, host_name: str=None, host_uuid: str=None,
        callback: JobCallback=default_callback, **kwargs):
        """ Add host to VLAN. """
        if not host_uuid:
            host = backend.get_object(object_type="host",
                                    realm=config.realm,
                                    site=self.site,
                                    name=host_name)
            if not host:
                msg = _("Host does not exist: {host_name}")
                msg = msg.format(host_name=host_name)
                return callback.error(msg)
            host_uuid = host.uuid
        check_result = self.check_member_vlan("host", host_uuid,
                                            callback=callback)
        if check_result is not True:
            return check_result
        return super().add_host(host_name=host_name,
                                host_uuid=host_uuid,
                                callback=callback, **kwargs)

    def add_device(self, device_name: str=None, device_uuid: str=None,
        callback: JobCallback=default_callback, **kwargs):
        """ Add device to VLAN. """
        if not device_uuid:
            device = backend.get_object(object_type="device",
                                    realm=config.realm,
                                    site=self.site,
                                    name=device_name)
            if not device:
                msg = _("Device does not exist: {device_name}")
                msg = msg.format(device_name=device_name)
                return callback.error(msg)
            device_uuid = device.uuid
        check_result = self.check_member_vlan("device", device_uuid,
                                            callback=callback)
        if check_result is not True:
            return check_result
        return super().add_device(device_name=device_name,
                                device_uuid=device_uuid,
                                callback=callback, **kwargs)

    @check_acls(['edit:vlan_id'])
    @object_lock()
    @audit_log()
    @object_changelog("change VLAN ID {vlan_id}")
    def change_vlan_id(
        self,
        vlan_id: Union[str,int,None]=None,
        force: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Change VLAN ID. """
        msg = _("Change VLAN ID of VLAN '{vlan_name}' to '{vlan_id}'?: ")
        msg = msg.format(vlan_name=self.name, vlan_id=vlan_id)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        if vlan_id is None or vlan_id == "":
            self.vlan_id = None
            self.del_index("vlan_id")
            return self._cache(callback=callback)
        try:
            vlan_id = check_vlan_id(vlan_id)
        except OTPmeException as e:
            return callback.error(str(e))
        # add_index() appends, so drop the old ID or the object stays
        # searchable (and shows up) under both.
        if self.vlan_id:
            self.del_index("vlan_id", self.vlan_id)
        self.vlan_id = vlan_id
        self.add_index("vlan_id", vlan_id)
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    @object_changelog("add")
    def add(
        self,
        vlan_id: Union[str,int,None]=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a VLAN. """
        # Fail before creating the object if the ID is not usable.
        if vlan_id is not None:
            try:
                check_vlan_id(vlan_id)
            except OTPmeException as e:
                return callback.error(str(e))
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()
        # Add object using parent class.
        add_result = super().add(verify_acls=verify_acls,
                                verbose_level=verbose_level,
                                callback=callback, **kwargs)
        if not add_result:
            msg = _("Failed to add VLAN.")
            return callback.error(msg)
        if vlan_id is not None:
            self.change_vlan_id(vlan_id,
                                force=True,
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
        """ Delete VLAN. """
        if not self.exists():
            msg = _("VLAN does not exist.")
            return callback.error(msg)

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {vlan_name}")
                    msg = msg.format(vlan_name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception:
                return callback.error()

        # Assignments live in the "vlans" config parameter of the assigned
        # objects, which is not indexed, so we cannot list them here.
        msg = _("Objects the VLAN is assigned to will keep an unresolvable assignment.")
        # Members are the other way round: they live on us and go away
        # with us, so nothing is left behind -- but the objects lose
        # their VLAN, which is worth saying out loud.
        member_count = (len(self.tokens) + len(self.roles)
                        + len(self.hosts) + len(self.devices))
        if member_count > 0:
            member_msg = _("The VLAN still has {member_count} member(s) which will lose their VLAN.")
            member_msg = member_msg.format(member_count=member_count)
            msg = f"{msg} {member_msg}"
        if not self.ask_delete_confirmation(force=force,
                                            exception=msg,
                                            callback=callback):
            return callback.abort()

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
        """ Rename VLAN. """
        msg = _("Rename VLAN '{vlan_name}' to '{new_name}'?: ")
        msg = msg.format(vlan_name=self.name, new_name=new_name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        # Build new OID.
        new_oid = oid.get(object_type="vlan",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show VLAN config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:vlan_id"):
            vlan_id = self.vlan_id
            if vlan_id is None:
                vlan_id = ""
            lines.append(f'VLAN_ID="{vlan_id}"')
        else:
            lines.append('VLAN_ID=""')

        for x_type, x_field in (('token', 'TOKENS'), ('role', 'ROLES'),
                                ('host', 'HOSTS'), ('device', 'DEVICES')):
            if not self.verify_acl(f"view:{x_field.lower()}") \
            and not self.verify_acl(f"add:{x_type}") \
            and not self.verify_acl(f"remove:{x_type}"):
                lines.append(f'{x_field}=""')
                continue
            x_members = []
            for x_uuid in self.get_members(x_type):
                x_oid = backend.get_oid(uuid=x_uuid,
                                        object_type=x_type,
                                        instance=True)
                # Show the UUID of an orphan member instead of hiding it.
                if not x_oid:
                    x_members.append(x_uuid)
                    continue
                if x_type == "token":
                    x_members.append(x_oid.rel_path)
                else:
                    x_members.append(x_oid.name)
            x_members.sort()
            x_members = ",".join(x_members)
            lines.append(f'{x_field}="{x_members}"')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show VLAN details. """
        return self.show_config(**kwargs)
