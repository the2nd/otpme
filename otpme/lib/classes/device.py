# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import audit_log
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeObject
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

DEFAULT_UNIT = "devices"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]

read_acls = []
write_acls = []

read_value_acls = {
                    "view"      : [
                                    "mac_address",
                                    "policy",
                                ],
            }

write_value_acls = {
                    "edit"    : [
                                    "mac_address",
                                ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
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
    'touch'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'touch',
                    'job_type'          : 'process',
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_getter("device"),
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
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_getter("device"),
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
                    'method'            : cli.list_getter("device"),
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
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'job_type'          : 'process',
                    },
                },
            },
    'enable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable',
                    'job_type'          : 'process',
                    },
                },
            },
    'rename'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'rename',
                    'args'              : ['new_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'move'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'move',
                    'args'              : ['new_unit'],
                    'oargs'             : ['keep_acls'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_acl_inheritance'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_acl_inheritance'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_acl_inheritance',
                    'job_type'          : 'process',
                    },
                },
            },
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_policies',
                    'job_type'          : 'process',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
                    },
                },
            },
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls',],
                    'dargs'             : {'recursive_acls':False, 'apply_default_acls':False},
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
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
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'remove_policy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_policy',
                    'args'              : ['policy_name'],
                    'job_type'          : 'process',
                    },
                },
            },
    'description'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_description',
                    'oargs'             : ['description'],
                    'job_type'          : 'process',
                    },
                },
            },
    'export'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'export_config',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'mac'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_mac',
                    'args'              : ['mac_address'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_config_param',
                    'args'              : ['parameter'],
                    'oargs'             : ['value', 'append', 'delete'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config_parameters',
                    'oargs'              : ['parameter'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'remove_orphans'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'remove_orphans',
                    'oargs'             : ['recursive'],
                    'job_type'          : 'process',
                    },
                },
            },
    '_show_config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'show_config',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_object_classes'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_object_classes',
                    'job_type'          : 'thread',
                    },
                },
            },
    'show_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_default_acls'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_supported_acls',
                    'args'              : { 'acl_types' : 'default_acls' },
                    'job_type'          : 'thread',
                    },
                },
            },
    '_show_supported_recursive_default_acls'   : {
            'OTPme-mgmt-1.0'    : {
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
    config_params = config.get_config_parameters("device")
    if split:
        read_acls = result[0]['view']
        write_acls = result[1]['edit']
    else:
        read_acls = result['view']
        write_acls = result['edit']
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        write_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("device")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("device")
    return acls

def register():
    register_oid()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("device", commands)
    config.register_recursive_default_acl("site", "+device")
    config.register_default_acl("unit", "+device")
    config.register_recursive_default_acl("unit", "+device")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_base_object("unit", DEFAULT_UNIT)
    config.register_default_unit("device", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    device_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    device_path_re = f'{unit_path_re}[/]{device_name_re}'
    device_oid_re = f'device|{device_path_re}'
    oid.register_oid_schema(object_type="device",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=device_name_re,
                            path_regex=device_path_re,
                            oid_regex=device_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="device",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="device")

def register_backend():
    """ Register object for the file backend. """
    device_dir_extension = "device"
    def path_getter(device_oid, device_uuid):
        return backend.config_path_getter(device_oid, device_dir_extension)
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
        return backend.rebuild_object_index("device", objects, after)
    # Register object to config.
    config.register_object_type(object_type="device",
                            tree_object=True,
                            uniq_name=True,
                            add_after=["node"],
                            object_cache=1024,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Device
    backend.register_object_type(object_type="device",
                                dir_name_extension=device_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

@match_class_typing
class OTPmeDevice(OTPmeObject):
    """ Class that implements OTPme device object. """
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        # Call parent class init.
        super(OTPmeDevice, self).__init__(object_id=object_id, **kwargs)
        # List and dict attributes must be set after calling super because
        # self.incremental_update is only available after calling super.
        self.mac_address = None

    def authenticate(self, **kwargs):
        """ Wrapper to call auth handler. """
        from otpme.lib.classes.auth_handler import AuthHandler
        auth_handler = AuthHandler()
        start_time = time.time()
        auth_status = auth_handler.authenticate(user=self, **kwargs)
        end_time = time.time()
        duration = float(end_time - start_time)
        log_msg = _("Authentication took {duration} seconds.", log=True)[1]
        log_msg = log_msg.format(duration=duration)
        logger.debug(log_msg)
        return auth_status

    @check_acls(['edit:mac_address'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_mac(
        self,
        mac_address: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Set device MAC address. """
        if not stuff.is_mac_address(mac_address):
            msg = _("Invalid MAC address.")
            return callback.error(msg)
        if self.mac_address == mac_address:
            msg = _("MAC address already set to: {mac_address}")
            msg = msg.format(mac_address=mac_address)
            return callback.error(msg)
        result = backend.search(attribute="mac_address",
                                value=mac_address,
                                return_type="instance")
        if result:
            msg = _("MAC address already exists: {object}")
            msg = msg.format(object=result[0])
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_mac",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.mac_address = mac_address
        self.update_index('mac_address', mac_address)
        return self._cache(callback=callback)

    def show_config(self, config_lines=[], callback: JobCallback=default_callback, **kwargs):
        """ Show role config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if self.verify_acl("view:mac_address"):
            config_lines.append(f'MAC="{self.mac_address}"')
        else:
            config_lines.append('MAC=""')

        return OTPmeObject.show_config(self,
                                    config_lines=config_lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show role details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)

@match_class_typing
class Device(OTPmeDevice):
    """ Class that implements OTPme device object. """
    commands = commands
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        self.type = "device"
        # Call parent class init.
        super(Device, self).__init__(object_id=object_id, **kwargs)

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Roles should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "MAC_ADDRESS",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "MAC_ADDRESS",
                            ]
                        },
                    }

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()

    def set_variables(self):
        """ Set instance variables. """
        return True

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'MAC_ADDRESS'               : {
                                                        'var_name'  : 'mac_address',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log()
    def add(
        self,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a device. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(check_exists=False,
                                    callback=callback,
                                    **kwargs)
        if result is False:
            return callback.error()
        # Add device.
        add_result = super(Device, self).add(callback=callback, **kwargs)
        # Check for default accessgroup.
        device_ag = self.get_config_parameter("devices_accessgroup")
        if device_ag:
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=device_ag,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if result:
                ag = result[0]
                ag.add_device(self.name, verify_acl=False, callback=callback)
                ag._cache(callback=callback)
            else:
                msg = _("Unknown accessgroup: {ag}")
                msg = msg.format(ag=device_ag)
                callback.error(msg)
        return add_result

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(
        self,
        force: bool=False,
        verify_acls: bool=True,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete a device. """
        if not self.exists():
            return callback.error("Device does not exist.")

        # Check for default accessgroup.
        result = backend.search(object_type="accessgroup",
                                attribute="device",
                                value=self.uuid,
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        for ag in result:
            ag.remove_device(self.name, verify_acl=False, callback=callback)
            ag._cache(callback=callback)

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = f"delete:{self.type}"
                if not parent_object.verify_acl(del_acl):
                    msg = _("Permission denied: {name}")
                    msg = msg.format(name=self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if not self.ask_delete_confirmation(force=force, callback=callback):
            return callback.abort()

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        return super(Device, self).delete(callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename device. """
        # Build new OID.
        new_oid = oid.get(object_type="device",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)
