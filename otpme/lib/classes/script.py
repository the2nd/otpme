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
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import audit_log
from otpme.lib.changelog import object_changelog
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.otpme_acl import denied_msg
from otpme.lib.encoding.base import decode
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import OTPmeObject
from otpme.lib.classes.otpme_object import name_len_setter
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

read_acls = [
                "verify",
                "dump",
                #"run",
            ]

# Permission to point an object at this script, i.e. to make it run in
# that objects context. Not the same as being allowed to change it, which
# is edit:script.
write_acls = ["assign"]

read_value_acls = {
                "view"      : [ "script", "signatures" ],
                "verify"    : [ "signature" ],
            }

write_value_acls = {
                "add"       : [ "signature" ],
                "delete"    : [ "signature" ],
                "set"       : [
                                "config",
                            ],
                "edit"      : [
                                "script",
                            ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'default'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['script'],
                    'oargs'             : ['replace', 'sign'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['script'],
                    'oargs'             : ['replace', 'sign'],
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
    'show'   : {
            'default'    : {
                'missing'    : {
                    'method'            : cli.show_getter("script"),
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
                                        'limit',
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
            'default'    : {
                'missing'    : {
                    'method'            : cli.list_getter("script"),
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
                    'method'            : cli.list_getter("script"),
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
    'copy'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'copy',
                    'args'              : ['destination_script'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'dump',
                    'job_type'          : 'thread',
                    },
                },
            },
    'sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'sign',
                    'oargs'             : ['tags', 'stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'resign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'resign',
                    'oargs'             : ['stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_sign',
                    'oargs'             : ['username', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'verify_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'thread',
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
    'list_policies'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'list_policies',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
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
    'show_info'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'show_info',
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
    }

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(split=False, **kwargs):
    result = _get_value_acls(read_value_acls, write_value_acls, split=split, **kwargs)
    config_params = config.get_config_parameters("script")
    if split:
        read_acls = result[0]['view']
        set_acls = result[1]['set']
        enable_acls = result[1]['enable']
        disable_acls = result[1]['disable']
        edit_acls = result[1]['edit']
    else:
        read_acls = result['view']
        set_acls = result['set']
        enable_acls = result['enable']
        disable_acls = result['disable']
        edit_acls = result['edit']
    # A script has no status: nothing that loads or runs one reads it.
    # So there is nothing to disable, and no time to disable it at.
    read_acls.remove("status")
    read_acls.remove("auto_disable")
    enable_acls.remove("object")
    disable_acls.remove("object")
    edit_acls.remove("auto_disable")
    for x in config_params:
        acl = f"config:{x}"
        read_acls.append(acl)
        set_acls.append(acl)
    return result

def get_default_acls(**kwargs):
    acls = _get_default_acls(default_acls, **kwargs)
    acls += config.get_default_acls("script")
    return acls

def get_recursive_default_acls(**kwargs):
    acls = _get_recursive_default_acls(recursive_default_acls, **kwargs)
    acls += config.get_recursive_default_acls("script")
    return acls

DEFAULT_UNIT = "scripts"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.unit"]

def register():
    register_oid()
    config.register_config_parameter(name="max_script_name_len",
                                    ctype=int,
                                    default_value=64,
                                    setter=name_len_setter,
                                    object_types=['site', 'unit'])
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("script", commands)
    config.register_recursive_default_acl("site", "+script")
    config.register_default_acl("unit", "+script")
    config.register_recursive_default_acl("unit", "+script")

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("script", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['site']['name']
    unit_name_re = oid.object_regex['unit']['name']
    script_name_re = '([0-9a-z_.-])*'
    script_path_re = f'{unit_path_re}[/]{script_name_re}'
    # An OID is not a path, see accessgroup.py. Our read schema is the
    # full one, so the unit is always there and the part is required
    # rather than optional.
    #script_oid_re = f'script|{script_path_re}'
    script_oid_re = (f'script[|]{realm_name_re}[/]{site_name_re}'
                    f'([/]{unit_name_re})+[/]{script_name_re}')
    oid.register_oid_schema(object_type="script",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=script_name_re,
                            path_regex=script_path_re,
                            oid_regex=script_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="script",
                                getter=rel_path_getter)

def register_hooks():
    # Run by dump(). Not registered, an auth on action policy refused it
    # as an unknown hook.
    config.register_auth_on_action_hook("script", "dump")
    config.register_auth_on_action_hook("script", "sign")
    config.register_auth_on_action_hook("script", "add_sign")
    config.register_auth_on_action_hook("script", "del_sign")
    config.register_auth_on_action_hook("script", "show_config_parameters")
    config.register_auth_on_action_hook("script", "set_config_parameter")

def register_backend():
    """ Register object for the file backend. """
    script_dir_extension = "script"
    def path_getter(script_oid, script_uuid):
        return backend.config_path_getter(script_oid, script_dir_extension)
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
                'role',
                'policy',
                'resolver',
                ]
        return backend.rebuild_object_index("script", objects, after)
    # Register object to config.
    config.register_object_type(object_type="script",
                            version=1,
                            tree_object=True,
                            uniq_name=False,
                            add_after=["unit", "policy"],
                            sync_after=["user", "token"],
                            object_cache=512,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'unit', 'name'])
    # Register object to backend.
    class_getter = lambda: Script
    backend.register_object_type(object_type="script",
                                dir_name_extension=script_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="script")

@match_class_typing
class Script(OTPmeObject):
    """ Implements OTPme script object. """
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
        self.type = "script"

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

        self.script = None
        self.script_md5sum = None
        self.signable = True
        #self.signatures = {}
        # Scripts should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "EXTENSIONS",
                            "SIGNATURES",
                            "SCRIPT",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "EXTENSIONS",
                            "SIGNATURES",
                            "SCRIPT",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SCRIPT'                    : {
                                                        'var_name'  : 'script',
                                                        'type'      : str,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },

                        'SCRIPT_MD5'                : {
                                                        'var_name'  : 'script_md5sum',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },

                        'SIGNATURES'                : {
                                                        'var_name'  : 'signatures',
                                                        'type'      : dict,
                                                        'required'  : False,
                                                    },
            }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name: str):
        """ Set object name. """
        # Make sure name is lowercase.
        self.name = name.lower()

    def check_base_script(self):
        """ Check if script is a base script. """
        if self.unit == "scripts":
            base_scripts = config.get_base_objects("script")
            if self.name in base_scripts:
                return True
        return False

    def verify_acl(self, action: str, **kwargs):
        """ Verify ACLs required to allow <action>. """
        # Parent class cannot know the ACL to allow verification of signatures
        # e.g. "view:script" for script objects and "view_public_key" for SSH
        # tokens.
        if action == "verify_signature":
            if self._verify_acl("verify:signature") \
            or self._verify_acl("view:signatures") \
            or self._verify_acl("view:script"):
                return True

        if action == "get_signatures":
            if self._verify_acl("view:signatures") \
            or self.verify_acl("view:script"):
                return True

        # Finally try to verify ACL via parent class method. The kwargs
        # go only here: the ACLs above are other ones than the action.
        if self._verify_acl(action, **kwargs):
            return True

        return  False

    def get_sign_data(self, callback: JobCallback=default_callback, **kwargs):
        """ Return script to be signed by parent class method. """
        # No ACLs here: this is no command, and who calls it checked
        # what they need. verify_sign() takes verify:signature, and
        # with the ACLs of dump checked here that was not enough.
        script = self.dump(run_policies=False,
                        verify_acls=False,
                        callback=callback)
        return callback.ok(script)

    # What is signed is the content: who may not read it may not sign it.
    # get_sign_data() checks nothing, and when it still went through
    # dump() and that refused, the refusal was signed in its place.
    @check_acls(['view:script', 'dump'])
    def sign(self, **kwargs):
        """ Sign the script. """
        return super().sign(**kwargs)

    @check_acls(['view:script', 'dump'])
    def dump(
        self,
        run_policies: bool=True,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Return script as string. """
        if not self.script:
            if _caller == "CLIENT":
                return callback.error(_("Empty script."))
            else:
                return callback.abort()
        if run_policies:
            try:
                self.run_policies("dump", callback=callback, _caller=_caller)
            except Exception as e:
                msg = _("Error running policies: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)
        decoded_script = decode(self.script, "base64")
        if _caller == "API":
            return decoded_script
        if _caller == "CLIENT":
            return callback.dump(decoded_script)
        return callback.ok(decoded_script)

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
        """ Rename script. """
        if self.check_base_script():
            msg = _("Cannot rename base script.")
            return callback.error(msg)

        msg = _("Rename script '{script_name}' to '{new_name}'?: ")
        msg = msg.format(script_name=self.name, new_name=new_name)
        if not self.ask_change_confirmation(msg, force=force, callback=callback):
            return callback.abort()

        # Build new OID.
        new_oid = oid.get(object_type="script",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    def move(self, callback: JobCallback=default_callback, **kwargs):
        if self.check_base_script():
            msg = _("Cannot move base script.")
            return callback.error(msg)
        return super().move(callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    @audit_log(ignore_args=['script'])
    @object_changelog("add")
    def add(
        self,
        script: str,
        replace: bool=False,
        sign: bool=False,
        uuid: Union[str,None]=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a script. """
        if verify_acls:
            # With -r a script that is not there yet is added, and that
            # takes what adding takes.
            if replace and self.exists():
                if not self.verify_acl("edit:script"):
                    msg = denied_msg(self, "edit:script")
                    return callback.error(msg, exception=PermissionDenied)
            else:
                _unit = backend.get_object(object_type="unit",
                                        uuid=self.unit_uuid)
                if not _unit.verify_acl("add:script"):
                    msg = denied_msg(_unit, "add:script")
                    return callback.error(msg, exception=PermissionDenied)
        check_exists = True
        if replace:
            check_exists = False

        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(verify_acls=False,
                                check_exists=check_exists,
                                handle_uuid=False,
                                callback=callback,
                                **kwargs)
        if result is False:
            return callback.error()

        if self.exists():
            if not replace:
                return callback.error(_("Script already exists."))
        else:
            if replace:
                # If user requested to replace the script but it does not exist
                # we will create a new one.
                replace = False

        if not replace:
            if uuid:
                for t in config.tree_object_types:
                    x = backend.get_object(object_type=t, uuid=uuid)
                    if not x:
                        continue
                    msg = _("UUID conflict: {self_oid} <> {x_oid}")
                    msg = msg.format(self_oid=self.oid, x_oid=x.oid)
                    return callback.error(msg)
                self.uuid = uuid
            else:
                self.uuid = stuff.gen_uuid()

        # Set script.
        self.script = script
        # Gen script MD5 sum.
        script_md5sum = decode(self.script, "base64")
        script_md5sum = stuff.gen_md5(script_md5sum)
        self.script_md5sum = script_md5sum

        auto_sign = False
        if self.auto_sign:
            auto_sign = True
        if config.auth_user:
            if config.auth_user.autosign_enabled:
                auto_sign = True
        if auto_sign:
            sign = True

        if sign:
            if not config.auth_user:
                msg = _("Cannot update signatures: Not logged in")
                return callback.error(msg)

            # Try to resign script.
            callback.raise_exception = True
            try:
                sign_status = self.resign(force=True, callback=callback)
            except NoSignature:
                callback.raise_exception = False
                # Without existing signatures just add a new one.
                sign_status = self.sign(force=True, callback=callback)
            except Exception as e:
                sign_status = False
                msg = _("Resigning failed: {error}")
                msg = msg.format(error=e)
                callback.send(msg)
            finally:
                callback.raise_exception = False

            if not sign_status:
                msg = _("Auto-signing failed.")
                callback.send(msg)
        else:
            if replace and self.signatures:
                msg = _("NOTE: Please update script signatures after editing!!!")
                callback.send(msg)

        # When replacing the script we just need to commit our config.
        if replace:
            return self._cache(callback=callback)

        # Add object using parent class.
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    # The copy holds the content, so it takes what dump takes to read it.
    @check_acls(['view:script', 'dump'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("copy to {destination_script}")
    def copy(
        self,
        destination_script: str,
        force: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Copy the content of this script to another one. """
        # Resolv object path (e.g. unit/script).
        if "/" in destination_script:
            x = oid.resolve_path(destination_script, object_type='script')
            # Within the site: the signatures and the ACLs are of it.
            if x['realm'] != self.realm or x['site'] != self.site:
                msg = _("Cannot copy a script to another site.")
                return callback.error(msg)
            object_unit = x['unit']
            object_name = x['name']
        else:
            object_unit = self.unit
            object_name = destination_script

        # Check if object name does contain invalid chars.
        if not oid.check_name(object_type='script', object_name=object_name):
            return callback.error(_("Invalid destination script name."))

        # A name is unique within its unit only, so the destination is
        # looked up by its OID, not by its name.
        dst_oid = oid.get(object_type="script",
                        realm=self.realm,
                        site=self.site,
                        unit=object_unit,
                        name=object_name)
        if dst_oid.read_oid == self.oid.read_oid:
            msg = _("Cannot copy a script to itself.")
            return callback.error(msg)

        dst_script = backend.get_object(object_id=dst_oid)
        # Use existing script if it exists.
        if dst_script:
            # Check if we have permissions to replace destination script.
            if not dst_script.verify_acl("edit:script"):
                msg = denied_msg(dst_script, "edit:script")
                return callback.error(msg, exception=PermissionDenied)
            # Ask user for confirmation if needed.
            msg = _("Replace script '{name}'?: ")
            msg = msg.format(name=dst_script.name)
            if not self.ask_change_confirmation(msg, force=force, callback=callback):
                return callback.abort()
            return dst_script._copy_from(self, callback=callback)

        # Create new script instance.
        try:
            dst_script = Script(name=object_name,
                                unit=object_unit,
                                realm=self.realm,
                                site=self.site)
        except Exception as e:
            msg = _("Error loading destination script: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        # Try to add the new script.
        # With our callback: auto_sign signs the copy as it signs a script
        # added by hand, and asks the user to. Without it the signing went
        # to the default callback, reached no client and failed, and the
        # "Auto-signing failed." went nowhere: the copy stayed unsigned.
        try:
            add_status = dst_script.add(script=self.script, callback=callback)
            add_message = ""
        except Exception as e:
            add_message = str(e)
            add_status = False
        if not add_status:
            # add() said why itself, through the callback.
            if not add_message:
                return add_status
            return callback.error(add_message)

        # The signatures stay with the source. Each carries the tag
        # script:<uuid> of the source, and the copy looks for its own:
        # verify_sign, del_sign and get_sign --tags did not find them
        # there, and only resign could renew them. Sign the copy.
        return callback.ok()

    @object_lock(full_lock=True)
    @backend.transaction
    def _copy_from(self, source, callback: JobCallback=default_callback):
        """ Replace the content by that of <source>.

        The script that copies holds its own lock, and changelog entry:
        this one takes the lock of the destination, and the entry, which
        object_changelog writes only for the command it decorates.

        The signatures of the source are not taken, see copy(). Those of
        this script stay, as with add -r, and no longer match.
        """
        self.script = source.script
        # Of the content, as add() does it.
        script_md5sum = decode(self.script, "base64")
        self.script_md5sum = stuff.gen_md5(script_md5sum)
        if self.signatures:
            msg = _("NOTE: Please update script signatures after editing!!!")
            callback.send(msg)
        if self.changelog_enabled():
            action = f"copy from {source.rel_path}"
            self.add_changelog_entry(action=action, callback=callback)
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    @object_changelog("delete")
    def delete(
        self,
        force: bool=False,
        run_policies: bool=True,
        verify_acls: bool=True,
        add_to_trash: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Delete script. """
        if self.check_base_script():
            msg = _("Cannot delete base script.")
            return callback.error(msg)

        if not self.exists():
            return callback.error(_("Script does not exist."))

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
            except Exception as e:
                return callback.error()

        if not self.ask_delete_confirmation(force=force, callback=callback):
            return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force,
                                    add_to_trash=add_to_trash,
                                    callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show script config. """
        if not self.verify_acl("view_public:object"):
            msg = denied_msg(self, "view_public:object")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:script") or self.verify_acl("edit:script"):
            lines.append(f'SCRIPT_MD5="{self.script_md5sum}"')
        else:
            lines.append('SCRIPT_MD5=""')

        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show script details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
