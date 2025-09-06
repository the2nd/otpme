# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import decode
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.otpme_object import OTPmeObject
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

write_acls = []

read_value_acls = {
                "view"      : [ "script", "signature" ],
                "verify"    : [ "signature" ],
            }

write_value_acls = {
                "add"       : [ "signature" ],
                "delete"    : [ "signature" ],
                "edit"      : [
                                "config",
                                "script",
                            ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['script'],
                    'oargs'             : ['replace'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['script'],
                    'oargs'             : ['replace'],
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
                    'method'            : cli.show_getter("script"),
                    'oargs'              : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'max_policies',
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
    'copy'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'copy',
                    'args'              : ['destination_script'],
                    'job_type'          : 'process',
                    },
                },
            },
    'dump'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump',
                    'job_type'          : 'thread',
                    },
                },
            },
    'sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'sign',
                    'oargs'             : ['tags', 'stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'resign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'resign',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sign',
                    'oargs'             : ['signature', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sign',
                    'oargs'             : ['username', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'verify_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign_data',
                    'oargs'             : ['tags'],
                    'job_type'          : 'thread',
                    },
                },
            },
    'get_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'thread',
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
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls',],
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
    'list_policies'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_policies',
                    'job_type'          : 'thread',
                    'oargs'             : ['return_type', 'policy_types'],
                    'dargs'             : {'return_type':'name', 'ignore_hooks':True},
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
    'config'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'set_config_param',
                    'args'              : ['parameter', 'value'],
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def get_acls(**kwargs):
    return _get_acls(read_acls, write_acls, **kwargs)

def get_value_acls(**kwargs):
    return _get_value_acls(read_value_acls, write_value_acls, **kwargs)

def get_default_acls(**kwargs):
    return _get_default_acls(default_acls, **kwargs)

def get_recursive_default_acls(**kwargs):
    return _get_recursive_default_acls(recursive_default_acls, **kwargs)

DEFAULT_UNIT = "scripts"
REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.unit"]

def register():
    register_oid()
    register_hooks()
    register_backend()
    register_object_unit()
    register_sync_settings()
    register_commands("script", commands)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("script", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    script_name_re = '([0-9a-z_.-])*'
    script_path_re = '%s[/]%s' % (unit_path_re, script_name_re)
    script_oid_re = 'script|%s' % script_path_re
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
    config.register_auth_on_action_hook("script", "sign")
    config.register_auth_on_action_hook("script", "add_sign")
    config.register_auth_on_action_hook("script", "del_sign")

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
        super(Script, self).__init__(object_id=object_id,
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

    def verify_acl(self, action: str):
        """ Verify ACLs required to allow <action>. """
        # Parent class cannot know the ACL to allow verification of signatures
        # e.g. "view:script" for script objects and "view_public_key" for SSH
        # tokens.
        if action == "verify_signature":
            if self._verify_acl("verify:signature") \
            or self._verify_acl("view:signature") \
            or self._verify_acl("view:script"):
                return True

        if action == "get_signatures":
            if self._verify_acl("view:signature") \
            or self.verify_acl("view:script"):
                return True

        # Finally try to verify ACL via parent class method.
        if self._verify_acl(action):
            return True

        return  False

    def get_sign_data(self, callback: JobCallback=default_callback, **kwargs):
        """ Return script to be signed by parent class method. """
        # Get script, this also checks ACLs.
        script = self.dump(run_policies=False, callback=callback)
        return callback.ok(script)

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
                return callback.error("Empty script.")
            else:
                return callback.abort()
        if run_policies:
            try:
                self.run_policies("dump", callback=callback, _caller=_caller)
            except Exception as e:
                msg = "Error running policies: %s" % e
                return callback.error(msg)
        decoded_script = decode(self.script, "base64")
        if _caller == "API":
            return decoded_script
        if _caller == "CLIENT":
            return callback.dump(decoded_script)
        return callback.ok(decoded_script)

    @object_lock(full_lock=True)
    @backend.transaction
    def rename(
        self,
        new_name: str,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Rename script. """
        if self.check_base_script():
            msg = (_("Cannot rename base script."))
            return callback.error(msg)
        # Build new OID.
        new_oid = oid.get(object_type="script",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    def move(self, callback: JobCallback=default_callback, **kwargs):
        if self.check_base_script():
            msg = (_("Cannot move base script."))
            return callback.error(msg)
        return super(Script, self).move(callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(
        self,
        script: str,
        replace: bool=False,
        uuid: Union[str,None]=None,
        verify_acls: bool=True,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a script. """
        if verify_acls:
            if replace:
                if self.exists():
                    if not self.verify_acl("edit:script"):
                        msg = ("Permission denied.")
                        return callback.error(msg, exception=PermissionDenied)
            else:
                _unit = backend.get_object(object_type="unit",
                                        uuid=self.unit_uuid)
                if not _unit.verify_acl("add:script"):
                    msg = (_("Permission denied: %s") % _unit.path)
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
                return callback.error("Script already exists.")
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
                    msg = (_("UUID conflict: %s <> %s") % (self.oid, x.oid))
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
            if not config.auth_user:
                msg = "Cannot update signatures: Not logged in"
                return callback.error(msg)

            # Try to resign script.
            callback.raise_exception = True
            try:
                sign_status = self.resign(callback=callback)
            except NoSignature:
                callback.raise_exception = False
                # Without existing signatures just add a new one.
                sign_status = self.sign(callback=callback)
            except Exception as e:
                sign_status = False
                msg = "Resigning failed: %s" % e
                callback.send(msg)
            finally:
                callback.raise_exception = False

            if not sign_status:
                msg = "Auto-signing failed."
                callback.send(msg)
        else:
            if replace and self.signatures:
                msg = ("NOTE: Please update script signatures after editing!!!")
                callback.send(msg)

        # When replacing the script we just need to commit our config.
        if replace:
            return self._cache(callback=callback)

        # Add object using parent class.
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    def copy(
        self,
        destination_script: str,
        force: bool=False,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Copy this script (and its signatures) to another one. """
        # Resolv object path (e.g. unit/script).
        if "/" in destination_script:
            x = oid.resolve_path(destination_script, object_type='script')
            #object_realm = x['realm']
            #object_site = x['site']
            object_unit = x['unit']
            object_name = x['name']
        else:
            #object_realm = self.realm
            #object_site = self.site
            object_unit = self.unit
            object_name = destination_script

        # Check if object name does contain invalid chars.
        if not oid.check_name(object_type='script', object_name=object_name):
            return callback.error("Invalid destination script name.")

        # Check if destination script exists.
        result = backend.search(object_type="script",
                                attribute="name",
                                value=object_name,
                                realm=self.realm,
                                return_type="instance")
        # Use existing script if it exists.
        if result:
            # FIXME: acquire_lock() and release_lock() when replacing a script!?!
            # Get destination script from result.
            dst_script = result[0]
            # Check if we have permissions to replace destination script.
            if not dst_script.verify_acl("edit:script"):
                msg = (_("%s: Permission denied") % dst_script.rel_path)
                return callback.error(msg, exception=PermissionDenied)
            # Ask user for confirmation if needed.
            if not force:
                if self.confirmation_policy != "force":
                    answer = callback.ask(_("Replace script '%s'?: ")
                                            % dst_script.name)
                    if answer.lower() != "y":
                        return callback.abort()
            # Copy script to destination script.
            dst_script.script = self.script
        else:
            # Create new script instance.
            try:
                dst_script = Script(name=object_name,
                                    unit=object_unit,
                                    realm=self.realm,
                                    site=self.site)
                                    # FIXME: how to copy between sites!?!
                                    #realm=object_realm,
                                    #site=object_site)
            except Exception as e:
                return callback.error(_("Error loading destination script: %s")
                                        % e)
            # Try to add the new script.
            try:
                add_status = dst_script.add(script=self.script)
                add_message = ""
            except Exception as e:
                add_message = str(e)
                add_status = False
            if not add_status:
                return callback.error(add_message)

        # Copy script signatures to destination script.
        dst_script.signatures = self.signatures

        return dst_script._write(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
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
        """ Delete script. """
        if self.check_base_script():
            msg = (_("Cannot delete base script."))
            return callback.error(msg)

        if not self.exists():
            return callback.error("Script does not exist exists.")

        # Get parent object to check ACLs.
        parent_object = self.get_parent_object()
        if verify_acls:
            if not self.verify_acl("delete:object"):
                del_acl = "delete:%s" % self.type
                if not parent_object.verify_acl(del_acl):
                    msg = (_("Permission denied: %s") % self.name)
                    return callback.error(msg, exception=PermissionDenied)

        if run_policies:
            try:
                self.run_policies("delete", callback=callback, _caller=_caller)
            except Exception as e:
                return callback.error()

        if not force:
            if self.confirmation_policy != "force":
                if self.confirmation_policy == "paranoid":
                    msg = "Please type '%s' to delete object: " % self.name
                    answer = callback.ask(msg)
                    if answer != self.name:
                        return callback.abort()
                else:
                    answer = callback.ask(_("Delete script '%s'?: ") % self.rel_path)
                    if answer.lower() != "y":
                        return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show script config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:script") or self.verify_acl("edit:script"):
            lines.append('SCRIPT_MD5="%s"' % self.script_md5sum)
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
