# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.spsc import SPSC
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
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

read_acls =   [
                    "dump",
                ]

write_acls =   []

read_value_acls = {
                    "view"      : [ "dictionaries" ],
            }
write_value_acls = {
                    "add"       : [ "words", "dictionary" ],
                    "delete"    : [ "dictionary" ],
            }

default_acls = []

recursive_default_acls = []

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'args'              : ['dict_name'],
                    'oargs'             : ['dict_type'],
                    'job_type'          : 'process',
                    },
                'exists'    : {
                    'method'            : 'add',
                    'args'              : ['dict_name'],
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
                    'method'            : cli.show_getter("dictionary"),
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
                    'method'            : cli.list_getter("dictionary"),
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
                    'method'            : cli.list_getter("dictionary"),
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
    'move'      : {
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
    'dump'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump',
                    'job_type'          : 'process',
                    },
                },
            },
    'word_import'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_words',
                    'args'              : ['word_list'],
                    'job_type'          : 'process',
                    },
                },
            },
    'word_export'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'dump',
                    'job_type'          : 'process',
                    },
                },
            },
    'clear'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'clear',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_acl',
                    'args'              : ['owner_type', 'owner_name', 'acl', 'recursive_acls', 'apply_default_acls',],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_acl'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_acl',
                    'args'              : ['acl', 'recursive_acls', 'apply_default_acls',],
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
                    'job_type'          : 'process',
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

DEFAULT_UNIT = "dictionaries"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.unit",
                "otpme.lib.compression",
                ]

def register():
    register_oid()
    register_backend()
    register_base_object()
    register_object_unit()
    register_sync_settings()
    register_commands("dictionary", commands)

def register_object_unit():
    """ Register default unit for this object type. """
    config.register_default_unit("dictionary", DEFAULT_UNIT)
    config.register_base_object("unit", DEFAULT_UNIT, early=True)

def register_base_object():
    """ Base dictionaries to add. """
    base_dictionaries = {
            'de-male'           : {
                                    'pos'   : 0,
                                    'type'  : 'sorted-list',
                                },
            'de-female'         : {
                                    'pos'   : 1,
                                    'type'  : 'sorted-list',
                                },
            'de-surnames'       : {
                                    'pos'   : 2,
                                    'type'  : 'sorted-list',
                                },
            'at-surnames'       : {
                                    'pos'   : 3,
                                    'type'  : 'sorted-list',
                                },
            'de-top10000'       : {
                                    'pos'   : 4,
                                    'type'  : 'sorted-list',
                                },
            'us-female'         : {
                                    'pos'   : 5,
                                    'type'  : 'sorted-list',
                                },
            'us-male'           : {
                                    'pos'   : 6,
                                    'type'  : 'sorted-list',
                                },
            'us-surnames'       : {
                                    'pos'   : 7,
                                    'type'  : 'sorted-list',
                                },
            'en-top10000'       : {
                                    'pos'   : 8,
                                    'type'  : 'sorted-list',
                                },
            'abbreviations-it'  : {
                                    'pos'   : 9,
                                    'type'  : 'list',
                                },
            'german'            : {
                                    'pos'   : 10,
                                    'type'  : 'list',
                                },
            'english'           : {
                                    'pos'   : 11,
                                    'type'  : 'list',
                                },
            'common-passwords'  : {
                                    'pos'   : 12,
                                    'type'  : 'list',
                                },
            'german-guessing'   : {
                                    'pos'   : 13,
                                    'type'  : 'guessing',
                                },
            'english-guessing'  : {
                                    'pos'   : 14,
                                    'type'  : 'guessing',
                                },
        }
    # Register base dictionaries.
    x_sort = lambda x: base_dictionaries[x]['pos']
    for x_name in sorted(base_dictionaries, key=x_sort):
        x_type = base_dictionaries[x_name]['type']
        config.register_base_object(object_type="dictionary",
                                    name=x_name,
                                    stype=x_type)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'unit', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    # OID regex stuff.
    unit_path_re = oid.object_regex['unit']['path']
    dictionary_name_re = '([0-9a-z]([0-9a-z_.-]*[0-9a-z]){0,})'
    dictionary_path_re = '%s[/]%s' % (unit_path_re, dictionary_name_re)
    dictionary_oid_re = 'dictionary|%s' % dictionary_path_re
    oid.register_oid_schema(object_type="dictionary",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            name_regex=dictionary_name_re,
                            path_regex=dictionary_path_re,
                            oid_regex=dictionary_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="dictionary",
                                getter=rel_path_getter)

def register_backend():
    """ Register object for the file backend. """
    dict_dir_extension = "dictionary"
    def path_getter(dict_oid):
        return backend.config_path_getter(dict_oid, dict_dir_extension)
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
                'script',
                ]
        return backend.rebuild_object_index("dictionary", objects, after)
    # Register object to config.
    config.register_object_type(object_type="dictionary",
                            tree_object=True,
                            add_after=["unit", "resolver"],
                            sync_after=["user", "token"],
                            uniq_name=True,
                            object_cache=128,
                            cache_region="tree_object",
                            backup_attributes=['realm', 'site', 'name'])
    # Register object to backend.
    class_getter = lambda: Dictionary
    backend.register_object_type(object_type="dictionary",
                                dir_name_extension=dict_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_object_sync(host_type="node", object_type="dictionary")
    config.register_object_sync(host_type="host", object_type="dictionary")

class Dictionary(OTPmeObject):
    """ Dictionary object. """
    commands = commands
    def __init__(self, object_id=None, path=None, name=None,
        unit=None, site=None, realm=None, **kwargs):
        # Set our type (used in parent class)
        self.type = "dictionary"

        # Call parent class init.
        super(Dictionary, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        unit=unit,
                                        name=name,
                                        path=path,
                                        **kwargs)
        # Dictionary type.
        self.dictionary_type = "list"
        self.supported_dict_types = [ 'list', 'sorted-list', 'guessing' ]

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Dictionaries should not inherit ACLs by default.
        self.acl_inheritance_enabled = False

        self.dictionary = {}
        self.dict_size = 0

        self._sync_fields = {
                            'host'  : {
                                'own_site'  : [
                                        "DICTIONARY",
                                        "DICTIONARY_TYPE",
                                        "DICT_SIZE",
                                        ]
                            },
                        }

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'DICTIONARY'                : {
                                                        'var_name'      : 'dictionary',
                                                        'type'          : dict,
                                                        'incremental'   : False,
                                                        'required'      : False,
                                                        'compression'   : 'ZLIB',
                                                    },

                        'DICTIONARY_TYPE'           : {
                                                        'var_name'  : 'dictionary_type',
                                                        'type'      : str,
                                                        'required'  : False,
                                                    },
                        'DICT_SIZE'                      : {
                                                        'var_name'      : 'dict_size',
                                                        'type'          : int,
                                                        'required'      : False,
                                                    },

            }

        return object_config

    def set_variables(self):
        """ Set instance variables. """
        # Set OID.
        self.set_oid()

    def _set_name(self, name):
        """ Set object name. """
        # Make sure name is a string and lowercase.
        self.name = str(name).lower()

    @check_acls(['dump'])
    def dump(self, run_policies=True, _caller="API",
        callback=default_callback, **kwargs):
        """ Dump dictionary words. """
        if run_policies:
            try:
                self.run_policies("dump",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()

        dicts = {
            self.name : {
                    'dict'      : self.dictionary,
                    'dict_type' : self.dictionary_type,
                    }
                }
        spsc = SPSC(dictionaries=dicts)
        word_list = spsc.dump(self.name)
        if _caller != "API":
            word_list = "\n".join(word_list)
        return callback.ok(word_list)

    @object_lock()
    def update_dict_size(self):
        """ Update size of dictionary. """
        self.dict_size = sys.getsizeof(self.dictionary)
        # Update index.
        self.update_index("dict_size", self.dict_size)

    @object_lock()
    @backend.transaction
    def clear(self, _caller="API", callback=default_callback, **kwargs):
        """ Remove all dictionary data. """
        self.dictionary = {}
        self.update_dict_size()
        return self._cache(callback=callback)

    @check_acls(['add:words'])
    @object_lock()
    @backend.transaction
    def add_words(self, word_list, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Add words to dictionary. """
        if run_policies:
            try:
                self.run_policies("modify",
                                    callback=callback,
                                    _caller=_caller)
                self.run_policies("add_words",
                                    callback=callback,
                                    _caller=_caller)
            except Exception as e:
                return callback.error()

        position = len(self.dictionary)
        dict_changed = False
        for word in word_list:
            if not word in self.dictionary:
                position += 1
                self.dictionary[word] = position
                dict_changed = True

        if not dict_changed:
            return callback.ok()

        self.update_dict_size()

        return self._cache(callback=callback)

    @check_acls(['rename'])
    @object_lock(full_lock=True)
    @backend.transaction
    def rename(self, new_name, callback=default_callback, _caller="API", **kwargs):
        """ Rename dictionary. """
        # Build new OID.
        new_oid = oid.get(object_type="dictionary",
                        realm=self.realm,
                        site=self.site,
                        unit=self.unit,
                        name=new_name)
        return self._rename(new_oid, callback=callback, _caller=_caller, **kwargs)

    @object_lock(full_lock=True)
    @backend.transaction
    @run_pre_post_add_policies()
    def add(self, dict_type="list", verbose_level=0,
        callback=default_callback, **kwargs):
        """ Add a dictionary. """
        # Run parent class stuff e.g. verify ACLs.
        result = self._prepare_add(callback=callback, **kwargs)
        if result is False:
            return callback.error()

        if not dict_type in self.supported_dict_types:
            return callback.error(_("Unknown dictionary type: %s") % dict_type)

        # Set dict type.
        self.dictionary_type = dict_type
        # Update index.
        self.add_index("dictionary_type", dict_type)
        # Update dict size.
        self.update_dict_size()

        # Add object using parent class.
        return OTPmeObject.add(self, verbose_level=verbose_level,
                                callback=callback, **kwargs)

    @check_acls(['delete'])
    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, force=False, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete dictionary. """
        if not self.exists():
            return callback.error("Dictionary does not exist exists.")

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
            if self.confirmation_policy == "paranoid":
                msg = "Please type '%s' to delete object: " % self.name
                answer = callback.ask(msg)
                if answer != self.name:
                    return callback.abort()
            else:
                answer = callback.ask(_("Delete dictionary '%s'?: ")
                                        % self.name)
                if answer.lower() != "y":
                    return callback.abort()

        # Delete object using parent class.
        return OTPmeObject.delete(self, verbose_level=verbose_level,
                                    force=force, callback=callback)


    def show_config(self, callback=default_callback, **kwargs):
        """ Show dictionary config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []
        lines.append('DICTIONARY_TYPE="%s"' % self.dictionary_type)
        lines.append('SIZE="%s"' % self.dict_size)
        return OTPmeObject.show_config(self,
                                    config_lines=lines,
                                    callback=callback,
                                    **kwargs)

    def show(self, **kwargs):
        """ Show dictionary details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
