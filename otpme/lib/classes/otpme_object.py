# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import copy
import time
import ujson
import types
import pprint
import datetime
import importlib
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import cli
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import encryption
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.pki.cert import SSLCert
from otpme.lib.extensions import utils
from otpme.lib.cache import ldif_cache
from otpme.lib.cache import config_cache
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import encode
from otpme.lib.cache import ldap_search_cache
from otpme.lib.cache import assigned_role_cache
from otpme.lib.cache import assigned_token_cache
from otpme.lib.policy import one_time_policy_run
from otpme.lib.cache import supported_acls_cache
from otpme.lib.otpme_acl import check_special_user
from otpme.lib.classes.object_config import ObjectConfig

from otpme.lib.exceptions import *

OBJECT_LOCK_TYPE = "object"
LAST_USED_LOCK_TYPE = "last_used"

logger = config.logger
default_callback = config.get_callback()

# Global ACLs that are valid for every OTPme object.
global_read_acls = [
                    "view_public",
                    "view_all",
                    "view",
                    "export",
                ]
global_write_acls = [
                    "all",
                    "rename",
                    "edit",
                    "add",
                    "remove",
                    "delete",
                    "enable",
                    "disable",
                    "import",
                ]

global_read_value_acls = {
                    "view"      : [
                                "uuid",
                                "path",
                                "rel_path",
                                "read_oid",
                                "full_oid",
                                "checksum",
                                "sync_checksum",
                                "object",
                                "policy",
                                "extension",
                                "attribute",
                                "acl_inheritance",
                                "status",
                                "config",
                                "description",
                                "last_modified",
                                "last_used",
                                "create_time",
                                "creator",
                                "resolver",
                                "resolver_key",
                                "resolver_checksum",
                                ],
            }

global_write_value_acls = {
                    "enable"    : [
                                "object",
                                "acl_inheritance",
                                ],
                    "disable"   : [
                                "object",
                                "acl_inheritance",
                                ],
                    "rename"    : [
                                "object",
                                ],
                    "delete"    : [
                                "object",
                                "attribute",
                                "config",
                                "acl",
                                ],
                    "add"       : [
                                "extension",
                                "attribute",
                                "policy",
                                "config",
                                "acl",
                                ],
                    "remove"    : [
                                "extension",
                                "orphans",
                                "policy",
                                ],
                    "edit"      : [
                                "attribute",
                                "description",
                                ],
}

global_default_acls = []

global_recursive_default_acls = []

def get_acls(read_acls, write_acls, split=False):
    """ Get all supported object ACLs """
    if split:
        otpme_object_read_acls, \
        otpme_object_write_acls = get_global_acls(split=True)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_object_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_object_write_acls)
        return _read_acls, _write_acls
    global_acls = get_global_acls()
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, global_acls)
    return _acls

def get_value_acls(read_value_acls, write_value_acls, split=False):
    """ Get all supported object value ACLs """
    if split:
        otpme_object_read_value_acls, \
        otpme_object_write_value_acls = get_global_value_acls(split=True)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                    otpme_object_read_value_acls)
        _write_value_acls = otpme_acl.merge_value_acls(write_value_acls,
                                    otpme_object_write_value_acls)
        return _read_value_acls, _write_value_acls
    global_value_acls = get_global_value_acls()
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, global_value_acls)
    return _acls

def get_default_acls(default_acls):
    """ Get all supported object default ACLs """
    global_default_acls = get_global_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, global_default_acls)
    return _acls

def get_recursive_default_acls(recursive_default_acls):
    """ Get all supported object recursive default ACLs """
    global_recursive_default_acls = get_global_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                global_recursive_default_acls)
    return _acls

def get_global_acls(split=False):
    """ Get all supported object ACLs """
    if split:
        return global_read_acls, global_write_acls
    _acls = otpme_acl.merge_acls(global_read_acls, global_write_acls)
    return _acls

def get_global_value_acls(split=False):
    """ Get all supported object value ACLs """
    if split:
        return global_read_value_acls, global_write_value_acls
    _acls = otpme_acl.merge_value_acls(global_read_value_acls, global_write_value_acls)
    return _acls

def get_global_default_acls():
    """ Get all supported object default ACLs """
    return global_default_acls

def get_global_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    return global_recursive_default_acls

def run_pre_post_add_policies():
    """ Decorator to run pre/post-add policies. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            # Call given class method.
            try:
                callback = f_kwargs['callback']
            except:
                callback = default_callback
            try:
                run_policies = f_kwargs['run_policies']
            except:
                run_policies = True
            if run_policies:
                try:
                    self._run_pre_add_policies(callback=callback)
                except PolicyException as e:
                    msg = str(e)
                    return callback.error(msg)
            result = f(self, *f_args, **f_kwargs)
            if result is not False:
                if run_policies:
                    try:
                        self._run_post_add_policies(callback=callback)
                    except PolicyException as e:
                        msg = str(e)
                        return callback.error(msg)
            return result
        return wrapped
    return wrapper

def load_object(force=True):
    """ Decorator to make sure the object gets (re) loaded. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            # Call given class method.
            result = f(self, *f_args, **f_kwargs)
            # Load object if method was succesful.
            if result is not False:
                if force or not self._modified:
                    self._load_object()
            return result
        return wrapped
    return wrapper

def oid_getter(path):
    """ Get OID from path. """
    objects_dir = backend.get_data_dir("objects")
    if not path.startswith(objects_dir):
        return
    object_part_regex = '^%s/' % objects_dir
    object_part = re.sub(object_part_regex, r'', path)
    object_type_regex = '.*[.]([^./]*)$'
    object_type = re.sub(object_type_regex, r'\1', object_part)

    oid_path = []
    for x in object_part.split("/"):
        o_type = re.sub(object_type_regex, r'\1', x)
        object_regex = '[.]%s$' % o_type
        o = re.sub(object_regex, r'', x)
        oid_path.append(o)
    oid_path = "/" + "/".join(oid_path)

    result = oid.resolve_path(oid_path, object_type=object_type)
    object_realm = result['realm']
    object_site = result['site']
    object_unit = result['unit']
    object_rel_path = result['rel_path']
    object_owner = result['owner']
    object_name = result['name']

    object_id = oid.OTPmeOid(object_type=object_type,
                            realm=object_realm,
                            site=object_site,
                            unit=object_unit,
                            rel_path=object_rel_path,
                            name=object_name,
                            user=object_owner)
    return object_id

LAST_USED_NAME = "last_used"
LAST_USED_DIR = os.path.join(config.data_dir, "data", LAST_USED_NAME)

REGISTER_BEFORE = []
REGISTER_AFTER = [
                'otpme.lib.daemon.controld',
                'otpme.lib.extensions.ldif_handler',
                'otpme.lib.classes.data_objects.cert',
                'otpme.lib.classes.data_objects.rsa_key',
                'otpme.lib.compression',
                'otpme.lib.encryption',
                'otpme.lib.encoding',
                #'otpme.lib.extensions',
                #'otpme.lib.classes.policy',
                #'otpme.lib.classes.unit',
                ]

def register():
    """ Register object stuff. """
    register_backend()
    register_last_used_dir()
    register_config_parameters()
    locking.register_lock_type(OBJECT_LOCK_TYPE, module=__file__)
    locking.register_lock_type(LAST_USED_LOCK_TYPE, module=__file__)

def register_backend():
    # Register index attributes.
    config.register_index_attribute('acl')
    config.register_index_attribute('unit')
    config.register_index_attribute('role')
    config.register_index_attribute('token')
    config.register_index_attribute('group')
    config.register_index_attribute('policy')
    config.register_index_attribute('enabled')
    config.register_index_attribute('signature')
    config.register_index_attribute('object_uuid')
    config.register_index_attribute('create_time')
    config.register_index_attribute('last_modified')
    config.register_index_attribute('resolver')
    config.register_index_attribute('resolver_key')
    config.register_index_attribute('resolver_checksum')
    config.register_index_attribute('origin')

def register_last_used_dir():
    """ Directory to store last used timestamp of objects as file mtime. """
    config.register_config_var("last_used_dir", str, LAST_USED_DIR)
    backend.register_data_dir(name=LAST_USED_NAME,
                            path=LAST_USED_DIR,
                            drop=True,
                            perms=0o770)

def register_config_parameters():
    """ Register config parameters. """
    # Object types our config parameters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'token',
                    'script',
                    ]
    # With this setting you can configure when OTPme should ask user for confirmation
    # (e.g. when deleting a user)
    # Valid settings:
    #   - force (Never ask for confirmation)
    #   - normal (Ask user in important cases e.g. when deleting an object will also
    #     delete child objects)
    #   - paranoid (Ask user for almost anything)
    config.register_config_parameter(name="confirmation_policy",
                                    ctype=str,
                                    default_value="paranoid",
                                    valid_values=['force', 'normal', 'paranoid'],
                                    object_types=config.tree_object_types)
    # With the auto sign parameter enabled the user gets offered to sign the object she changes.
    config.register_config_parameter(name="auto_sign",
                                    ctype=bool,
                                    default_value=False,
                                    object_types=object_types)
    # Auto-revoke object signatures.
    config.register_config_parameter(name="auto_revoke",
                                    ctype=bool,
                                    default_value=True,
                                    object_types=object_types)

def get_ldif(ldif, attributes=None, verify_acl_func=None,
    fake_dc=None, auth_token=None, text=False, **kwargs):
    """ Return objects LDIF. """
    # Sort LDIF: dn -> sorted(objectClasses) -> sorted(attributes)
    _dn = None
    _ocs = []
    _ldif = []
    _attrs = []
    for x in sorted(ldif):
        if x == "dn":
            _dn = ldif[x][0]
        elif x == "objectClass":
            _ocs = ldif[x]
        else:
            for v in ldif[x]:
                _attrs.append((x, v))

    if attributes is None or "dn" in attributes:
        if _dn:
            # Add fake DC to LDIF. This is used to allow LDAP authentication
            # to different clients/accessgroups by specifying the client as DC.
            if fake_dc:
                realm_len = len(config.realm.split("."))
                dn_parts = _dn.split(",")
                dc = "dc=%s" % fake_dc
                dn_parts.insert(-realm_len, dc)
                _dn = ",".join(dn_parts)

    for x in _attrs:
        a = x[0]
        v = x[1]
        if attributes is not None:
            if a not in attributes:
                continue
        add_attribute = True
        if verify_acl_func:
            if a not in config.ldif_whitelist_attributes:
                add_attribute = False
                attribute_acl = "view:attribute:%s" % a
                if verify_acl_func(attribute_acl, auth_token=auth_token):
                    add_attribute = True
        if add_attribute:
            attr = "%s: %s" % (a, v)
            if isinstance(v, str):
                if stuff.contains_non_ascii(v):
                    v = encode(v, "base64")
                    attr = "%s:: %s" % (a, v)
            _ldif.append(attr)

    if attributes is None or "objectClass" in attributes:
        if _ocs:
            _ocs.sort(reverse=True)
        for x in _ocs:
            _ldif.insert(0, 'objectClass: %s' % x)
        _ldif.insert(0, 'dn: %s' % _dn)

    result = _ldif.copy()
    if text:
        result = "\n".join(result)

    return result

class IncrementaObject(object):
    def set_normal_attrs(self, value):
        if isinstance(value, IncrementalList):
            normal_value = value.copy()
        elif isinstance(value, IncrementalDict):
            normal_value = value.copy()
        else:
            normal_value = value
        return normal_value

    def set_incremental_attrs(self, value, dict_path, _set=False):
        if isinstance(value, list):
            _list = value
            if _set:
                _list = []
            inc_value = IncrementalList(data=_list,
                                    key=self.key,
                                    dict_path=dict_path,
                                    incremental_data=self.incremental_data)
            if _set:
                inc_value.set(value)
        elif isinstance(value, dict):
            _dict = value
            if _set:
                _dict = {}
            inc_value = IncrementalDict(data=_dict,
                                    key=self.key,
                                    dict_path=dict_path,
                                    incremental_data=self.incremental_data)
            if _set:
                inc_value.set(value)
        else:
            inc_value = value
        return inc_value

class IncrementalDict(IncrementaObject):
    """ Handle incremental updates of dict attribute. """
    def __init__(self, data={}, key=None, dict_path=[], incremental_data=[]):
        self.key = key
        self.data = {}
        self.type = "dict"
        self.dict_path = dict_path
        self.incremental_data = incremental_data
        for x in data:
            self.__setitem__(x, data[x])

    @property
    def modified(self):
        for x in self.incremental_data:
            if self.key not in x:
                continue
            return True
        return False

    def incremental_add(self, key, value):
        if isinstance(value, IncrementalDict):
            value = value.copy()
        if isinstance(value, IncrementalList):
            value = value.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'add',
                                    self.type,
                                    self.dict_path,
                                    key, value))

    def incremental_del(self, key, value):
        if isinstance(value, IncrementalDict):
            value = value.copy()
        if isinstance(value, IncrementalList):
            value = value.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'del',
                                    self.type,
                                    self.dict_path,
                                    key, value))

    def __getitem__(self, key):
        key = str(key)
        return self.data[key]

    def copy(self):
        dict_copy = {}
        for x in self.data:
            x_val = self.data[x]
            if isinstance(x_val, IncrementalDict):
                x_val = x_val.copy()
            if isinstance(x_val, IncrementalList):
                x_val = x_val.copy()
            x_normal_value = self.set_normal_attrs(x_val)
            dict_copy[x] = x_normal_value
        return dict_copy

    def __setitem__(self, key, value):
        key = str(key)
        dict_path = self.dict_path.copy()
        dict_path.append(key)
        inc_value = self.set_incremental_attrs(value, dict_path)
        self.data[key] = inc_value
        add_value  = True
        if isinstance(value, list):
            add_value = False
        if isinstance(value, dict):
            add_value = False
        if not add_value:
            return
        self.incremental_add(key, value)

    def __delitem__(self, key):
        key = str(key)
        del_val = self.data.pop(key)
        self.incremental_del(key, del_val)

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        _str = self.data.__str__()
        return _str

    def values(self):
        return self.data.values()

    def items(self):
        return self.data.items()

    def keys(self):
        return self.data.keys()

    def pop(self, key):
        key = str(key)
        del_val = self.data.pop(key)
        self.incremental_del(key, del_val)
        return del_val

    def set(self, _dict):
        self.data = {}
        for key in _dict:
            key = str(key)
            val = _dict[key]
            dict_path = self.dict_path.copy()
            dict_path.append(key)
            inc_value = self.set_incremental_attrs(val, dict_path, _set=True)
            self.data[key] = inc_value

class IncrementalList(list, IncrementaObject):
    """ Handle incremental updates of list attribute. """
    def __init__(self, data=[], key=None, dict_path=[], incremental_data=[]):
        self.key = key
        self.type = "list"
        self.dict_path = dict_path
        self.incremental_data = incremental_data
        _list = []
        if data is not None:
            _list = data
        for x in _list:
            self.append(x)
        #return super(IncrementalList, self).__init__(_list)

    @property
    def modified(self):
        for x in self.incremental_data:
            if self.key not in x:
                continue
            return True
        return False

    def incremental_add(self, item):
        if isinstance(item, IncrementalDict):
            item = item.copy()
        if isinstance(item, IncrementalList):
            item = item.copy()
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'add',
                                    self.type,
                                    self.dict_path,
                                    item))

    def incremental_del(self, item):
        self.incremental_data.append((time.time(),
                                    self.key,
                                    'del',
                                    self.type,
                                    self.dict_path,
                                    item))

    def __setitem__(self, index, item):
        self.incremental_add(item)
        return super(IncrementalList, self).__setitem__(index, item)

    def __delitem__(self, index):
        del_item = self[index]
        self.incremental_del(del_item)
        return super(IncrementalList, self).__delitem__(index)

    #def copy(self):
    #    list_copy = super(IncrementalList, self).copy()
    #    for x in list_copy:
    #        if isinstance(x, IncrementalDict):
    #            x = x.copy()
    #        if isinstance(x, IncrementalList):
    #            x = x.copy()
    #        #x_normal_value = self.set_normal_attrs(x)
    #        #dict_copy[x] = x_normal_value
    #    return list_copy

    def append(self, value):
        self.incremental_add(value)
        return super(IncrementalList, self).append(value)

    def insert(self, index, value):
        self.incremental_add(value)
        return super(IncrementalList, self).insert(index, value)

    def pop(self, index=-1):
        del_item = super(IncrementalList, self).pop(index)
        self.incremental_del(del_item)
        return del_item

    def remove(self, value):
        self.incremental_del(value)
        return super(IncrementalList, self).remove(value)

    def set(self, _list):
        super(IncrementalList, self).__init__(_list)

class OTPmeLockObject(object):
    """ OTPme lock object. """
    def __init__(self):
        self.full_write_lock = False

    @property
    def _object_lock(self):
        try:
            _lock = locking.get_lock(OBJECT_LOCK_TYPE, self.oid.read_oid)
        except:
            return
        return _lock

    def acquire_lock(self, lock_caller, write=False, recursive=False,
        skip_same_caller=False, timeout=None, reload_on_change=True,
        full=False, cluster=True, _caller="API", callback=default_callback):
        """ Acquire object lock. """
        if self.offline:
            return
        if full:
            self.full_write_lock = True
        # Acquire object lock. We use the object ID as lock ID to prevent
        # issues when adding a new object (e.g. new object has no UUID).
        if self._object_lock:
            self._object_lock.acquire_lock(lock_caller=lock_caller,
                                    skip_same_caller=skip_same_caller)
        else:
            old_uuid = backend.get_uuid(self.oid)
            old_checksum = backend.get_checksum(self.oid)
            object_existed = backend.object_exists(self.oid)
            try:
                locking.acquire_lock(lock_type=OBJECT_LOCK_TYPE,
                                    lock_id=self.oid.read_oid,
                                    lock_caller=lock_caller,
                                    write=write,
                                    timeout=timeout,
                                    cluster=cluster,
                                    callback=callback)
            except LockWaitTimeout:
                raise
            except Exception as e:
                config.raise_exception()
                msg = (_("Failed to acquire lock: %s") % e)
                raise OTPmeException(msg)
            if object_existed:
                if not backend.object_exists(self.oid):
                    msg = "Object deleted while waiting for lock: %s" % self
                    self._object_lock.release_lock(lock_caller=lock_caller)
                    raise LockWaitAbort(msg)
                if self.uuid:
                    object_id = backend.get_oid(self.uuid,
                                                instance=True,
                                                object_type=self.type)
                    if object_id != self.oid:
                        msg = "Object renamed while waiting for lock: %s" % self
                        self._object_lock.release_lock(lock_caller=lock_caller)
                        raise LockWaitAbort(msg)
                object_uuid = backend.get_uuid(self.oid)
                if object_uuid != old_uuid:
                    msg = "Object re-created while waiting for lock: %s" % self
                    self._object_lock.release_lock(lock_caller=lock_caller)
                    raise LockWaitAbort(msg)
                new_checksum = backend.get_checksum(self.oid)
                if old_checksum != new_checksum:
                    if not reload_on_change:
                        msg = "Object changed while waiting for lock: %s" % self
                        raise LockWaitAbort(msg)
                    #if self._modified:
                    #    msg = "Will not auto-reload modified object: %s" % self
                    #    raise LockWaitAbort(msg)
                    #self._load()
            else:
                if backend.object_exists(self.oid):
                    msg = "Object created while waiting for lock: %s" % self
                    self._object_lock.release_lock(lock_caller=lock_caller)
                    raise LockWaitAbort(msg)

        # Add transaction lock if needed. This will prevent the
        # object from being released before the transaction
        # finished.
        if not self.no_transaction:
            if self.full_write_lock:
                transaction = backend.get_transaction()
                if transaction:
                    # Add locked object to transaction.
                    transaction.cache_locked_object(self)
                    # Add transaction lock.
                    self._object_lock.acquire_lock(lock_caller=transaction.lock_caller,
                                                        skip_same_caller=True)

    def release_lock(self, lock_caller=None,
        recursive=False, force=False, callback=None):
        """ Release object lock. """
        if self.offline:
            return
        if not self._object_lock:
            return
        # Release lock.
        self._object_lock.release_lock(lock_caller=lock_caller,
                                        force=force)

    def is_locked(self):
        """ Check if the instance is locked. """
        if not self._object_lock:
            return False
        if not self._object_lock.is_locked():
            return False
        if self._object_lock.write:
            return "write"
        else:
            return "read"

class OTPmeBaseObject(OTPmeLockObject):
    """ Generic OTPme object. """
    def __init__(self, object_config=None,
    uuid=None, no_transaction=False, **kwargs):
        self.oid = None
        self.uuid = uuid
        self.site = None
        self.site_uuid = None
        self.realm = None
        self.realm_uuid = None
        self.cert = None
        self._cert_oid = None
        self._cert_public_key_oid = None
        self.key = None
        self._key_oid = None
        self._private_key_oid = None
        self.public_key = None
        self._public_key_oid = None
        self.pickable = True
        self.cache_expire = 30
        self.sub_type = None
        self.index_journal = []
        self.incremental_updates = []
        self.list_attributes = []
        self.dict_attributes = []
        self.template_name = None
        self.template_object = False
        self.handle_key_loading = False
        self.handle_cert_loading = False
        self.handle_public_key_loading = False
        self.handle_private_key_loading = False
        self.origin = None
        self.origin_cache = None

        self.offline = False
        self.check_attribute_types = True
        self.create_time = int(time.time())
        self.last_modified = 0
        self.track_last_used = False
        self._modified = False
        self._cached = False
        self._last_modified_written = False
        self._sync_fields = {}
        self._sub_sync_fields = {}
        self._base_sync_fields = {}
        self.object_config = {}
        self.no_transaction = no_transaction
        self.kwargs_object_config = object_config
        # Object version.
        self.version = 1
        self.add_properties()
        super(OTPmeBaseObject, self).__init__()

    def __setstate__(self, _dict):
        self.__dict__ = _dict
        self.add_properties()

    def add_properties(self):
        # Get object config.
        base_config = self._get_base_config()
        for x in base_config:
            x_type = base_config[x]['type']
            try:
                x_incremental = base_config[x]['incremental']
            except KeyError:
                x_incremental = True
            if not x_incremental:
                continue
            x_var_name = base_config[x]['var_name']
            if x_type == dict:
                prop_getter = self.get_dict_prop_getter(x)
                prop_setter = self.get_dict_prop_setter(x)
                prop = property(prop_getter, prop_setter, None, "Dict property")
                setattr(self.__class__, x_var_name, prop)
                if x not in self.dict_attributes:
                    self.dict_attributes.append(x)
            if x_type == list:
                prop_getter = self.get_list_prop_getter(x)
                prop_setter = self.get_list_prop_setter(x)
                prop = property(prop_getter, prop_setter, None, "List property")
                setattr(self.__class__, x_var_name, prop)
                if x not in self.list_attributes:
                    self.list_attributes.append(x)

        # Get object config from child class.
        object_config = self._get_object_config()
        for x in object_config:
            x_type = object_config[x]['type']
            try:
                x_incremental = object_config[x]['incremental']
            except KeyError:
                x_incremental = True
            if not x_incremental:
                continue
            x_var_name = object_config[x]['var_name']
            if x_type == dict:
                prop_getter = self.get_dict_prop_getter(x)
                prop_setter = self.get_dict_prop_setter(x)
                prop = property(prop_getter, prop_setter, None, "Dict property")
                setattr(self.__class__, x_var_name, prop)
                if x not in self.dict_attributes:
                    self.dict_attributes.append(x)
            if x_type == list:
                prop_getter = self.get_list_prop_getter(x)
                prop_setter = self.get_list_prop_setter(x)
                prop = property(prop_getter, prop_setter, None, "List property")
                setattr(self.__class__, x_var_name, prop)
                if x not in self.list_attributes:
                    self.list_attributes.append(x)

    def get_list_prop_getter(self, attr):
        def prop_getter(self):
            try:
                x_attr = getattr(self, attr)
            except AttributeError:
                x_attr = None
            if x_attr:
                return x_attr
            x_attr = IncrementalList(data=[],
                                    key=attr,
                                    incremental_data=self.incremental_updates)
            setattr(self, attr, x_attr)
            return x_attr
        return prop_getter

    def get_list_prop_setter(self, attr):
        def prop_setter(self, _list):
            try:
                cur_attr = getattr(self, attr)
            except AttributeError:
                cur_attr = None
            if cur_attr:
                for x in cur_attr:
                    cur_attr.incremental_del(x)
            x_attr = IncrementalList(data=_list,
                                    key=attr,
                                    incremental_data=self.incremental_updates)
            setattr(self, attr, x_attr)
        return prop_setter

    def get_dict_prop_getter(self, attr):
        def prop_getter(self):
            try:
                x_attr = getattr(self, attr)
            except AttributeError:
                x_attr = None
            if x_attr:
                return x_attr
            x_attr = IncrementalDict(data={},
                                    key=attr,
                                    incremental_data=self.incremental_updates)
            setattr(self, attr, x_attr)
            return x_attr
        return prop_getter

    def get_dict_prop_setter(self, attr):
        def prop_setter(self, _dict):
            try:
                cur_attr = getattr(self, attr)
            except AttributeError:
                cur_attr = None
            x_attr = IncrementalDict(data=_dict,
                                    key=attr,
                                    incremental_data=self.incremental_updates)
            if cur_attr:
                for k in cur_attr:
                    if k in _dict:
                        continue
                    v = cur_attr[k]
                    x_attr.incremental_del(k, v)
            setattr(self, attr, x_attr)
        return prop_setter

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __str__(self):
        if not self.oid:
            raise OTPmeException("Object without OID. :(")
        if self.oid.full_oid:
            return self.oid.full_oid
        if self.oid.read_oid:
            return self.oid.read_oid

    def __eq__(self, other):
        if not hasattr(other, "oid"):
            return False
        return self.oid == other.oid

    def __ne__(self, other):
        if not hasattr(other, "oid"):
            return False
        return self.oid != other.oid

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()

    def set_variables(self):
        """ To be overridden by child class. """
        return

    def is_template(self):
        return self.template_object

    def reset_modified(self):
        self._modified = False
        self.full_write_lock = False
        self._last_modified_written = False
        self.object_config.reset_modified()

    @property
    def sync_fields(self):
        """ Merge sync fields. """
        # Get base sync fields.
        sync_fields = stuff.copy_object(self._base_sync_fields)
        # Merge object sync fields.
        for peer_type in self._sync_fields:
            if not peer_type in sync_fields:
                sync_fields[peer_type] = {}
            for trust_type in self._sync_fields[peer_type]:
                if not trust_type in sync_fields[peer_type]:
                    sync_fields[peer_type][trust_type] = []
                for x in self._sync_fields[peer_type][trust_type]:
                    if not x in sync_fields[peer_type][trust_type]:
                        sync_fields[peer_type][trust_type].append(x)
        # Merge sub type sync fields.
        for peer_type in self._sub_sync_fields:
            if not peer_type in sync_fields:
                sync_fields[peer_type] = {}
            for trust_type in self._sub_sync_fields[peer_type]:
                if not trust_type in sync_fields[peer_type]:
                    sync_fields[peer_type][trust_type] = []
                for x in self._sub_sync_fields[peer_type][trust_type]:
                    if not x in sync_fields[peer_type][trust_type]:
                        sync_fields[peer_type][trust_type].append(x)
        return sync_fields

    @property
    def size(self):
        if self.object_config is None:
            return 0
        object_size = sys.getsizeof(self.object_config)
        return object_size

    @property
    def checksum(self):
        """ Get object checksum from backend. """
        checksum = self.object_config.checksum
        return checksum

    @property
    def sync_checksum(self):
        """ Get object sync checksum from backend. """
        sync_checksum = self.object_config.sync_checksum
        return sync_checksum

    @property
    def last_used(self):
        """ Get last used timestamp. """
        if not self.track_last_used:
            return
        last_used_timestamp = backend.get_last_used(self.realm,
                                                    self.site,
                                                    self.type,
                                                    self.uuid)
        return last_used_timestamp

    @last_used.setter
    def last_used(self, timestamp):
        """ Set last used timestamp. """
        if not self.track_last_used:
            return
        backend.set_last_used(self.realm,
                            self.site,
                            self.type,
                            self.uuid,
                            timestamp)

    @property
    def cache_expire_time(self):
        if self.is_special_object():
            return
        return self.cache_expire

    def _get_object_config(self):
        """ Should be overridden by child class. """
        return {}

    def set_unit(self):
        """ Set objects unit. """
        if not self.type in config.tree_object_types:
            return
        if self.unit_uuid:
            unit_oid = backend.get_oid(self.unit_uuid,
                                        object_type="unit",
                                        instance=True)
            if not unit_oid:
                msg = "Unknown unit: %s: %s" % (self, self.unit_uuid)
            self.unit = unit_oid.rel_path
            return

        if not self.unit:
            return

        result = backend.search(object_type="unit",
                                realm=self.realm,
                                site=self.site,
                                attribute="rel_path",
                                value=self.unit,
                                return_type="oid")
        if not result:
            msg = ("Unknown unit: %s" % self.unit)
            raise OTPmeException(msg)

        unit_oid = result[0]
        unit_uuid = backend.get_uuid(unit_oid)
        self.unit = unit_oid.rel_path
        self.unit_uuid = unit_uuid

    def get_sync_config(self, peer):
        """
        Get object config with fields selected by sync peer type (e.g.
        host or node)
        """
        # Make sure our object config is up-to-date.
        #self.update_object_config()
        # Get a copy of our object config.
        #sync_config = self.object_config.copy()
        sync_config = backend.read_config(self.oid)
        sync_config = sync_config.copy()

        if peer.type != "node":
            if not peer.type in self.sync_fields:
                raise PermissionDenied("Permission denied.")

        # If the syncing host is this host do not restrict sync fields.
        if self.type == "host" and peer.type == "host":
            if peer.uuid == self.uuid:
                return sync_config

        own_site = False
        relationship = "untrusted"
        # Check if this object is from peers site.
        if peer.site_uuid == self.site_uuid:
            relationship = "trusted"
            own_site = True
        # Check if this object is peers site.
        elif peer.site_uuid == self.uuid:
            relationship = "trusted"
        # Check if peer is from our site.
        elif peer.site_uuid == config.site_uuid:
            relationship = "trusted"
        else:
            # Check if peer is from one of our trusted sites.
            our_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            if peer.site_uuid in our_site.trusted_sites:
                relationship = "trusted"

        # Trusted nodes are allowed to sync all fields.
        if peer.type == "node" and relationship == "trusted":
            return sync_config

        allowed_fields = ['VERSION']
        # Get base sync fields (e.g. UUID, REALM, SITE...)
        try:
            allowed_fields += list(self._base_sync_fields[peer.type][relationship])
        except:
            pass

        if own_site:
            try:
                allowed_fields += list(self._base_sync_fields[peer.type]['own_site'])
            except:
                pass

        # Get object specific sync fields (e.g. GROUP, TOKENS...)
        try:
            allowed_fields += list(self.sync_fields[peer.type][relationship])
        except:
            pass

        if own_site:
            try:
                allowed_fields += list(self.sync_fields[peer.type]['own_site'])
            except:
                pass

        if allowed_fields:
            for f in dict(sync_config):
                if not f in allowed_fields:
                    sync_config.pop(f)

        return sync_config

    @property
    def _cert(self):
        cert = None
        if self._cert_oid:
            cert = cache.get_instance(self._cert_oid)
        if not cert:
            cert = self._load_cert()
        return cert

    def get_realm(self):
        """ Get realm of this object. """
        if self.type == "realm":
            realm = self.name
        else:
            realm = self.realm
        return realm

    def get_site(self):
        """ Get site of this object. """
        if self.type == "realm":
            site = None
        elif self.type == "site":
            site = self.name
        else:
            site = self.site
        return site

    def _load_cert(self):
        """ Load objects cert. """
        from otpme.lib.classes.data_objects.cert import OTPmeCert
        if not self.handle_cert_loading:
            return
        if not self.cert:
            return
        realm = self.get_realm()
        site = self.get_site()
        cert = OTPmeCert(realm=realm, site=site, cert=self.cert, key=self.key)
        cache.add_instance(cert)
        self._cert_oid = cert.oid
        return cert

    @property
    def _cert_public_key(self):
        cert_public_key = None
        if self._cert_public_key_oid:
            cert_public_key = cache.get_instance(self._cert_public_key_oid)
        if not cert_public_key:
            cert_public_key = self._load_cert_public_key()
        return cert_public_key

    def _load_cert_public_key(self):
        """ Load objects cert. """
        from otpme.lib.classes.data_objects.rsa_key import OTPmeRSAKey
        if not self.handle_cert_loading:
            return
        if not self.cert:
            return
        realm = self.get_realm()
        site = self.get_site()
        cert_public_key = OTPmeRSAKey(realm=realm,
                                    site=site,
                                    key=self._cert.public_key())
        cache.add_instance(cert_public_key)
        self._cert_public_key_oid = cert_public_key.oid
        return cert_public_key

    @property
    def _key(self):
        key = None
        if self._key_oid:
            key = cache.get_instance(self._key_oid)
        if not key:
            key = self._load_key()
        return key

    def _load_key(self):
        """ Load objects key. """
        from otpme.lib.classes.data_objects.rsa_key import OTPmeRSAKey
        if not self.handle_key_loading:
            return
        if not self.key:
            return
        realm = self.get_realm()
        site = self.get_site()
        cert_private_key = OTPmeRSAKey(realm=realm,
                                        site=site,
                                        key=self.key)
        cache.add_instance(cert_private_key)
        self._key_oid = cert_private_key.oid
        return cert_private_key

    @property
    def _private_key(self):
        key = None
        if self._private_key_oid:
            key = cache.get_instance(self._private_key_oid)
        if not key:
            key = self._load_private_key()
        return key

    def _load_private_key(self):
        """ Load objects private key. """
        from otpme.lib.classes.data_objects.rsa_key import OTPmeRSAKey
        if not self.handle_private_key_loading:
            return
        if not self.private_key:
            return
        realm = self.get_realm()
        site = self.get_site()
        private_key = OTPmeRSAKey(realm=realm,
                                site=site,
                                key=self.private_key)
        cache.add_instance(private_key)
        self._private_key_oid = private_key.oid
        return private_key

    @property
    def _public_key(self):
        key = None
        if self._public_key_oid:
            key = cache.get_instance(self._public_key_oid)
        if not key:
            key = self._load_public_key()
        return key

    def _load_public_key(self):
        """ Load objects public key. """
        from otpme.lib.classes.data_objects.rsa_key import OTPmeRSAKey
        if not self.handle_public_key_loading:
            return
        if not self.public_key:
            return
        public_key = OTPmeRSAKey(realm=self.realm,
                                site=self.site,
                                key=self.public_key)
        cache.add_instance(public_key)
        self._public_key_oid = public_key.oid
        return public_key

    def _load_object(self):
        """ Do anything to load the object from the object config. """
        # Set variables for use in child classes.
        try:
            self._set_variables()
        except Exception as e:
            msg = ("Error loading object variables: %s: %s" % (self, e))
            logger.critical(msg, exc_info=True)
            config.raise_exception()
            return False
        # Set child class variables.
        try:
            self.set_variables()
        except Exception as e:
            msg = "Error to loading child class variables: %s: %s" % (self, e)
            logger.critical(msg, exc_info=True)
            return False
        self._load_key()
        self._load_cert()
        self._load_cert_public_key()
        self._load_private_key()
        self._load_public_key()

    @load_object()
    def _load(self, read_from_cache=True, no_update=False):
        """ Load object config from backend. """
        # Check for replacement method when beeing offline (e.g. offline tokens)
        read_method = backend.read_config
        if self.offline:
            try:
                read_method = config.offline_methods['read_config'][self.oid.read_oid]
            except Exception as e:
                pass
        else:
            if not backend.is_available(write=False):
                raise BackendUnavailable("Backend not available.")

        # Check if we got the object config via kwargs.
        object_config = None
        if self.kwargs_object_config:
            object_config = ObjectConfig(object_id=self.oid,
                                object_config=self.kwargs_object_config,
                                encrypted=False)
            self.kwargs_object_config = None

        # Try to get object config from backend.
        if not object_config:
            try:
                object_config = read_method(object_id=self.oid,
                                    read_from_cache=read_from_cache)
            except Exception as e:
                msg = ("Error reading object config (%s): %s: %s"
                        % (read_method, self, e))
                logger.critical(msg, exc_info=True)
                return False
            # Load object config.
            if object_config:
                object_config = ObjectConfig(object_id=self.oid,
                                    object_config=object_config,
                                    encrypted=False)
            if no_update:
                return object_config

        # Cannot load object without data.
        if not object_config:
            return False

        # Set new object config.
        self.object_config = object_config

        return True

    def _set_variables(self):
        """ Set instance variables. """
        # Get object config.
        base_config = self._get_base_config()
        # Get object config from child class.
        object_config = self._get_object_config()

        # Handle base object parameters.
        for i in base_config:
            # Make sure we prefer child class config.
            if i in object_config:
                conf = object_config[i]
                object_config.pop(i)
            else:
                conf = base_config[i]
            # Load object config attribute.
            self._config_attribute(attribute=i, conf=conf)

        # Handle child class object parameters.
        for i in object_config:
            conf = object_config[i]
            # Load object config attribute.
            self._config_attribute(attribute=i, conf=conf)

        # Try to get unit.
        #self.set_unit()
        try:
            set_unit_method = getattr(self, "set_unit")
        except:
            set_unit_method = None
        if set_unit_method:
            set_unit_method()

        # Set object path.
        try:
            set_path_method = getattr(self, "set_path")
        except:
            set_path_method = None
        if set_path_method:
            set_path_method()

        return True

    def _config_attribute(self, attribute, conf, update=False):
        """ Read/Update object config attribute. """
        # Get required flag.
        try:
            required = conf['required']
        except:
            required = False

        # Get variable name.
        try:
            var_name = conf['var_name']
        except:
            msg = (_("Got no variable name for attribute: %s")
                    % attribute)
            raise OTPmeException(msg)

        # Check if class attribute is a method.
        val = None
        has_attr = False
        is_method = False
        if hasattr(self, var_name):
            has_attr = True
            x = getattr(self, var_name)
            if type(x) == types.MethodType:
                is_method = True

        # Get value.
        if update:
            if has_attr:
                if is_method:
                    val = x()
                else:
                    val = x
                if isinstance(val, IncrementalDict):
                    if not val.modified:
                        return
                    #print("IIIIIIIIIIIIIIIIIIIIIIIII", self, id(self), var_name, self.incremental_updates)
                    val = val.copy()
                if isinstance(val, IncrementalList):
                    if not val.modified:
                        return
                    #print("iiiiiiiiiiiiiiiiiiiiiii", self, id(self), var_name, self.incremental_updates)
                    val = val.copy()
        else:
            try:
                val = self.object_config.get(attribute, no_headers=True)
            except KeyError:
                val = None
            except Exception as e:
                msg = "Failed to read attribute from object config: %s" % e
                logger.critical(msg)
                raise

        # Make sure we use a copy of the value.
        try:
            val = stuff.copy_object(val)
            #val = copy.deepcopy(val)
        except TypeError as e:
            msg = "Failed to copy attribute value: %s" % attribute
            logger.critical(msg)
            raise

        # Zero length strings should be None.
        if isinstance(val, str) and len(val) == 0:
            val = None

        # Get value type.
        try:
            type_wanted = conf['type']
        except:
            type_wanted = str
        # Check if we should force value type.
        try:
            force_type = conf['force_type']
        except:
            force_type = False

        # Get compression tag to add.
        try:
            compression = conf['compression']
        except:
            compression = None
        if compression and not compression in config.supported_compression_types:
            msg = (_("Got unknown compression type '%(compression)s' "
                    "for attribute: %(attribute)s")
                    % {"compression":compression, "attribute":attribute})
            raise OTPmeException(msg)
        # Get encoding tag to add.
        try:
            encoding = conf['encoding']
        except:
            encoding = None
        if encoding and not encoding in config.supported_encoding_types:
            msg = (_("Got unknown encoding type '%(encoding)s' "
                    "for attribute: %(attribute)s")
                    % {"encoding":encoding, "attribute":attribute})
            raise OTPmeException(msg)
        # Get encryption tag to add.
        try:
            encryption = conf['encryption']
        except:
            encryption = None
        if encryption and not encryption in config.supported_encryption_types:
            msg = (_("Got unknown encryption type '%(encryption)s "
                    "for attribute: %(attribute)s")
                    % {"encryption":encryption, "attribute":attribute})
            raise OTPmeException(msg)

        # Make sure we en-/decode value as JSON if needed.
        encode_as_json = False
        if compression:
            encode_as_json = True
        if encoding:
            encode_as_json = True
        if encryption:
            encode_as_json = True

        if update:
            if self.check_attribute_types:
                # Make sure we got a value of the wanted type.
                type_ok = False
                if type(type_wanted) == type \
                or type(type_wanted) == type(str):
                    if isinstance(val, type_wanted):
                        type_ok = True
                    else:
                        if force_type:
                            # None type values will always stay None.
                            if val is None:
                                type_ok = True
                            else:
                                try:
                                    val = type_wanted(val)
                                    type_ok = True
                                except:
                                    pass

                elif type_wanted == "uuid":
                    if isinstance(val, str) and stuff.is_uuid(val):
                        type_ok = True
            else:
                type_ok = True

            # If the attribute is None and not required remove it from the
            # current object config.
            if val is None and not required:
                if attribute in self.object_config:
                    self.object_config.pop(attribute)
                return

            if not type_ok:
                msg = (_("Cannot update. Got wrong value for '%(attribute)s': "
                        "%(object_id)s: Wanted: %(type_wanted)s Got: %(val_type)s: %(val)s")
                        % {"attribute":attribute,
                            "object_id":self.oid,
                            "type_wanted":type_wanted,
                            "val_type":repr(type(val)),
                            "val":val})
                logger.warning(msg)
                raise OTPmeException(msg)

            # Make sure we set empty value right.
            if val is None:
                if type_wanted is list:
                    val = []
                if type_wanted is dict:
                    val = {}

            # Get copy of value.
            val = stuff.copy_object(val)
            #val = copy.deepcopy(val)

            # Encode val as JSON.
            if encode_as_json:
                val = json.encode(val)

            # Set object config attribute.
            self.object_config.add(attribute, val,
                                compression=compression,
                                encoding=encoding,
                                encryption=encryption)
        else:
            if encode_as_json:
                try:
                    val = json.decode(val)
                except OTPmeTypeError:
                    pass
            if self.check_attribute_types:
                type_ok = False
                if type_wanted is list:
                    if isinstance(val, list):
                        type_ok = True
                elif type_wanted is dict:
                    if isinstance(val, dict):
                        type_ok = True
                elif type_wanted == "uuid":
                    if isinstance(val, str) and stuff.is_uuid(val):
                        type_ok = True
                elif type(type_wanted) is type \
                or type(type_wanted) is type(str):
                    if isinstance(val, type_wanted):
                        type_ok = True
                    elif force_type:
                        # None type values will always stay None.
                        if val is None:
                            type_ok = True
                        else:
                            try:
                                val = type_wanted(val)
                                type_ok = True
                            except:
                                pass
                    else:
                        type_ok = False
                else:
                    msg = (_("Got unknown value type: %s") % type_wanted)
                    raise OTPmeException(msg)
            else:
                type_ok = True

            if not type_ok:
                # If the attribute is None and not required we can ignore it.
                if val is None and not required:
                    return
                msg = (_("Cannot load. Got wrong value for '%(attribute)s': "
                        "%(object_id)s: Wanted: %(type_wanted)s Got: %(val_type)s: %(val)s")
                        % {"attribute":attribute,
                            "object_id":self.oid,
                            "type_wanted":type_wanted,
                            "val_type":repr(type(val)),
                            "val":val})
                logger.warning(msg)
                raise OTPmeException(msg)

            # Set class variable.
            if val is None:
                if type_wanted is list:
                    val = []
                if type_wanted is dict:
                    val = {}
            if has_attr and not is_method:
                attr = getattr(self, var_name)
                attr_type = type(attr)
                if attr_type == IncrementalList:
                    attr.set(val)
                elif attr_type == IncrementalDict:
                    attr.set(val)
                else:
                    setattr(self, var_name, val)

    def update_object_config(self):
        """ Update object config. """
        # Get object config.
        base_config = self._get_base_config()
        # Get object config from child class.
        object_config = self._get_object_config()

        # Handle base object parameters.
        for i in base_config:
            # Make sure we prefer child class config.
            if i in object_config:
                conf = object_config[i]
                object_config.pop(i)
            else:
                conf = base_config[i]
            # Update object config attribute.
            self._config_attribute(attribute=i, conf=conf, update=True)

        # Handle child class object parameters.
        for i in object_config:
            conf = object_config[i]
            # Update object config attribute.
            self._config_attribute(attribute=i, conf=conf, update=True)

    def update_last_modified(self):
        """ Update last modified times. """
        # Set last modified timestamp.
        self.last_modified = int(time.time())
        # Update index.
        self.update_index('last_modified', self.last_modified)

    @object_lock()
    def touch(self, callback=default_callback, **kwargs):
        return self._write(callback=callback)

    @object_lock()
    def _write(self, cluster=True, update_last_modified=True,
        callback=default_callback):
        """ Write object config to backend. """
        if self.oid is None:
            msg = ("Object misses OID: %s" % self)
            raise OTPmeException(msg)
        if self.uuid is None:
            msg = ("Object misses UUID: %s" % self.oid)
            raise OTPmeException(msg)
        if self.type in config.tree_object_types:
            if self.name is None:
                msg = ("Object misses name: %s" % self.oid)
                raise OTPmeException(msg)

        if update_last_modified:
            # Update last modified timestamp.
            self.update_last_modified()

        # Process index journal.
        index_journal = []
        if self.index_journal:
            index_journal = copy.deepcopy(self.index_journal)
        self.index_journal = []

        # Update object config from variables.
        self.update_object_config()

        # Add incremental update stuff.
        self.object_config['INDEX_JOURNAL'] = index_journal
        self.object_config['LIST_ATTRIBUTES'] = self.list_attributes
        self.object_config['DICT_ATTRIBUTES'] = self.dict_attributes
        self.object_config['INCREMENTAL_UPDATES'] = list(self.incremental_updates)

        if self.incremental_updates:
            # Clear incremental journal.
            self.incremental_updates.clear()

        # No need to write unmodified object.
        if not self.object_config.modified:
            return

        msg = "Writing object: %s" % self.oid
        logger.debug(msg)

        # Check for replacement method when being offline (e.g. offline tokens).
        write_method = backend.write_config
        if self.offline:
            try:
                write_method = config.offline_methods['write_config'][self.oid.read_oid]
            except:
                pass
        elif not backend.is_available():
            raise BackendUnavailable("Backend not available.")

        # Try to write object config to backend.
        try:
            write_method(object_id=self.oid,
                        instance=self,
                        cluster=cluster,
                        no_transaction=self.no_transaction,
                        index_journal=index_journal)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error writing config for %s '%s': %s")
                    % (self.type, self.oid, e))
            if config.daemon_mode:
                # When running in daemon mode we never want to raise an exception
                # but log the error and return the status via callback on write
                # failure.
                logger.critical(msg)
                return callback.error(msg, raise_exception=False)
            else:
                return callback.error(msg)

        return callback.ok()

    def update_index(self, key, value, **kwargs):
        """ Update attribute in object index. """
        self.del_index(key)
        self.add_index(key, value, **kwargs)

    def add_index(self, key, value):
        """ Add attribute to object index. """
        if [key, value] in self.index:
            return
        self.index.append([key, value])
        self.index_journal.append(('add', key, value))

    def del_index(self, key, value=None):
        """ Remove attribute from object index. """
        if value is not None:
            try:
                self.index.remove([key, value])
            except ValueError:
                pass
            self.index_journal.append(('del', key, value))
            return
        for x in list(self.index):
            x_key = x[0]
            if x_key != key:
                continue
            self.index.remove(x)
            x_val = x[1]
            self.index_journal.append(('del', x_key, x_val))

    def add(self, uuid=None, verbose_level=0, callback=default_callback,
        write=True, **kwargs):
        """ Should be called from child class to add object. """
        if uuid is not None:
            self.uuid = uuid
        # Origin node this object was created on.
        self.origin = config.uuid
        origin = backend.get_object(uuid=config.uuid)
        if origin:
            self.origin_cache = origin.oid.full_oid
        # Set create time.
        self.create_time = int(time.time())
        # Update index.
        self.update_index('create_time', self.create_time)
        self.update_index('realm_uuid', self.realm_uuid)
        self.update_index('site_uuid', self.site_uuid)
        self.add_index('origin', self.origin)
        if write:
            return self._write(callback=callback)
        return self._cache(callback=callback)

    def delete(self, force=False, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Delete object from backend. """
        msg = "Deleting object: %s" % self.oid
        logger.debug(msg)
        # Make sure this object will not be written on cache.flush().
        self._modified = False
        cache.remove_modified_object(self.oid)
        # Delete object.
        try:
            backend.delete_object(object_id=self.oid,
                            cluster=True,
                            no_transaction=self.no_transaction)
        except UnknownObject:
            pass
        except Exception as e:
            config.raise_exception()
            msg = (_("Error removing %(object_type)s 's(rel_path)s': %(error)s")
                    % {"object_type":self.type,
                    "rel_path":self.rel_path,
                    "error":e})
            return callback.error(msg)

        return callback.ok()

    def update_last_used_time(self):
        """ Update last_used time for this object. """
        if not self.track_last_used:
            return
        msg = "Updating last used timestamp of %s: %s" % (self.type, self)
        logger.debug(msg)
        self.last_used = int(time.time())

    def get_last_used_time(self, return_type="epoch"):
        """ Get last_used time of this object. """
        last_used = self.last_used
        if return_type == "date":
            try:
                last_used = datetime.datetime.fromtimestamp(last_used)
            except Exception as e:
                msg = (_("Invalid last used timestamp: %s: %s")
                            % (self.oid, last_used))
                logger.warning(msg, exc_info=True)
        return last_used

    def is_special_object(self, return_true_false=True):
        """ Check if object is a base or internal object. """
        base_object, \
        internal_object = cli.check_special_object(self.type, self.name)
        if not return_true_false:
            return base_object, internal_object
        if base_object:
            return True
        if internal_object:
            return True
        return False

class OTPmeObject(OTPmeBaseObject):
    """ Generic OTPme object. """
    def __init__(self, object_id=None, realm=None, site=None,
        unit=None, name=None, path=None, object_config=None,
        template=False, dummy=False, **kwargs):
        # Call parent class init.
        super(OTPmeObject, self).__init__(object_config=object_config, **kwargs)

        self.unit = None
        self.unit_uuid = None
        # All child objects we locked on acquire_lock(recursive=True).
        self.child_locks = []

        # The resolver this object was added by.
        self.resolver = None
        # The key used by the resolver to identify the object (e.g. on rename)
        self.resolver_key = None
        # The checksum of the object parameters received from the resolver.
        self.resolver_checksum = None

        # Make sure we have at least empty ACL variables.
        self._acls = []
        self._value_acls = {}
        self._default_acls = []

        # Not every object has all attributes but all OTPme objects need them,
        # at least set to None.
        self.access_group = None
        self.path = None
        self.rel_path = None
        self._enabled = False
        self.acl_inheritance_enabled = None
        self._extensions = {}
        self.token_owner = None
        self.description = ""
        self.secret = None
        self.secret_format_regex = None
        self.secret_format_warning = None
        self.signable = False
        self.signatures = {}
        self.creator = None
        self.creator_cache = None
        self.template_object = template

        self.auto_disable = ""
        self.unused_disable = False
        self.auto_disable_start_time = 0.0

        self._base_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "UUID",
                            "REALM",
                            "SITE",
                            "UNIT",
                            "NAME",
                            "TYPE",
                            "INDEX",
                            "ENABLED",
                            "LDIF",
                            "LDIF_ATTRIBUTES",
                            "EXTENSION_ATTRIBUTES",
                            "POLICIES",
                            "POLICY_OPTIONS",
                            "CONFIG_PARAMS",
                            "CHECKSUM",
                            "SYNC_CHECKSUM",
                            "SALT",
                            "DESCRIPTION",
                            "CREATOR",
                            "CREATE_TIME",
                            "LAST_MODIFIED",
                            "TEMPLATE",
                            "ORIGIN",
                            ],
                        },

                    'node'  : {
                        'untrusted'  : [
                            "UUID",
                            "REALM",
                            "SITE",
                            "UNIT",
                            "NAME",
                            "TYPE",
                            "CERT",
                            "INDEX",
                            "TEMPLATE_INDEX",
                            "LDIF",
                            "LDIF_ATTRIBUTES",
                            "EXTENSION_ATTRIBUTES",
                            "ENABLED",
                            "UNUSED_DISABLE",
                            "AUTO_DISABLE",
                            "AUTO_DISABLE_START_TIME",
                            "POLICIES",
                            "POLICY_OPTIONS",
                            "CONFIG_PARAMS",
                            "CHECKSUM",
                            "SYNC_CHECKSUM",
                            "SALT",
                            "DESCRIPTION",
                            "CREATOR",
                            "CREATE_TIME",
                            "LAST_MODIFIED",
                            "TEMPLATE",
                            "ORIGIN",
                            ],
                        },
                    }

        # Type checking is only needed on nodes the object is managed by.
        self.check_attribute_types = True
        try:
            host_type = config.host_data['type']
        except:
            host_type = None
        if host_type == "host":
            self.check_attribute_types = False
        elif host_type == "node":
            try:
                my_realm = config.host_data['realm']
            except:
                my_realm = None
            if self.realm != my_realm:
                self.check_attribute_types = False
            else:
                try:
                    my_site = config.host_data['site']
                except:
                    my_site = None
                if self.site != my_site:
                    self.check_attribute_types = False

        # We only set realm if subclass is not of type realm.
        if self.type != "realm":
            # Set realm if given or use own.
            if realm:
                self.realm = realm
            else:
                self.realm = config.realm

            if config.realm:
                if self.realm != config.realm:
                    r = backend.get_object(object_type="realm",
                                            name=self.realm)
                    if not r:
                        msg = (_("Unknown realm '%'.") % self.realm)
                        raise OTPmeException(msg)
                    self.realm_uuid = r.uuid
                else:
                    self.realm_uuid = config.realm_uuid

        if object_id:
            self.oid = object_id
            self.realm = object_id.realm
            self.site = object_id.site
            self.unit = object_id.unit
            self.name = object_id.name
            self.path = object_id.path
            self.rel_path = object_id.rel_path
        elif path:
            # Remove tailing slash from path.
            #self.path = re.sub('/$', '', path)
            self.path = path
            # Check path format
            if not oid.check_path(self.type, self.path):
                msg = (_("Invalid path: %s") % self.path)
                raise OTPmeException(msg)

            x = oid.resolve_path(self.path, object_type=self.type)
            self.realm = x['realm']
            self.site = x['site']
            self.unit = x['unit']
            self.rel_path = x['rel_path']
            self.name = x['name']
        else:
            self.name = name
            self.realm = realm
            self.site = site
            self.unit = unit
            if not dummy:
                self.set_path()

        if dummy:
            self.oid = oid.get(object_type="user",
                                realm=config.realm,
                                site=config.site,
                                name="dummy")
            return

        # Set default unit if none was given.
        if not self.unit:
            x_type = self.type
            if self.template_object:
                x_type = "template"
            try:
                #self.unit = config.default_units[x_type]
                self.unit = config.get_default_unit(x_type)
            except:
                pass

        # Set unit.
        self.set_unit()

        # Set name using child class method (e.g. to ensure names are
        # lowercase etc.)
        self._set_name(self.name)
        # Set our object ID.
        if not self.oid:
            self.set_oid()

        # Make sure we got a valid OID.
        self.oid.verify()

        # Set object config.
        self.object_config = ObjectConfig(self.oid)

        # We only set site if subclass is not of type site.
        if self.type == "site":
            self.site = None
            self.site_uuid = None
        else:
            # Set site UUID if we have one.
            if self.site and config.site:
                if self.site != config.site:
                    site_oid = oid.get(object_type="site",
                                        realm=self.realm,
                                        name=self.site)
                    if not site_oid:
                        msg = (_("Unknown site '%s'.") % self.site)
                        raise OTPmeException(msg)
                    site_uuid = backend.get_uuid(site_oid)
                    self.site_uuid = site_uuid
                else:
                    self.site_uuid = config.site_uuid

        if not oid.check_name(self.type, self.name):
            msg = (_("Invalid name: %s") % self.name)
            raise OTPmeException(msg)

    def set_oid(self, new_oid=None, switch_lock=False,
        lock_caller=None, callback=default_callback, **kwargs):
        """ Set our OID. """
        # Without lock nothing to switch.
        if not self._object_lock:
            switch_lock = False
        if switch_lock and not lock_caller:
            msg = "Need <lock_caller> if <switch_lock=True>."
            raise OTPmeException(msg)
        # Save lock of old OID.
        if switch_lock:
            old_oid = self.oid.read_oid
            old_lock = self._object_lock
            old_lock_callers = list(old_lock.lock_callers)
        # Gen new OID.
        if new_oid is None:
            new_oid = oid.OTPmeOid(object_type=self.type,
                                        realm=self.realm,
                                        site=self.site,
                                        unit=self.unit,
                                        path=self.path,
                                        name=self.name,
                                        full=True)
        # Check if we have to switch the lock to a new OID.
        if switch_lock:
            if new_oid.read_oid != old_oid:
                # Switch lock to new OID.
                try:
                    new_lock = locking.acquire_lock(lock_type=OBJECT_LOCK_TYPE,
                                                lock_id=new_oid.read_oid,
                                                lock_caller=lock_caller,
                                                callback=callback)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Failed to acquire lock of new OID: %s: %s")
                            % (new_oid.read_oid, e))
                    raise OTPmeException(msg)
                # Switch lock callers.
                old_lock.lock_callers = list(self._object_lock.lock_callers)
                # Set lock callers of old lock.
                new_lock.lock_callers = old_lock_callers
                # Release old lock.
                old_lock.release_lock(lock_caller=lock_caller)
        # Finally set new OID.
        self.oid = new_oid

    def set_resolver(self, resolver):
        """ Set resolver. """
        self.resolver = resolver
        self.update_index('resolver', self.resolver)

    def set_resolver_key(self, resolver_key):
        """ Set resolver key. """
        self.resolver_key = resolver_key
        self.update_index('resolver_key', self.resolver_key)

    def set_resolver_checksum(self, resolver_checksum):
        """ Set resolver checksum. """
        self.resolver_checksum = resolver_checksum
        self.update_index('resolver_checksum', self.resolver_checksum)

    def _load(self, read_from_cache=True, no_update=False):
        """ Load object config from backend. """
        # Call base class write method.
        result = super(OTPmeObject, self)._load()
        # Preload object extensions.
        self.preload_extensions()
        return result

    def exists(self, run_policies=True):
        """ Check if object exists. """
        if self.object_config:
            object_exists = backend.object_exists(self.oid)
        else:
            try:
                object_exists = self._load()
            except Exception as e:
                msg = "Failed to read object config: %s: %s" % (self, e)
                logger.critical(msg, exc_info=True)
                raise

        if self.offline:
            return True

        if not object_exists:
            return False

        if run_policies:
            try:
                self.run_policies("exists")
            except BackendUnavailable as e:
                msg = ("Unable to run policies. Backend not available.")
                logger.debug(msg)
            except Exception as e:
                config.raise_exception()
                msg = ("Error running 'exists' policy hook: %s: %s"
                        % (self.oid, e))
                logger.warning(msg, exc_info=True)

        # Check for auto-disable of object.
        self.check_auto_disable()

        return True

    @property
    def enabled(self):
        if self.template_object:
            return False
        self.check_auto_disable()
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def auto_disable_time(self):
        if not self.auto_disable:
            return 0.0
        if self.unused_disable:
            check_time = self.get_last_used_time()
        else:
            check_time = self.auto_disable_start_time
        try:
            # Check if given date string is valid.
            auto_disable_time = units.string2unixtime(self.auto_disable, check_time)
        except Exception as e:
            msg = "Invalid date string: %s" % e
            raise OTPmeException(msg)
        auto_disable_time = datetime.datetime.fromtimestamp(auto_disable_time)
        auto_disable_time = auto_disable_time.strftime('%d.%m.%Y %H:%M:%S')
        return auto_disable_time

    @property
    def valid_config_params(self):
        """ Get valid config parameters. """
        # Realm does support all config parameters.
        valid_config_params = []
        for x in config.valid_config_params:
            object_types = config.valid_config_params[x]['object_types']
            if self.type not in object_types:
                continue
            valid_config_params.append(x)
        return valid_config_params

    @config_cache.cache_method()
    def get_config_parameter(self, parameter):
        """ Get config parameter. """
        # Try to get the default value.
        try:
            default_value = config.valid_config_params[parameter]['default']
        except:
            default_value = None

        parent_object = self
        while True:
            try:
                value = parent_object.config_params[parameter]
            except:
                value = None

            if value:
                break

            parent_object = parent_object.get_parent_object(run_policies=False)
            if not parent_object:
                break

        if value is None:
            value = default_value

        return value

    def set_config_param(self, parameter, value=None,
        callback=default_callback, **kwargs):
        """ Set config parameter. """
        try:
            value_type = config.valid_config_params[parameter]['type']
        except:
            msg = "Invalid parameter: %s: %s" % (self, parameter)
            return callback.error(msg)

        try:
            valid_values = config.valid_config_params[parameter]['valid_values']
        except:
            valid_values = []

        # Delete config parameter.
        if value is None:
            self.config_params.pop(parameter)
            config_cache.invalidate()
            return self._cache(callback=callback)

        if not isinstance(value, value_type):
            msg = ("Parameter <%s> needs to be of type: %s"
                    % (parameter, value_type))
            return callback.error(msg)

        if valid_values:
            if not value in valid_values:
                msg = "Invalid value: %s: %s" % (parameter, value)
                return callback.error(msg)

        self.config_params[parameter] = value

        config_cache.invalidate()

        return self._cache(callback=callback)

    def _get_base_config(self):
        """ Get base object config """
        base_config = {
            'UUID'                      : {
                                            'var_name'      : 'uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'TYPE'                      : {
                                            'var_name'      : 'type',
                                            'type'          : str,
                                            'required'      : True,
                                        },

            'NAME'                      : {
                                            'var_name'      : 'name',
                                            'type'          : str,
                                            'required'      : True,
                                        },

            'ENABLED'                   : {
                                            'var_name'      : '_enabled',
                                            'type'          : bool,
                                            'required'      : True,
                                        },

            'UNUSED_DISABLE'            : {
                                            'var_name'      : 'unused_disable',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'AUTO_DISABLE'            : {
                                            'var_name'      : 'auto_disable',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'AUTO_DISABLE_START_TIME'   : {
                                            'var_name'      : 'auto_disable_start_time',
                                            'type'          : float,
                                            'force_type'    : True,
                                            'required'      : False,
                                        },

            'LDIF'                      : {
                                            'var_name'      : 'ldif',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'LDIF_ATTRIBUTES'           : {
                                            'var_name'      : 'ldif_attributes',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'EXTENSION_ATTRIBUTES'      : {
                                            'var_name'      : 'extension_attributes',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'ACL_INHERITANCE_ENABLED'   : {
                                            'var_name'      : 'acl_inheritance_enabled',
                                            'type'          : bool,
                                            'required'      : False,
                                        },

            'REALM'                     : {
                                            'var_name'      : 'realm_uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'SITE'                      : {
                                            'var_name'      : 'site_uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'CERT'                      : {
                                            'var_name'      : 'cert',
                                            'type'          : str,
                                            'required'      : False,
                                            'encoding'      : 'BASE64',
                                        },

            'KEY'                       : {
                                            'var_name'      : 'key',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'UNIT'                      : {
                                            'var_name'      : 'unit_uuid',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },

            'SECRET'                    : {
                                            'var_name'      : 'secret',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'OBJECT_CLASSES'            : {
                                            'var_name'      : 'object_classes',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'EXTENSIONS'                : {
                                            'var_name'      : 'extensions',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'CONFIG_PARAMS'             : {
                                            'var_name'      : 'config_params',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'POLICIES'                  : {
                                            'var_name'      : 'policies',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'POLICY_OPTIONS'            : {
                                            'var_name'      : 'policy_options',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'ACLS'                      : {
                                            'var_name'      : 'acls',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'TEMPLATE'                  : {
                                            'var_name'      : 'template_object',
                                            'type'          : bool,
                                            'required'      : True,
                                        },

            'DESCRIPTION'               : {
                                            'var_name'      : 'description',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'RESOLVER'                  : {
                                            'var_name'      : 'resolver',
                                            'type'          : "uuid",
                                            'required'      : False,
                                        },

            'RESOLVER_KEY'         : {
                                            'var_name'      : 'resolver_key',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'RESOLVER_CHECKSUM'         : {
                                            'var_name'      : 'resolver_checksum',
                                            #'type'          : dict,
                                            'type'          : str,
                                            'required'      : False,
                                            #'encoding'      : 'HEX',
                                        },

            'CREATOR'                   : {
                                            'var_name'      : 'creator',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'CREATOR_CACHE'             : {
                                            'var_name'      : 'creator_cache',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'CREATE_TIME'               : {
                                            'var_name'      : 'create_time',
                                            'type'          : int,
                                            'required'      : True,
                                        },

            'LAST_MODIFIED'             : {
                                            'var_name'      : 'last_modified',
                                            'type'          : int,
                                            'required'      : True,
                                        },
            'INDEX'                     : {
                                            'var_name'      : 'index',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'ORIGIN'                    : {
                                            'var_name'      : 'origin',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },
            'ORIGIN_CACHE'              : {
                                            'var_name'      : 'origin_cache',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            'VERSION'                   : {
                                            'var_name'      : 'version',
                                            'type'          : int,
                                            'required'      : True,
                                        },
            }
        return base_config

    def acquire_lock(self, lock_caller, recursive=False,
        skip_same_caller=False, callback=default_callback, **kwargs):
        """ Acquire object lock. """
        if self.offline:
            return
        # Call parent class method.
        super(OTPmeObject, self).acquire_lock(lock_caller,
                                skip_same_caller=skip_same_caller,
                                callback=callback, **kwargs)
        if not recursive:
            return
        # Acquire child locks.
        self.acquire_child_locks(lock_caller=lock_caller,
                                skip_same_caller=skip_same_caller,
                                callback=callback)

    def acquire_child_locks(self, lock_caller, skip_same_caller=False,
        callback=default_callback, _caller="API"):
        """ Lock all child objects. """
        # Lock all child objects.
        child_objects = self.get_members(return_type="instance", recursive=True)
        for t in child_objects:
            for x in child_objects[t]:
                x.acquire_lock(lock_caller=lock_caller,
                                skip_same_caller=skip_same_caller,
                                callback=callback)
                self.child_locks.append(x)

    def release_lock(self, lock_caller=None, recursive=False, callback=None, **kwargs):
        """ Release object lock. """
        # Remove child locks.
        if recursive:
            self.release_child_locks(lock_caller=lock_caller,
                                    callback=callback)
        super(OTPmeObject, self).release_lock(lock_caller=lock_caller,
                                                callback=callback, **kwargs)

    def release_child_locks(self, lock_caller, callback=default_callback):
        """ Release lock of all child objects. """
        # Release child objects.
        for x in list(self.child_locks):
            x.release_lock(lock_caller=lock_caller, callback=callback)
            self.child_locks.remove(x)

    def set_path(self):
        """ Set object path and relative path. """
        if self.realm and self.site and self.unit:
            path_parts = [self.realm, self.site]
            path_parts += self.unit.split("/")
            path_parts.append(self.name)
            self.path = "/%s" % "/".join(path_parts)
        else:
            if self.type == "realm":
                self.path = "/%s" % self.name
            elif self.type == "site":
                self.path = "/%s/%s" % (self.realm, self.name)
            #else:
            #    if self.site:
            #        self.path = "/%s/%s/%s" % (self.realm, self.site, self.name)
            #        self.rel_path = self.name

        if self.path and oid.check_path(self.type, self.path):
            self.rel_path = "/".join(self.path.split("/")[3:])

    @property
    def confirmation_policy(self):
        """ The confirmation policy to apply for user requests. """
        confirmation_policy = self.get_config_parameter("confirmation_policy")
        return confirmation_policy

    @property
    def auto_sign(self):
        """
        The auto-sign config parameter to configre if the object should be
        signed automatically on change.
        """
        # Disable auto-sign while adding a site.
        if config.site_init:
            return False
        auto_sign = self.get_config_parameter("auto_sign")
        return auto_sign

    @property
    def auto_revoke(self):
        """
        The auto-revoke config parameter to configre if object signatures should
        be revoked automatically on object delete/update.
        """
        auto_revoke = self.get_config_parameter("auto_revoke")
        return auto_revoke

    def acquire_cached_lock(self, callback=default_callback):
        """ Acquire cached lock. """
        self.acquire_lock(lock_caller="cached",
                        skip_same_caller=True,
                        callback=callback)
        # Add object to callback (used after job has finished).
        callback.add_locked_object(self)

    def _cache(self, callback=default_callback):
        """ Mark object changes to be written on next write. """
        # Mark object as modified.
        self._modified = True
        self._cached = True
        # Add object to cache (used on cache.flush()).
        cache.add_modified_object(self)
        # Add object to callback (used after job has finished).
        if callback is not None:
            callback.add_modified_object(self)
        # Add modified object to transaction.
        if not self.no_transaction:
            transaction = backend.get_transaction()
            if transaction:
                transaction.cache_modified_object(self)
        # Ensure object keeps locked after method call (object_lock decorator!).
        if self.full_write_lock:
            self.acquire_cached_lock(callback=callback)
        return callback.ok()

    @object_lock()
    def _write(self, update_last_modified=True,
        callback=default_callback, **kwargs):
        """ Write object config to backend. """
        if not self.offline:
            if not self._object_lock:
                msg = "Cannot write without object lock: %s" % self
                raise OTPmeException(msg)
            if self._object_lock.outdated:
                msg = "Cannot write object with expired lock: %s" % self
                return callback.error(msg)

        # Check if we are within a transaction.
        transaction = None
        if not self.no_transaction:
            transaction = backend.get_transaction()

        if transaction is not None:
            if self._last_modified_written:
                update_last_modified = False

        if update_last_modified:
            # Update last modified timestamp.
            self.update_last_modified()
            # Update extensions.
            self.update_extensions("update_modified_timestamp",
                                    callback=callback)

        # Call base class write method.
        super(OTPmeObject, self)._write(update_last_modified=False,
                                        callback=callback,
                                        **kwargs)

        # Update auth user if needed. There is also some code to update the
        # auth user in OTPmeMgmtP1().
        if self.type == "user":
            if config.auth_user:
                if self.uuid == config.auth_user.uuid:
                    config.auth_user = self

        # Update auth token if needed. There is also some code to update the
        # auth token in OTPmeMgmtP1().
        if self.type == "token":
            if config.auth_token:
                if self.uuid == config.auth_token.uuid:
                    config.auth_token = self

        # Release cache lock.
        if self._cached:
            self._cached = False
            if self.full_write_lock:
                self.release_lock(lock_caller="cached", callback=callback)

        # Handle modified flags.
        if self._modified:
            # With an activate transaction we must keep the modified state
            # because the transaction does the final write.
            if transaction:
                # Remember write status for last modified attribute.
                self._last_modified_written = True
            else:
                # Remove object from cache (used on cache.flush()).
                cache.remove_modified_object(self.oid)
                # Reset modified.
                self._modified = False
                # Reset write status.
                self._transaction_written = False
        return callback.ok()

    @check_acls(acls=['export'])
    def export_config(self, run_policies=True, password=None,
        _caller="API", callback=default_callback, **kwargs):
        """ Export object config. """
        if not self.exists():
            msg = (_("Object '%s' does not exist.") % self.oid)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("export", callback=callback, _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        fake = True
        enc_key = None
        key_salt = None
        if password is not None:
            fake = False
            x = encryption.derive_key(password, hash_type=config.object_export_hash_type)
            enc_key = x['key']
            key_salt = x['salt']

        # Get current object config from backend.
        object_config = backend.read_config(self.oid)
        object_config['OID'] = self.oid.full_oid
        if key_salt:
            object_config['ENC_SALT'] = key_salt

        # Encrypt object config.
        object_config = ObjectConfig(object_id=self.oid,
                                object_config=object_config,
                                encrypted=False)
        encrypted_object_config = object_config.encrypt(enc_key, fake=fake)
        # Encode object config.
        config_string = ujson.dumps(encrypted_object_config, indent=4, sort_keys=True)
        return callback.ok(config_string)

    def get_members(self, **kwargs):
        """ Dummy method, to be overridden by child class. """
        return []

    def get_parent_object(self, run_policies=True, callback=default_callback):
        """ Get parent object of this object (e.g. its unit). """
        parent_type = "unit"
        parent_uuid = self.unit_uuid
        if self.type == "realm":
            return
        if self.type == "site":
            parent_uuid = self.realm_uuid
            parent_type = "realm"
        if self.type == "unit":
            if not self.unit_uuid:
                parent_type = "site"
                parent_uuid = self.site_uuid

        if not parent_uuid:
            msg = (_("Unable to get parent object of: %s") % self.oid)
            return callback.error(msg)

        parent_object = backend.get_object(uuid=parent_uuid,
                                        object_type=parent_type,
                                        run_policies=run_policies)
        if not parent_object:
            msg = (_("Unknown parent object: %s") % parent_uuid)
            return callback.error(msg)

        return parent_object

    def preload_extensions(self, verbose_level=0, callback=default_callback):
        """ Preload all extensions for this object. """
        from otpme.lib.extensions import utils
        # Empty extensions stuff.
        self._extensions = {}
        extensions = utils.load_extensions(self.extensions)
        for _e in extensions:
            #_e.load_schema(verbose_level=verbose_level, callback=callback)
            _e.preload(self)
            self._extensions[_e.name] = _e

    def load_extensions(self, verbose_level=0, callback=default_callback):
        """ Load all extensions for this object. """
        from otpme.lib.extensions import utils
        # Empty extensions stuff.
        self.ldif = {}
        self._extensions = {}
        self.ldif_attributes = []

        extensions = utils.load_extensions(self.extensions)
        for _e in extensions:
            try:
                _e.load(self, log_errors=True,
                        verbose_level=verbose_level,
                        callback=callback)
                self._extensions[_e.name] = _e
            except Exception as e:
                config.raise_exception()
                msg = (_("Failed to load extension: %s: %s") % (_e.name, e))
                logger.critical(msg)
                callback.send(msg)

    @check_acls(acls=['add:extension'])
    @object_lock()
    def add_extension(self, extension, default_attributes={},
        run_policies=True, verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Add OTPme extension to object. """
        if extension in self.extensions:
            msg = (_("Extension already enabled for this object."))
            return callback.error(msg)

        try:
            ext = utils.get_extension(extension)
        except Exception as e:
            config.raise_exception()
            return callback.error(str(e))

        if not self.type in ext.object_types:
            msg = (_("Extension '%s' not valid for this object type.")
                    % extension)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_extension",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                config.raise_exception()
                return callback.error(msg)

        for dep_ext in ext.need_extensions:
            if not dep_ext in self.extensions:
                msg = (_("Cannot add extension '%(ext_name)s' that depends on "
                        "extension %(dep_ext)s'.")
                        % {"ext_name":ext.name, "dep_ext":dep_ext})

                # FIXME: log user messages?
                #logger.critical(msg)
                return callback.error(msg)

        # Init extension.
        ext.init(self, default_attributes=default_attributes,
                verbose_level=verbose_level, callback=callback)

        # Add extension to object.
        self.extensions.append(extension)
        # Reload extensions (to re-create ldif)
        self.load_extensions(verbose_level=verbose_level, callback=callback)
        # Update index.
        self.add_index('extension', extension)

        return self._cache(callback=callback)

    @check_acls(acls=['remove:extension'])
    @object_lock()
    def remove_extension(self, extension, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Remove OTPme extension from object. """
        if not extension in self.extensions:
            msg = ("Extension not enabled for this object.")
            return callback.error(msg)

        dep_extensions = []
        for e in dict(self._extensions):
            _e = self._extensions[e]
            for dep_ext in _e.need_extensions:
                if dep_ext == extension:
                    dep_extensions.append(e)

        if len(dep_extensions) > 0:
            msg = (_("Cannot remove extension '%(ext)s' needed by: %(dep_ext)s")
                % {"ext":extension, "dep_ext":", ".join(dep_extensions)})
            # FIXME: log user messages?
            #logger.critical(msg)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_extension",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove extension from object.
        self.extensions.remove(extension)
        # Reload extensions (to re-create ldif)
        self.load_extensions(verbose_level=verbose_level, callback=callback)
        # Update index.
        self.del_index('extension', extension)

        return self._cache(callback=callback)

    ##@backend.transaction
    #def update_extensions(self, hook, write=True,
    #    callback=default_callback, **kwargs):
    #    """ Make sure object is written. """
    #    if write:
    #        self._write(callback=callback)
    #    return self._update_extensions(hook, callback=callback, **kwargs)

    #@object_lock()
    def update_extensions(self, hook, extensions=None,
        fail_on_unknown_hook=False, **kwargs):
        """ Update OTPme extensions. """
        # Get callback.
        try:
            callback = kwargs['callback']
        except:
            callback = default_callback
        # Get verbose level.
        try:
            verbose_level = kwargs['verbose_level']
        except:
            verbose_level = 0

        if extensions is None:
            _extensions = list(self._extensions)
        else:
            _extensions = list(extensions)

        # Get child objects to be updated.
        also_update = {}
        for x in _extensions:
            try:
                extension = self._extensions[x]
            except:
                msg = ("Cannot update unknown extension: %s: %s"
                        % (self.oid, x))
                return callback.error(msg)
            # Check if we have child objects to update.
            try:
                child_types = extension.update_childs[self.type][hook]
            except:
                continue
            # Build list with objects we also need to update.
            update_childs = []
            for child_type in child_types:
                childs = []
                child_hook = child_types[child_type]
                if self.type == "unit":
                    childs = self.get_members(object_types=[child_type],
                                                return_type="instance",
                                                recursive=False)
                    childs = childs[child_type]
                if self.type == "role":
                    if child_type == "group":
                        childs = self.get_groups(return_type="instance")
                        role_roles = self.get_roles(parent=True,
                                                recursive=True,
                                                return_type="instance")
                        for role in role_roles:
                            childs += role.get_groups(return_type="instance")
                if self.type == "user":
                    if child_type == "group":
                        for token_uuid in self.tokens:
                            childs = backend.search(object_type=child_type,
                                                        attribute="token",
                                                        value=token_uuid,
                                                        return_type="instance")
                            token_roles = backend.search(object_type="role",
                                                        attribute="token",
                                                        value=token_uuid,
                                                        return_type="uuid")
                            for role_uuid in token_roles:
                                childs += backend.search(object_type=child_type,
                                                        attribute="role",
                                                        value=role_uuid,
                                                        return_type="instance")
                for child in childs:
                    child_data = (child, child_hook)
                    if child_data in child_types:
                        continue
                    if child.site != config.site:
                        continue
                    update_childs.append(child_data)
            also_update[extension.name] = update_childs

        # Update extensions of this object.
        self.acquire_lock(lock_caller="update_extensions")
        try:
            update_status = True
            for x in _extensions:
                try:
                    extension = self._extensions[x]
                except:
                    msg = ("Cannot update unknown extension: %s: %s"
                            % (self.oid, x))
                    return callback.error(msg)
                # Get hook.
                extension_hook = extension.get_hook(self, hook, **kwargs)
                if not extension_hook:
                    if fail_on_unknown_hook:
                        msg = ("Cannot update unknown hook: %s: %s (%s)"
                                % (self.oid, hook, extension.name))
                        return callback.error(msg)
                    continue
                # Logging.
                msg = ("Updating extension: %s: %s (%s)"
                        % (self.oid, extension.name, hook))
                if config.debug_level() > 3:
                    logger.debug(msg)
                if verbose_level > 2:
                    callback.send(msg)
                # Run extension hook.
                try:
                    update_status = extension_hook(self, **kwargs)
                except Exception as e:
                    msg = ("Failed to run extension hook: %s: %s: %s"
                        % (extension.name, hook, e))
                    logger.warning(msg)
                    config.raise_exception()
        finally:
            self.release_lock(lock_caller="update_extensions")

        # Update child objects.
        update_childs = {}
        updated_childs = []
        for x in also_update:
            update_childs = also_update[x]
            for c in update_childs:
                x_child = c[0]
                x_hook = c[1]
                x_result, \
                x_childs = x_child.update_extensions(hook=x_hook, **kwargs)
                if x_result is None:
                    continue
                updated_childs.append(x_child.oid)

        self._cache(callback=callback)

        return update_status, updated_childs

    def _add_extension_attribute(self, extension, attribute,
        value, auto_value=False, callback=default_callback):
        """ Add extension attribute. """
        if not extension in self.extension_attributes:
            self.extension_attributes[extension] = {}
        if not attribute in self.extension_attributes[extension]:
            self.extension_attributes[extension][attribute] = {}
        try:
            x_auto = self.extension_attributes[extension][attribute][value]['auto']
        except KeyError:
            x_auto = None
        try:
            x_value = self.extension_attributes[extension][attribute][value]['value']
        except KeyError:
            x_value = None
        if value == x_value:
            if auto_value == x_auto:
                return
        if not value in self.extension_attributes[extension][attribute]:
            self.extension_attributes[extension][attribute][value] = {}
        self.extension_attributes[extension][attribute][value]['value'] = value
        self.extension_attributes[extension][attribute][value]['auto'] = auto_value
        return self._cache(callback=callback)

    def _del_extension_attribute(self, extension, attribute,
        value=None, callback=default_callback):
        """ Delete extension attribute. """
        if value is None:
            try:
                self.extension_attributes[extension].pop(attribute)
            except KeyError:
                pass
            return self._cache(callback=callback)
        try:
            self.extension_attributes[extension][attribute].pop(value)
        except:
            return
        return self._cache(callback=callback)

    def get_extension_attribute(self, extension, attribute,
        auto_value=None, callback=default_callback):
        """ Get extension attribute values. """
        # NOTE: We have to handle JSONs inablity to have str dict keys!
        attr_values = []
        try:
            attr_data = dict(self.extension_attributes[extension][attribute])
        except:
            attr_data = {}
        for x in attr_data:
            if auto_value is not None:
                x_auto = attr_data[x]['auto']
                if x_auto != auto_value:
                    continue
            x_val = attr_data[x]['value']
            attr_values.append(x_val)
        return attr_values

    def get_extension_attributes(self, extension,
        auto_value=None, callback=default_callback):
        """ Get extension attributes. """
        try:
            x_attrs = self.extension_attributes[extension]
        except:
            x_attrs = {}
        if auto_value is None:
            return list(x_attrs)
        attr_list = []
        for x_attr in x_attrs:
            x_values = x_attrs[x_attr]
            for x_val in x_values:
                x_auto = x_attrs[x_attr][x_val]['auto']
                if x_auto != auto_value:
                    continue
                attr_list.append(x_attr)
        return attr_list

    @object_lock()
    def add_sync_user(self, user_name, force=False, run_policies=True,
        verify_acls=True, _caller="API", verbose_level=0,
        callback=default_callback, **kwargs):
        """ Adds user to object. """
        if self.sync_users is None:
            msg = (_("Object does not support users."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("add:user"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        user = backend.get_object(object_type="user",
                                    realm=config.realm,
                                    name=user_name)
        if not user:
            msg = (_("Unknown user: %s") % user_name)
            return callback.error(msg)

        if user.uuid in self.sync_users:
            msg = "User already added to object."
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                force=force,
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_sync_user",
                                force=force,
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        msg = "Adding user %s to %s %s." % (user.oid, self.type, self.name)
        callback.send(msg)

        # Add user to this object.
        self.sync_users.append(user.uuid)
        # Update index.
        self.add_index('sync_user', user.uuid)

        return self._cache(callback=callback)

    @object_lock()
    def remove_sync_user(self, user_name, force=False, verify_acls=True,
        run_policies=True, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Removes user from objects members list. """
        if self.sync_users is None:
            msg = (_("Object does not support users."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("remove:user"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        # FIXME: we also need to allow to remove UUIDs of user that do not exists anymore!!!!!       
        # Allow removal of orphan user UUIDs.
        if stuff.is_uuid(user_name):
            user = backend.get_object(object_type="user", uuid=user_ame)
        else:
            user = backend.get_object(object_type="user",
                                    realm=config.realm,
                                    name=user_name)
        if not user:
            msg = (_("Unknown user: %s") % user_name)
            return callback.error(msg)

        if user.uuid not in self.sync_users:
            msg = (_("User is not assigned to %s '%s'.")
                    % (self.type, self.name))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_sync_user",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove user from object.
        self.sync_users.remove(user.uuid)
        # Update index.
        self.del_index('sync_user', user.uuid)

        return self._cache(callback=callback)

    @object_lock()
    @cli.check_rapi_opts()
    def add_role(self, role_name, verify_acls=True, run_policies=True,
        verbose_level=0, _caller="API", callback=default_callback, **kwargs):
        """ Adds a role to objects member roles list. """
        if self.roles is None:
            msg = (_("Object does not support roles."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("add:role"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        if "/" in role_name:
            search_attribute = "name"
            search_site = role_name.split("/")[0]
            role_name = role_name.split("/")[1]
        else:
            search_attribute = "name"
            search_site = self.site

        result = backend.search(object_type="role",
                                attribute=search_attribute,
                                value=role_name,
                                return_type="instance",
                                realm=self.realm,
                                site=search_site)
        if not result:
            msg = (_("Unknown role: %s/%s") % (search_site, role_name))
            return callback.error(msg)

        role = result[0]

        if role.uuid in self.roles:
            msg = (_("Role is already a member of %s '%s'.")
                    % (self.type, self.name))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_role",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        if self.type == "role":
            from otpme.lib.classes.role import get_roles
            # FIXME: Maybe we should check role ACLs here? e.g. check if role
            #        has any view:secret, generate:otp or any other "dangerous" ACL
            #        that allows other users to gain permissions for this role!?
            msg = (_("WARNING: Please make sure role ACLs do not allow any "
                    "privilege escalation when adding a role to a role!"))
            # Detect role loops.
            child_roles = get_roles(role_uuid=self.uuid,
                                    recursive=True,
                                    return_type="uuid")
            # FIXME: Check if loop detection works fine!!!!        
            #       This must include check with roles from other sites!!!!!                   
            #parent_roles = get_roles(role_uuid=self.uuid,
            #                        recursive=True,
            #                        parent=True,
            #                        return_type="uuid")
            msg = "Loop detected."
            #if role.uuid in parent_roles:
            #    return callback.error(msg)
            if role.uuid in child_roles:
                return callback.error(msg)
            # Trigger ACL cache clearing.
            cache.clear_acl_cache()

        # Add role to object.
        self.roles.append(role.uuid)
        # Update index.
        self.add_index('role', role.uuid)

        # Clear cache.
        assigned_role_cache.invalidate()

        return self._cache(callback=callback)

    @object_lock()
    def remove_role(self, role_name, verify_acls=True, run_policies=True,
        verbose_level=0, _caller="API", callback=default_callback, **kwargs):
        """ Removes a role from objects member roles list. """
        if self.roles is None:
            msg = (_("Object does not support roles."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("remove:role"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        # Allow removal of orphan role UUIDs.
        if stuff.is_uuid(role_name):
            role_uuid = role_name
        else:
            if "/" in role_name:
                search_attribute = "name"
                search_site = role_name.split("/")[0]
                role_name = role_name.split("/")[1]
            else:
                search_attribute = "name"
                search_site = self.site

            result = backend.search(object_type="role",
                                    attribute=search_attribute,
                                    value=role_name,
                                    return_type="instance",
                                    realm=self.realm,
                                    site=search_site)
            if not result:
                msg = (_("Unknown role: %s/%s") % (search_site, role_name))
                return callback.error(msg)

            role = result[0]
            role_uuid = role.uuid

        if not role_uuid in self.roles:
            msg = (_("Role is not a member of %s '%s'.")
                    % (self.type, self.name))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_role",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove role from object.
        self.roles.remove(role_uuid)
        # Update index.
        self.del_index('role', role_uuid)

        # Clear cache.
        assigned_role_cache.invalidate()

        return self._cache(callback=callback)

    @object_lock()
    def add_token(self, token_path, token_options=None, login_interfaces=[],
        force=False, run_policies=True, verify_acls=True, auto_sign=None,
        sign=False, tags=None, _caller="API", verbose_level=0,
        callback=default_callback, **kwargs):
        """ Adds a token to objects member tokens list. """
        if self.tokens is None:
            msg = (_("Object does not support tokens."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("add:token"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        if not "/" in token_path:
            msg = ("Invalid token path: %s" % token_path)
            return callback.error(msg)

        found_pos = False
        found_neg = False
        for x in login_interfaces:
            if x.startswith("-"):
                i = x[1:]
                found_neg = True
            else:
                i = x
                found_pos = True
            if i not in config.valid_token_login_interfaces:
                msg = (_("Unknown login interface: %s") % x)
                return callback.error(msg)
        if found_pos and found_neg:
            msg = (_("You cannot mix positive/negative interface "
                    "options."))
            return callback.error(msg)

        # Get token.
        token_user = token_path.split("/")[0]
        token_name = token_path.split("/")[1]
        token = backend.get_object(object_type="token",
                                    realm=config.realm,
                                    user=token_user,
                                    name=token_name)
        if not token:
            msg = (_("Unknown token: %s") % token_path)
            return callback.error(msg)

        token_user = backend.get_object(object_type="user",
                                    uuid=token.owner_uuid)
        if not token_user:
            msg = (_("Orphan token: Unknown user: %s") % token.owner_uuid)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                force=force,
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_token",
                                force=force,
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Get current token options.
        try:
            current_opts = self.token_options[token.uuid]
        except:
            current_opts = None

        # Get current token login interfaces.
        try:
            current_login_interfaces = self.token_login_interfaces[token.uuid]
        except:
            current_login_interfaces = None

        if token.uuid in self.tokens:
            token_modify = False
            exception = AlreadyExists
            msg = (_("Token is already assigned to %s '%s'.")
                    % (self.type, self.name))
            if current_opts != token_options:
                if token_options:
                    token_modify = True
                    callback.error(msg)
                    msg = (_("Would you like to modify current token options? "))

            if current_login_interfaces != login_interfaces:
                if login_interfaces:
                    token_modify = True
                    callback.error(msg)
                    msg = (_("Would you like to modify current token "
                            "login interfaces? "))

            if not token_modify:
                return callback.error(msg, exception=exception)

            if not force:
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

            # FIXME: Maybe we should implement removal of signatues as a
            #        separate method later. Currently calling remove_token()
            #        works fine.
            self.remove_token(token_path,
                            callback=callback,
                            _caller=_caller,
                            force=force)

        msg = "Adding token %s to %s %s." % (token.rel_path, self.type, self.name)
        callback.send(msg)

        if self.type == "role":
            # Trigger ACL cache clearing.
            cache.clear_acl_cache(token_uuid=token.uuid)

        # Handle auto sign stuff.
        if auto_sign is None:
            # Check user auto-sign feature.
            if config.auth_user:
                if config.auth_user.autosign_enabled:
                    auto_sign = True
            # Check for auto sign config parameter.
            if self.auto_sign:
                auto_sign = True

        if auto_sign:
            sign = True

        # Disable signing if object is not signable.
        if not self.signable:
            sign = False

        # Add signature to token.
        if sign:
            if not config.auth_token:
                msg = (_("Cannot sign without login token."))
                return callback.error(msg)

            add_tags = []
            if tags:
                add_tags = tags

            if login_interfaces:
                login_interfaces_tag = ":".join(login_interfaces)
                login_interfaces_tag = ("login_interfaces:%s"
                                        % login_interfaces_tag)
                add_tags.append(login_interfaces_tag)

            # Add login user tag from token.
            user_tag = "user:%s" % token_user.uuid
            add_tags.append(user_tag)

            # Add token options tag.
            if token_options:
                opts_tag = "options:%s" % token_options
                add_tags.append(opts_tag)

            # Add object tags.
            if self.type == "group":
                group_tag = "group:%s" % self.uuid
                add_tags.append(group_tag)

            if self.type == "accessgroup":
                ag_tag = "accessgroup:%s" % self.uuid
                add_tags.append(ag_tag)

            if self.type == "client":
                client_tag = "client:%s" % self.uuid
                add_tags.append(client_tag)

            if self.type == "host":
                host_tag = "host:%s" % self.uuid
                add_tags.append(host_tag)

            if self.type == "node":
                node_tag = "node:%s" % self.uuid
                add_tags.append(node_tag)

            if self.type == "role":
                valid_roles = self.get_roles(return_type="instance",
                                            recursive=True,
                                            parent=True)
                valid_roles.append(self)
                for role in valid_roles:
                    role_tag = "role:%s" % role.uuid
                    if role_tag not in add_tags:
                        add_tags.append(role_tag)
                    role_ags = role.get_access_groups(return_type="instance")
                    for accessgroup in role_ags:
                        ag_tag = "accessgroup:%s" % accessgroup.uuid
                        if ag_tag not in add_tags:
                            add_tags.append(ag_tag)
                    role_groups = role.get_groups(return_type="instance")
                    for group in role_groups:
                        group_tag = "group:%s" % group.uuid
                        if group_tag not in add_tags:
                            add_tags.append(group_tag)

            # Check if a valid signature already exists.
            valid_sign = None
            valid_sign_exists = False
            auth_user_uuid = config.auth_token.owner_uuid
            token_signatures = token.search_sign(user_uuid=auth_user_uuid,
                                                tags=add_tags,
                                                callback=callback,
                                                _caller=_caller)
            try:
                user_signs = token_signatures[auth_user_uuid]
            except:
                user_signs = {}
            for sign_id in user_signs:
                # Get signature object.
                signature = token_signatures[auth_user_uuid][sign_id]
                callback.disable()
                try:
                    valid_sign_exists = token.verify_sign(signature=signature,
                                                            sign_id=sign_id,
                                                            callback=callback)
                except:
                    pass
                callback.enable()
                if valid_sign_exists:
                    valid_sign = user_signs[sign_id]
                    break

            # Use existing signature if present.
            if valid_sign_exists:
                sign_info = valid_sign.get_sign_info()
                sign_info = pprint.pformat(sign_info)
                msg = (_("Using existing signature: %s") % sign_info)
                callback.send(msg)
            else:
                # Add new signature.
                try:
                    sign_status = token.sign(tags=add_tags,
                                            sign_ref=self.uuid,
                                            callback=callback)
                    if sign_status is False:
                        msg = (_("Signing error."))
                        raise OTPmeException(msg)
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Error signing token: %s") % e)
                    return callback.error(msg)
                if sign_status is None:
                    return callback.abort()

        # Add token to this object.
        if not token.uuid in self.tokens:
            self.tokens.append(token.uuid)
            # Update index.
            self.add_index('token', token.uuid)
        if token_options:
            self.token_options[token.uuid] = token_options
        if login_interfaces:
            self.token_login_interfaces[token.uuid] = login_interfaces

        # Clear cache.
        assigned_token_cache.invalidate()

        return self._cache(callback=callback)

    @object_lock()
    def remove_token(self, token_path, keep_sign=False, force=False,
        verify_acls=True, run_policies=True, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Removes a token from objects member tokens list. """
        if self.tokens is None:
            msg = (_("Object does not support tokens."))
            raise OTPmeException(msg)

        if verify_acls:
            if not self.verify_acl("remove:token"):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)

        # FIXME: we also need to allow to remove UUIDs of tokens that do not exists anymore!!!!!       
        #               how to remove signatures of this tokens??????    
        # Allow removal of orphan token UUIDs.
        if stuff.is_uuid(token_path):
            token = backend.get_object(object_type="token", uuid=token_path)
        else:
            if not "/" in token_path:
                msg = ("Invalid token path: %s" % token_path)
                return callback.error(msg)
            # Get token.
            token_user = token_path.split("/")[0]
            token_name = token_path.split("/")[1]
            token = backend.get_object(object_type="token",
                                        realm=config.realm,
                                        user=token_user,
                                        name=token_name)
        if not token:
            msg = (_("Unknown token: %s") % token_path)
            return callback.error(msg)

        if not token.uuid in self.tokens:
            msg = (_("Token is not assigned to %s '%s'.")
                    % (self.type, self.name))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_token",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove signature from token.
        if not keep_sign:
            # Search token signatures that where signed for this object.
            token_signatures = token.search_sign(sign_object=self.uuid,
                                                callback=callback,
                                                _caller=_caller)
            for user_uuid in token_signatures:
                user_oid = backend.get_oid(object_type="user", uuid=user_uuid)
                for sign_id in token_signatures[user_uuid]:
                    signature = token_signatures[user_uuid][sign_id]

                    sign_info = signature.get_sign_info()
                    sign_info = pprint.pformat(sign_info)
                    msg = (_("Remove signature?\n%s:\n%s\n[y/n] ")
                            % (user_oid, sign_info))
                    if not force:
                        answer = callback.ask(msg)
                        if answer.lower() != "y":
                            continue
                    token.del_sign(user_uuid=user_uuid,
                                    tags=signature.tags,
                                    sign_id=sign_id,
                                    run_policies=run_policies,
                                    _caller=_caller,
                                    callback=callback)

        # Remove token from object.
        self.tokens.remove(token.uuid)
        try:
            self.token_options.pop(token.uuid)
        except KeyError:
            pass
        try:
            self.token_login_interfaces.pop(token.uuid)
        except KeyError:
            pass
        # Update index.
        self.del_index('token', token.uuid)

        # Clear cache.
        assigned_token_cache.invalidate()

        return self._cache(callback=callback)


    @check_acls(acls=['add:policy'])
    @object_lock()
    def add_policy(self, policy_name, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Add OTPme policy to object. """
        if self.type == "site":
            object_site = self.name
        else:
            object_site = self.site

        result = backend.search(object_type="policy",
                                attribute="name",
                                value=policy_name,
                                realm=self.realm,
                                site=object_site,
                                return_type="instance")
        if not result:
            msg = (_("Unknown policy: %s" % policy_name))
            return callback.error(msg)

        policy = result[0]

        if not self.type in policy.object_types:
            msg = (_("Policy not valid for object type: %s" % self.type))
            return callback.error(msg)

        if not policy.allow_multiple:
            policies = self.get_policies(policy_type=policy.policy_type)
            if len(policies) > 0:
                msg = (_("Policy of this type already exists."))
                return callback.error(msg)

        # Get policy options.
        policy_options = policy.activate()

        try:
            current_options = self.policy_options[policy.uuid]
        except:
            current_options = None

        if policy_options == current_options:
            if policy.uuid in self.policies:
                msg = (_("Policy already enabled for this object."))
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_policy",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Add policy to object.
        self.policies.append(policy.uuid)
        if policy_options:
            self.policy_options[policy.uuid] = policy_options
        # Update index.
        self.add_index('policy', policy.uuid)

        return self._cache(callback=callback)

    def update_policy(self, policy_name, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Update OTPme policy of object. """
        # Get policy.
        result = backend.search(object_type="policy",
                                attribute="name",
                                value=policy_name,
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        if not result:
            msg = (_("Unknown policy: %s" % policy_name))
            return callback.error(msg)

        policy = result[0]

        if not policy.uuid in self.policies:
            msg = (_("Policy not enabled for this object: %s" % self.oid))
            return callback.error(msg)

        # Get policy options.
        policy_options = policy.activate()

        # Update policy options of object.
        self.policy_options[policy.uuid] = policy_options

        return self._cache(callback=callback)

    @check_acls(acls=['remove:policy'])
    @object_lock()
    def remove_policy(self, policy_name, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Remove OTPme policy from object. """
        result = backend.search(object_type="policy",
                                attribute="name",
                                value=policy_name,
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        if not result:
            msg = ("Unknown policy: %s" % policy_name)
            return callback.error(msg)

        policy = result[0]

        if not policy.uuid in self.policies:
            msg = ("Policy not enabled for this object.")
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("remove_policy",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Remove policy from object.
        self.policies.remove(policy.uuid)
        if policy.uuid in self.policy_options:
            self.policy_options.pop(policy.uuid)
        # Update index.
        self.del_index('policy', policy.uuid)

        return self._cache(callback=callback)

    def get_policies(self, policy_type=None, policy_types=None, hook=None,
        child_object=None, return_type="uuid", ignore_hooks=False,
        _caller="API", callback=default_callback, **kwargs):
        """ Get policies enabled for this object. """
        if not backend.is_available():
            raise BackendUnavailable("Backend not available.")

        if policy_types is None:
            policy_types = []
        if policy_type is not None:
            if policy_type not in policy_types:
                policy_types.append(policy_type)

        search_result = []
        if self.policies:
            search_attributes = None
            if policy_types:
                search_attributes = {
                                    'policy_type' : {
                                            'values'    : policy_types,
                                            },
                                    }
            return_attributes = ['uuid']
            if return_type not in return_attributes:
                return_attributes.append(return_type)
            _return_type = "instance"
            if ignore_hooks:
                _return_type = "name"
            # Search policies assigned to this object.
            search_result = backend.search(object_type="policy",
                                            attribute="uuid",
                                            value="*",
                                            attributes=search_attributes,
                                            join_object_type=self.type,
                                            join_search_attr="uuid",
                                            join_search_val=self.uuid,
                                            join_attribute="policy",
                                            return_type=_return_type)
        result = []
        if ignore_hooks:
            result = search_result
        else:
            for policy in search_result:
                add_policy = False
                check_all = True
                check_type = True
                if not "all" in policy.hooks:
                    check_all = False
                    if not self.type in policy.hooks:
                        if not child_object:
                            continue
                        if not child_object.type in policy.hooks:
                            continue
                if not self.type in policy.hooks:
                    if child_object:
                        if not child_object.type in policy.hooks:
                            check_type = False
                    else:
                        check_type = False
                try:
                    object_hooks = policy.hooks[self.type]
                except:
                    object_hooks = []
                try:
                    child_hooks = policy.hooks[child_object.type]
                except:
                    child_hooks = []
                if hook and check_all and hook in policy.hooks["all"]:
                    add_policy = True
                elif hook and check_type and hook in object_hooks:
                    add_policy = True
                elif hook and check_type and child_object and hook in child_hooks:
                    add_policy = True
                elif not hook:
                    add_policy = True

                if not add_policy:
                    continue

                if return_type == "uuid":
                    if policy.uuid not in result:
                        result.append(policy.uuid)
                elif return_type == "full_oid":
                    if policy.oid.full_oid not in result:
                        result.append(policy.oid.full_oid)
                elif return_type == "name":
                    if policy.name not in result:
                        result.append(policy.name)
                elif return_type == "instance" and _caller == "API":
                    if policy not in result:
                        result.append(policy)
                else:
                    msg = (_("Unknown return type: %s") % return_type)
                    return callback.stop(msg)

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    def run_policies(self, hook_name=None, token=None, child_object=None,
        policy_type=None, ignore_policy_types=[], force=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Run policies for the given hook. """
        # We need to get arguments via local() before assigning any other vars.
        args = locals()
        success_policy_types = []
        from otpme.lib.policy import processed_objects

        # Handle one_time_policy_run decorator stuff.
        proc_id = multiprocessing.get_id()
        if proc_id in processed_objects:
            arguments = {'args':(), 'kwargs':args}
            kwargs_key = stuff.args_to_hash(arguments,
                                ignore_args=['callback'],
                                ignore_classes=['OTPmeOid', 'OTPmeBaseObject'])
            if kwargs_key in processed_objects[proc_id]:
                return
            processed_objects[proc_id].append(kwargs_key)

        policies = self.get_policies(hook=hook_name,
                                    policy_type=policy_type,
                                    child_object=child_object,
                                    return_type="instance")
        # Without policy we are done.
        if not policies:
            return success_policy_types

        for x in policies:
            if not x.enabled:
                continue
            if x.policy_type in ignore_policy_types:
                continue
            try:
                policy_options = stuff.copy_object(self.policy_options[x.uuid])
            except:
                policy_options = {}
            for a in kwargs:
                v = kwargs[a]
                policy_options[a] = v

            try:
                x.handle_hook(hook_object=self,
                            hook_name=hook_name,
                            child_object=child_object,
                            force=force,
                            token=token,
                            callback=callback,
                            _caller=_caller,
                            **policy_options)
            except PolicyException as e:
                msg = (_("Policy exception: %s: %s") % (x.name, e))
                callback.error(msg, raise_exception=False)
                # We pass on the PolicyException() to be handled by our caller.
                # This way the calling method can decide what to do e.g. return
                # via callback.error() without raising an exception.
                raise
            except Exception as e:
                config.raise_exception()
                msg = (_("Internal server error running policy: %s") % x.name)
                logger.critical(msg)
                # For real exceptions we should raise the exception now via our
                # callback. This will ensure that the exception is raised each
                # time callback.error() is called. This way we should get a
                # useful stacktrace.
                callback.exception(e)

            if not x.policy_type in success_policy_types:
                success_policy_types.append(x.policy_type)

        return success_policy_types

    @cli.check_rapi_opts()
    def get_sync_users(self, return_type="name", skip_disabled=False,
        include_roles=False, callback=default_callback,
        _caller="API", **kwargs):
        """ Get all users assigned to this object. """
        exception = None
        if not return_type in [ 'instance', 'uuid', 'oid', 'name', 'read_oid', 'full_oid']:
            exception = "Unknown return type: %s" % return_type
        if _caller != "API" and return_type == "instance":
            exception = "Unknown return type: %s" % return_type
        if exception:
            if _caller != "API":
                return callback.error(exception)
            else:
                raise Exception(exception)

        result = []
        # Users assinged to roles assigned to this object.
        if include_roles and self.roles:
            from otpme.lib.classes.role import get_roles
            # Get roles recursive.
            roles_result = []
            for role_uuid in self.roles:
                # Add child roles.
                roles_result += get_roles(role_uuid,
                                        recursive=True,
                                        return_type="instance")
                # Add roles assigned to this object.
                role = backend.get_object(uuid=role_uuid)
                # Ignore orphan roles
                if not role:
                    continue
                if role in roles_result:
                    continue
                roles_result.append(role)
            # Get all role tokens.
            for role in roles_result:
                x_result = role.get_sync_users(skip_disabled=skip_disabled,
                                                include_roles=False,
                                                return_type=return_type)
                result += x_result

        if self.sync_users:
            # Remove duplicates.
            user_uuids = sorted(list(set(self.sync_users)))
            # Search users (return attribute) via user UUID.
            search_attrs = {}
            if skip_disabled:
                search_attrs['enabled'] = {}
                search_attrs['enabled']['value'] = True
            result += backend.search(object_type="user",
                                    attribute="uuid",
                                    values=user_uuids,
                                    attributes=search_attrs,
                                    return_type=return_type)
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_token_users(self, return_type="name", skip_disabled=False,
        include_roles=False, callback=default_callback,
        _caller="API", **kwargs):
        """ Get all users that have a token assigned to this object. """
        exception = None
        if not return_type in [ 'instance', 'uuid', 'oid', 'name', 'read_oid', 'full_oid']:
            exception = "Unknown return type: %s" % return_type
        if _caller != "API" and return_type == "instance":
            exception = "Unknown return type: %s" % return_type
        if exception:
            if _caller != "API":
                return callback.error(exception)
            else:
                raise Exception(exception)
        # Get all assigned tokens.
        token_uuids = self.get_tokens(return_type="uuid",
                                    include_roles=include_roles)
        user_uuids = []
        if token_uuids:
            # Get users UUIDs from tokens.
            search_attrs = {}
            return_attrs = ['owner_uuid']
            if skip_disabled:
                search_attrs['enabled'] = {}
                search_attrs['enabled']['value'] = True
            user_uuids = backend.search(object_type="token",
                                            attribute="uuid",
                                            values=token_uuids,
                                            attributes=search_attrs,
                                            return_attributes=return_attrs)
        result = []
        if user_uuids:
            # Remove duplicates.
            user_uuids = sorted(list(set(user_uuids)))
            # Search users (return attribute) via user UUID.
            search_attrs = {}
            if skip_disabled:
                search_attrs['enabled'] = {}
                search_attrs['enabled']['value'] = True
            result = backend.search(object_type="user",
                                    attribute="uuid",
                                    values=user_uuids,
                                    attributes=search_attrs,
                                    return_type=return_type)
            result.sort()
        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_tokens(self, return_type="rel_path", token_types=None,
        skip_disabled=True, include_roles=False, user_uuid=None,
        include_options=False, include_login_interfaces=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Get all tokens tokens assigned to this object. """
        exception = None
        if not return_type in [ 'instance', 'uuid', 'oid', 'rel_path', 'read_oid', 'full_oid' ]:
            exception = "Unknown return type: %s" % return_type
        if _caller != "API" and return_type == "instance":
            exception = "Unknown return type: %s" % return_type
        if exception:
            return callback.error(exception)
        result = []
        if include_options or include_login_interfaces:
            result = {}
        # Tokens assigned to this object.
        if self.tokens:
            # Search attributes.
            search_attr = {}
            if user_uuid:
                search_attr['user'] =  {'value':user_uuid}
            if token_types:
                search_attr['token_type'] =  {'values':token_types}
            if skip_disabled:
                search_attr['enabled'] = {}
                search_attr['enabled']['value'] = True
            _return_type = return_type
            if include_options or include_login_interfaces:
                _return_type = "uuid"
            x_result = backend.search(attribute="uuid",
                                    values=self.tokens,
                                    attributes=search_attr,
                                    object_type="token",
                                    return_type=_return_type)
            if include_options or include_login_interfaces:
                for token_uuid in x_result:
                    result[token_uuid] = {}
                    if include_options:
                        try:
                            token_options = self.token_options[token_uuid]
                        except:
                            token_options = {}
                        result[token_uuid]['token_options'] = token_options
                    if include_login_interfaces:
                        try:
                            login_interfaces = self.token_login_interfaces[token_uuid]
                        except:
                            login_interfaces = {}
                        result[token_uuid]['login_interfaces'] = login_interfaces
            else:
                result += x_result
        # Tokens assinged to roles assigned to this object.
        if include_roles and self.roles:
            from otpme.lib.classes.role import get_roles
            # Get roles recursive.
            roles_result = []
            for role_uuid in self.roles:
                # Add child roles.
                roles_result += get_roles(role_uuid,
                                        recursive=True,
                                        return_type="instance")
                # Add roles assigned to this object.
                role = backend.get_object(uuid=role_uuid)
                # Ignore orphan roles
                if not role:
                    continue
                if role in roles_result:
                    continue
                roles_result.append(role)
            # Get all role tokens.
            for role in roles_result:
                x_result = role.get_tokens(token_types=token_types,
                                        user_uuid=user_uuid,
                                        skip_disabled=skip_disabled,
                                        include_roles=False,
                                        include_options=include_options,
                                        include_login_interfaces=include_login_interfaces,
                                        return_type=return_type)
                if include_options or include_login_interfaces:
                    for token_uuid in x_result:
                        result[token_uuid] = x_result[token_uuid]
                else:
                    result += x_result

        # Remove duplicates.
        if isinstance(result, list):
            result = sorted(list(set(result)))

        if include_options or include_login_interfaces:
            return result

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)

        return callback.ok(result)

    @cli.check_rapi_opts()
    def get_roles(self, return_type="read_oid", _caller="API",
        skip_disabled=True, callback=default_callback, **kwargs):
        """ Return list with all roles assigned to this object. """
        result = []
        if self.roles:
            search_attr = {}
            if skip_disabled:
                search_attr['enabled'] = {}
                search_attr['enabled']['value'] = True
            return_attributes = ['site', return_type]
            search_result = backend.search(object_type="role",
                                        attribute="uuid",
                                        values=self.roles,
                                        attributes=search_attr,
                                        return_attributes=return_attributes)
            for uuid in search_result:
                try:
                    x_result = search_result[uuid][return_type]
                except:
                    continue
                if return_type == "name":
                    x_site = search_result[uuid]['site']
                    if x_site != config.site:
                        x_result = "%s/%s" % (x_site, x_result)
                result.append(x_result)

            result.sort()

        if _caller == "RAPI":
            result = ",".join(result)
        if _caller == "CLIENT":
            result = "\n".join(result)
        return callback.ok(result)

    @assigned_token_cache.cache_method()
    def is_assigned_token(self, token_uuid, processed_roles=[]):
        if token_uuid in self.tokens:
            return True
        for role_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=role_uuid)
            if not role:
                continue
            if not role.enabled:
                continue
            if role.uuid in processed_roles:
                continue
            processed_roles.append(role.uuid)
            if role.is_assigned_token(token_uuid, processed_roles=processed_roles):
                return True
        return False

    @assigned_role_cache.cache_method()
    def is_assigned_role(self, role_uuid):
        if role_uuid in self.roles:
            return True
        for x_uuid in self.roles:
            role = backend.get_object(object_type="role", uuid=x_uuid)
            if not role:
                continue
            if not role.enabled:
                continue
            if role.is_assigned_role(role_uuid):
                return True
        return False

    def get_attribute(self, attribute, verbose_level=0,
        verify_acls=False, callback=default_callback, **kwargs):
        """ Get object attribute. """
        # Handle base attributes.
        base_attributes = {
                        "uuid"              : self.uuid,
                        "path"              : self.path,
                        "oid"               : self.oid.full_oid,
                        "rel_path"          : self.rel_path,
                        "read_oid"          : self.oid.read_oid,
                        "full_oid"          : self.oid.full_oid,
                        "checksum"          : self.checksum,
                        "sync_checksum"     : self.sync_checksum,
                        }

        if attribute in base_attributes:
            value = base_attributes[attribute]
            if value:
                val_list = [value]
            else:
                val_list = []
            return val_list
        # Handle LDIF attributes.
        if verify_acls:
            if not self.verify_acl("view:attribute:" + attribute):
                msg = ("Permission denied: %s" % self)
                return callback.error(msg, exception=PermissionDenied)
        try:
            val_list = list(self.ldif[attribute])
        except:
            val_list = []
        return val_list

    @check_acls(acls=['add:attribute'])
    @object_lock()
    def add_attribute(self, attribute, value=None, run_policies=True,
        ignore_ro=False, verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Add attribute to object. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_attribute",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Search extension to add attribute.
        extension = None
        for x in self._extensions:
            e = self._extensions[x]
            if self.type not in e.object_types:
                continue
            ext_attrs = config.get_ldif_attributes(e.name, self.type)
            if attribute not in ext_attrs:
                continue
            if verbose_level > 0:
                msg = (_("Using extension '%(ext)s' to add attribute "
                        "'%(attribute)s' to object.")
                        % {"ext":e.name, "attribute":attribute})
                callback.send(msg)
            extension = e

        if not extension:
            msg = ("Unable to find extension to add attribute to object: %s"
                    % attribute)
            # FIXME: log user messages?
            #logger.critical(msg)
            return callback.error(msg)

        # Try to add attribute.
        try:
            extension.add_attribute(self, attribute, value,
                                ignore_ro=ignore_ro,
                                verbose_level=verbose_level)
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to add attribute: %s: %s") % (attribute, e))
            return callback.error(msg)

        # Update extensions.
        self.update_extensions("add_attribute",
                            attribute=attribute,
                            value=value,
                            verbose_level=verbose_level,
                            callback=callback)

        return self._cache(callback=callback)

    @check_acls(acls=['edit:attribute'])
    @object_lock()
    def modify_attribute(self, attribute, old_value, new_value,
        run_policies=True, ignore_ro=False, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Add attribute to object. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("modify_attribute",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Search extension to add attribute.
        extension = None
        for x in self._extensions:
            e = self._extensions[x]
            if self.type not in e.object_types:
                continue
            ext_attrs = config.get_ldif_attributes(e.name, self.type)
            if attribute not in ext_attrs:
                continue
            if verbose_level > 0:
                msg = (_("Using extension '%(ext)s' to modify attribute "
                        "'%(attribute)s' of object.")
                        % {"ext":e.name, "attribute":attribute})
                callback.send(msg)
            extension = e

        if not extension:
            msg = ("Unable to find extension to modify attribute of object: %s"
                    % attribute)
            # FIXME: log user messages?
            #logger.critical(msg)
            return callback.error(msg)

        # Try to add attribute.
        try:
            extension.modify_attribute(self, attribute, old_value,
                                        new_value, ignore_ro=ignore_ro,
                                        verbose_level=verbose_level)
        except Exception as e:
            config.raise_exception()
            msg = (_("Unable to add attribute: %s: %s") % (attribute, e))
            return callback.error(msg)

        # Update extensions.
        self.update_extensions("modify_attribute",
                            attribute=attribute,
                            old_value=old_value,
                            new_value=new_value,
                            verbose_level=verbose_level,
                            callback=callback)

        return self._cache(callback=callback)

    @check_acls(acls=['delete:attribute'])
    @object_lock()
    def del_attribute(self, attribute, value=None, run_policies=True,
        ignore_ro=False, ignore_missing=False,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Delete attribute from object. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_attribute",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        extension = None
        for x in self._extensions:
            e = self._extensions[x]
            if self.type in e.object_types:
                ext_attrs = config.get_ldif_attributes(e.name, self.type)
                if attribute not in ext_attrs:
                    continue
                if verbose_level > 0:
                    msg = (_("Using extension '%(ext)s' to delete attribute "
                            "'%(attr)s' from object.")
                            % {"ext":e.name, "attr":attribute})
                    callback.send(msg)
                extension = e
                break

        if not extension:
            msg = "Unable to find extension to delete attribute from object."
            # FIXME: log user messages?
            #logger.critical(msg)
            return callback.error(msg)

        try:
            extension.del_attribute(self, attribute, value,
                                    ignore_ro=ignore_ro,
                                    ignore_missing=ignore_missing,
                                    verbose_level=verbose_level)
        except MandatoryAttribute as e:
            msg = (_("Unable to delete mandatory attribute: %s") % e)
            return callback.error(msg, exception=MandatoryAttribute)
        except Exception as e:
            msg = (_("Unable to delete attribute: %s: %s" % (attribute, e)))
            return callback.error(msg)

        return self._cache(callback=callback)

    #def show_attributes(self, callback=default_callback, **kwargs):
    #    """ Show all attributes of object """
    #    # xxxxxxxxxxxxx
    #    # FIXME: how to handle ACLs here?
    #    attributes = []
    #    for x in self._extensions:
    #        e = self._extensions[x]
    #        attributes += e.get_attributes(self)
    #    return callback.ok("\n".join(attributes))

    def list_valid_object_classes(self, callback=default_callback, **kwargs):
        """ List all valid object classes of object """
        valid_object_classes = []
        for x in self._extensions:
            e = self._extensions[x]
            valid_object_classes += e.get_valid_object_classes(self)
        valid_object_classes.sort()
        return callback.ok("\n".join(valid_object_classes))

    def list_valid_attributes(self, callback=default_callback, **kwargs):
        """ List all valid attributes of object """
        valid_attributes = []
        for x in self._extensions:
            e = self._extensions[x]
            valid_attributes += e.get_valid_attributes(self.type)
        valid_attributes.sort()
        return callback.ok("\n".join(valid_attributes))

    @check_acls(acls=['add:object_class'])
    @object_lock()
    def add_object_class(self, object_class, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Add object_class to object """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_object_class",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        extension = None
        for e in self._extensions:
            extension = self._extensions[e]
            if self.type in extension.object_types:
                if object_class in extension.object_classes[self.type]:
                    if verbose_level > 0:
                        msg = (_("Using extension '%(ext)s' to add object class "
                                "'%(oc)s' to object.")
                                % {"ext":extension.name, "oc":object_class})
                        callback.send(msg)
                    break
            extension = None

        if not extension:
            msg = (_("Unable to find extension to add object class to object: %s")
                    % object_class)
            # FIXME: log user messages?
            #logger.critical(msg)
            return callback.error(msg)

        try:
            extension.add_object_class(self, object_class,
                                        verbose_level=verbose_level)
        except Exception as e:
            msg = (_("Error adding object class: %s" % e))
            return callback.error(msg)

        return self._cache(callback=callback)

    @check_acls(acls=['delete:object_class'])
    @object_lock()
    def del_object_class(self, object_class=False, force=False,
        run_policies=True, verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Delete object class from object """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_object_class",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # xxxxxxxxxxx
        # FIXME: how to handle ACLs here?
        if not object_class in self.object_classes:
            object_type = "%s%s" % (self.type[0].upper(), self.type[1:])
            msg = (_("%(object)s does not have object class '%s' assigned.")
                    % {"object":object_type,
                    "object_class":object_class})
            return callback.error(msg)
        if not force:
            if self.confirmation_policy == "force":
                force = True

        while True:
            for e in self._extensions:
                extension = self._extensions[e]
                extension.clear_object_class(self,
                                            object_class,
                                            force=force,
                                            callback=callback)
            if force:
                break

            if not force:
                answer = callback.ask("Delete object class?: ")
                if answer.lower() == "y":
                    force = True
                else:
                    return callback.abort()

        self.object_classes.remove(object_class)

        return self._cache(callback=callback)

    def add_ldif(self, ldif):
        """ Add LDIF to object. """
        for x in ldif:
            a = x[0]
            v = x[1]
            if v is None:
                msg = "Cannot add empty attribute: %s" % a
                raise Exception(msg)
            if not a in self.ldif:
                self.ldif[a] = []
            if not v in self.ldif[a]:
                self.ldif[a].append(v)
                # Update index.
                ldif_attr = "ldif:%s" % a
                self.add_index(ldif_attr, v)

        self.add_ldif_attributes(ldif)

        # Invalidate LDIF cache.
        ldif_cache.invalidate()
        ldap_search_cache.invalidate()

    def del_ldif(self, ldif):
        """ Del LDIF from object. """
        for x in ldif:
            a = x[0]
            v = x[1]
            try:
                attr_values = self.ldif[a]
            except:
                attr_values = []
            try:
                attr_values.remove(v)
            except:
                pass
            # Update index.
            ldif_attr = "ldif:%s" % a
            self.del_index(ldif_attr, v)
            if not attr_values:
                self.ldif.pop(a)

        self.del_ldif_attributes(ldif)

        ldif_cache.invalidate()
        ldap_search_cache.invalidate()

    def add_ldif_attributes(self, ldif):
        """ Add LDIF attributes to object. """
        for x in ldif:
            a = x[0]
            if a in self.ldif_attributes:
                continue
            self.ldif_attributes.append(a)
        ldif_cache.invalidate()
        ldap_search_cache.invalidate()

    def del_ldif_attributes(self, ldif):
        """ Add LDIF attributes to object. """
        for x in ldif:
            a = x[0]
            if a not in self.ldif_attributes:
                continue
            self.ldif_attributes.remove(a)
        ldif_cache.invalidate()
        ldap_search_cache.invalidate()

    @ldif_cache.cache_method()
    def get_ldif(self, _caller="API", verify_acls=True,
        callback=default_callback, **kwargs):
        """ Return objects LDIF. """
        text = False
        if _caller == "CLIENT":
            text = True
        verify_acl_func = None
        if verify_acls:
            verify_acl_func = self.verify_acl
        ldif = get_ldif(ldif=self.ldif, text=text,
                        verify_acl_func=verify_acl_func,
                        **kwargs)
        return callback.ok(ldif)

    def get_object_classes(self, _caller="API", callback=default_callback, **kwargs):
        """ Return objects LDIF object classes """
        if _caller == "CLIENT":
            ocs = "\n".join(self.object_classes)
        else:
            ocs = list(self.object_classes)
        return callback.ok(ocs)

    @check_acls(acls=['enable:object'])
    @check_special_user()
    @object_lock()
    def enable(self, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable the object. """
        if not force:
            if self._enabled:
                object_type = "%s%s" % (self.type[0].upper(), self.type[1:])
                msg = (_("%s already enabled.") % object_type)
                return callback.error(msg)
            if self.confirmation_policy == "paranoid":
                msg = (_("Enable %(object_type)s '%(object_name)s'?: ")
                        % { "object_type":self.type, "object_name":self.name})
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable",
                                callback=callback,
                                _caller=_caller,
                                force=force)
            except Exception as e:
                msg = str(e)
                self.logger.warning(msg)
                return callback.error()

        self._enabled = True
        # Update index.
        self.update_index('enabled', True)

        if self.auto_disable:
            self.auto_disable_start_time = time.time()
            msg = ("Auto-disable active for this object: %s"
                    % self.auto_disable_time)
            callback.send(msg)

        return self._cache(callback=callback)

    @check_acls(acls=['disable:object'])
    @object_lock()
    def disable(self, force=False, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Disable the object. """
        if not force:
            if config.auth_token:
                if config.auth_token.owner_uuid == self.uuid:
                    return callback.error("You cannot disable yourself. :)")
                if config.auth_token.uuid == self.uuid and not force:
                    return callback.error("Cannot disable token used at login.")
                if config.auth_token.destination_token:
                    dst_token = config.auth_token.get_destination_token()
                    if dst_token and dst_token.uuid == self.uuid and not force:
                        return callback.error("Cannot disable token used at login.")
            if self.name == config.admin_user_name:
                return callback.error("Cannot disable admin user.")

        if not force:
            if not self._enabled:
                object_type = "%s%s" % (self.type[0].upper(), self.type[1:])
                msg = (_("%(object_type)s '%(object_name)s' already disabled.")
                        % {"object_type":object_type, "object_name":self.name})
                return callback.error(msg)

        base_access_groups = config.get_base_objects("accessgroup")
        if self.name in base_access_groups:
            msg = ("Cannot disable base accessgroup.")
            return callback.error(msg)

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask(_("Disable %(object_type)s "
                                        "'%(object_name)s'?: ")
                                        % {"object_type":self.type,
                                        "object_name":self.name})
                if answer.lower() != "y":
                    return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                config.raise_exception()
                return callback.error(msg)

        self._enabled = False
        # Update index.
        self.update_index('enabled', False)

        return self._cache(callback=callback)

    @object_lock()
    def enable_acl_inheritance(self, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Enable ACL inheritance for the object """
        if self.acl_inheritance_enabled is None:
            return callback.error("Object cannot inherit ACLs.")

        if not self.verify_acl("enable:acl_inheritance"):
            msg = ("Permission denied: %s" % self)
            return callback.error(msg, exception=PermissionDenied)

        if self.acl_inheritance_enabled:
            return callback.error("ACL inheritance already enabled.")

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Enable ACL inheritance?: ")
                if answer.lower() != "y":
                    return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_acl_inheritance",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.acl_inheritance_enabled = True

        self.update_index('acl_inheritance_enabled',
                        self.acl_inheritance_enabled)

        return self._cache(callback=callback)

    @object_lock()
    def disable_acl_inheritance(self, force=False, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Disable ACL inheritance for the object """
        if self.acl_inheritance_enabled is None:
            return callback.error("Object cannot inherit ACLs.")

        if not self.verify_acl("disable:acl_inheritance"):
            msg = ("Permission denied: %s" % self)
            return callback.error(msg, exception=PermissionDenied)

        if not self.acl_inheritance_enabled:
            return callback.error("ACL inheritance already disabled.")

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask("Disable ACL inheritance?: ")
                if answer.lower() != "y":
                    return callback.abort()

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_acl_inheritance",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        self.acl_inheritance_enabled = False

        self.update_index('acl_inheritance_enabled',
                        self.acl_inheritance_enabled)

        return self._cache(callback=callback)

    def verify_acl(self, acl, **kwargs):
        """ Wrapper class that may be overridden by child class """
        return self._verify_acl(acl, **kwargs)

    def _verify_acl(self, acl, need_exact_acl=False,
        check_admin_user=True, check_admin_role=True, auth_token=None):
        """ Check if current user is authorized by the given ACL """
        # Site admins should not have access to realm, site or admin token
        # without ACL check.
        if self.type == "realm":
            check_admin_role = False
        if self.type == "site":
            check_admin_role = False
        if self.uuid == config.admin_token_uuid:
            check_admin_role = False
        result = otpme_acl.verify(uuid=self.uuid, acl_list=self.acls, acl=acl,
                                    check_admin_role=check_admin_role,
                                    check_admin_user=check_admin_user,
                                    need_exact_acl=need_exact_acl,
                                    auth_token=auth_token)
        return result

    def get_acl_apply_ids(self, acl, inherit=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Get normal and recursive apply IDs. """
        # Default apply IDs.
        apply_id = None
        recursive_apply_id = None

        # Check if ACL is supported.
        supported_acl = self.check_supported_acl(acl=acl)

        if inherit:
            # On inheritance ignore non default ACLs.
            if not acl.default:
                return apply_id, recursive_apply_id
            # Recursive ACLs only apply if they are supported by this object.
            if acl.recursive:
                if supported_acl:
                    recursive_apply_id = acl.id
            # If the ACL object type matches this object we have to apply the
            # default ACL.
            if acl.object_type is None or acl.object_type == self.type:
                apply_id = acl.apply_id
        else:
            if supported_acl:
                apply_id = acl.id
            else:
                # For users we have to apply default and recursive token ACLs
                # with modified apply ID.
                if self.type == "user" and acl.object_type == "token":
                    if acl.default:
                        apply_id = acl.id
                    # For recursive ACLs we have to remove the first "+"
                    # (e.g. ++token:add) from the apply ID.
                    if acl.recursive:
                        apply_id = acl.id[1:]
                        recursive_apply_id = apply_id

        # Make sure we do not return same apply IDs.
        if recursive_apply_id == apply_id:
            recursive_apply_id = None

        return apply_id, recursive_apply_id

    def check_supported_acl(self, acl, _caller="API",
        callback=default_callback, **kwargs):
        """ Check if the given ACL is supported by this object. """
        acl_types = ['acls']
        if acl.default:
            if acl.recursive:
                acl_types = ['recursive_default_acls']
            else:
                acl_types = ['default_acls']

        supported_acls = self.get_supported_acls(acl_types=acl_types)
        if acl.id in supported_acls:
            return True

        return False

    @supported_acls_cache.cache_method()
    def get_supported_acls(self, acl_types=['acls'], _caller="API",
        callback=default_callback, **kwargs):
        """ Get all supported ACLs of object """
        from otpme.lib.extensions import utils
        acls = []

        if "acls" in acl_types:
            for i in self._acls:
                acls.append(i)
            for i in self._value_acls:
                for v in self._value_acls[i]:
                    acls.append("%s:%s" % (i, v))

        if "default_acls" in acl_types:
            for i in self._default_acls:
                if i.startswith("+"):
                    object_type = i.split("+")[1]
                    # Build module path to module.
                    object_module_path = "otpme.lib.classes.%s" % object_type
                    # Import object module.
                    object_module = importlib.import_module(object_module_path)
                    # Get object ACLs.
                    for a in object_module.get_acls():
                        default_acl = "+%s:%s" % (object_type, a)
                        acls.append(default_acl)

                    # Get extension ACLs.
                    for a in utils.get_acls(object_type):
                        default_acl = "+%s:%s" % (object_type, a)
                        acls.append(default_acl)

                    # Get object value ACLs.
                    value_acls = object_module.get_value_acls()
                    for a in value_acls:
                        for v in value_acls[a]:
                            default_acl = "+%s:%s:%s" % (object_type, a, v)
                            acls.append(default_acl)

                    # Get extension value ACLs.
                    value_acls = utils.get_value_acls(object_type)
                    for a in value_acls:
                        for v in value_acls[a]:
                            default_acl = "+%s:%s:%s" % (object_type, a, v)
                            acls.append(default_acl)
                else:
                    default_acl = "+%s" % i
                    acls.append(default_acl)

        if "recursive_default_acls" in acl_types:
            for i in self._recursive_default_acls:
                if i.startswith("+"):
                    object_type = i.split("+")[1]
                    # Build module path to module.
                    object_module_path = "otpme.lib.classes.%s" % object_type
                    # Import object module.
                    object_module = importlib.import_module(object_module_path)
                    # Get object ACLs.
                    for a in object_module.get_acls():
                        default_acl = "++%s:%s" % (object_type, a)
                        acls.append(default_acl)

                    # Get extension ACLs.
                    for a in utils.get_acls(object_type):
                        default_acl = "++%s:%s" % (object_type, a)
                        acls.append(default_acl)

                    # Get object value ACLs.
                    value_acls = object_module.get_value_acls()
                    for a in value_acls:
                        for v in value_acls[a]:
                            default_acl = "++%s:%s:%s" % (object_type, a, v)
                            acls.append(default_acl)

                    # Get extension value ACLs.
                    value_acls = utils.get_value_acls(object_type)
                    for a in value_acls:
                        for v in value_acls[a]:
                            default_acl = "++%s:%s:%s" % (object_type, a, v)
                            acls.append(default_acl)
                else:
                    default_acl = "++%s" % i
                    acls.append(default_acl)

        if _caller == "CLIENT":
            acls = "\n".join(acls)

        return callback.ok(acls)

    @object_lock()
    def inherit_default_acl(self, acl, force=False, verify_acls=True,
        verbose_level=0, callback=default_callback, **kwargs):
        """ Inherit default ACL from parent object. """
        exception = None

        # Skip normal ACLs.
        if not acl.default:
            return callback.ok()

        # Do not inherit ACL if object does not support it.
        if self.acl_inheritance_enabled is None:
            return callback.ok()
        # Do not inherit ACL if its disabled.
        if not force:
            if not self.acl_inheritance_enabled:
                if verbose_level >= 2:
                    msg = (_("ACL inheritance disabled for object %s")
                            % self.oid)
                    callback.send(msg)
                # Disabled ACL inheritance is not an error.
                return callback.ok()

        # Get ACL apply IDs.
        apply_id, recursive_apply_id = self.get_acl_apply_ids(acl=acl,
                                                            inherit=True)

        # Add recursive default ACL.
        if recursive_apply_id:
            try:
                add_status = self.add_acl(acl=recursive_apply_id,
                                        owner_uuid=acl.owner_uuid,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
                if not add_status:
                    exception = True
            except Exception as e:
                if not exception:
                    exception = str(e)

        # Add default ACL.
        if apply_id:
            try:
                add_status = self.add_acl(acl=apply_id,
                                        owner_uuid=acl.owner_uuid,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
                if not add_status:
                    exception = True
            except Exception as e:
                if not exception:
                    exception = str(e)

        if exception:
            return callback.error(exception)

        return callback.ok()

    @object_lock()
    def disinherit_default_acl(self, acl, force=False, verify_acls=True,
        verbose_level=0, callback=default_callback, **kwargs):
        """ Disinherit default ACL from parent object. """
        exception = None
        # Skip normal ACLs.
        if not acl.default:
            return callback.ok()
        # Do not inherit ACL if object does not support it.
        if self.acl_inheritance_enabled is None:
            return callback.ok()
        # Do not disinherit ACL if its disabled.
        if not force:
            if not self.acl_inheritance_enabled:
                if verbose_level >= 2:
                    msg = (_("ACL inheritance disabled for object %s")
                            % self.oid)
                    callback.send(msg)
                # Disabled ACL inheritance is not an error.
                return callback.ok()

        # Get ACL apply IDs.
        apply_id, recursive_apply_id = self.get_acl_apply_ids(acl=acl,
                                                            inherit=True)

        # Remove recursive default ACL.
        if recursive_apply_id:
            del_acl = "%s:%s:%s" % (acl.owner_type,
                                    acl.owner_uuid,
                                    recursive_apply_id)
            try:
                del_status = self.del_acl(acl=del_acl,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
                if not del_status:
                    exception = True
            except Exception as e:
                if not exception:
                    exception = str(e)

        if apply_id:
            del_acl = "%s:%s:%s" % (acl.owner_type,
                                    acl.owner_uuid,
                                    apply_id)
            try:
                del_status = self.del_acl(acl=del_acl,
                                        verify_acls=verify_acls,
                                        verbose_level=verbose_level,
                                        callback=callback,
                                        **kwargs)
                if not del_status:
                    exception = True
            except Exception as e:
                if not exception:
                    exception = str(e)

        if exception:
            return callback.error(exception)

        return callback.ok()

    @object_lock()
    def inherit_acls(self, parent_object=None, remove=False, force=False,
        verify_acls=True, verbose_level=0, callback=default_callback, **kwargs):
        """ Inherit ACLs from parent object. """
        exception = None

        # Realms do not inherit ACLs.
        if self.type == "realm":
            return True

        if parent_object is None:
            try:
                parent_object = self.get_parent_object()
            except Exception as e:
                msg = (_("Unable to get parent object: %s: %s") % (self.oid, e))
                return callback.error(msg)

        # Inherit parent object ACLs.
        for x in parent_object.acls:
            try:
                acl = otpme_acl.decode(x)
            except Exception as e:
                msg = (_("Error decoding ACL: %s: %s") % (acl, e))
                logger.critical(msg)
                return callback.error(msg)

            if remove:
                status = self.disinherit_default_acl(acl=acl,
                                                force=force,
                                                verify_acls=verify_acls,
                                                verbose_level=verbose_level,
                                                callback=callback,
                                                **kwargs)
                if not status:
                    exception = True
            else:
                status = self.inherit_default_acl(acl=acl,
                                                force=force,
                                                verify_acls=verify_acls,
                                                verbose_level=verbose_level,
                                                callback=callback,
                                                **kwargs)
                if not status:
                    exception = True

        if exception:
            return callback.error(exception)

        return callback.ok()

    @check_acls(acls=['view:acl'])
    def get_acls(self, run_policies=True, _caller="API",
        callback=default_callback, **kwargs):
        """ Get ACLs of object. """
        if run_policies:
            try:
                self.run_policies("get_acls",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        acls = []
        for i in self.acls:
            o_type = i.split(":")[0]
            o_uuid = i.split(":")[1]
            acl = ":".join(i.split(":")[2:])
            result = backend.search(attribute="uuid",
                                    value=o_uuid,
                                    return_type="path")
            if result:
                o_path = result[0]
                x = oid.resolve_path(o_path, object_type=o_type)
                o_realm = x['realm']
                o_site = x['site']
                o_rel_path = x['rel_path']
                o_name = x['name']

                if o_type == "role":
                    if o_realm == config.realm:
                        resolved_acl = "%s:%s/%s:%s" % (o_type,
                                                        o_site,
                                                        o_name,
                                                        acl)
                    else:
                        resolved_acl = "%s:/%s/%s/%s:%s" % (o_type,
                                                            o_realm,
                                                            o_site,
                                                            o_name,
                                                            acl)
                if o_type == "token":
                    resolved_acl = "%s:%s:%s" % (o_type, o_rel_path, acl)
                acls.append(resolved_acl)
            else:
                # xxxxxxxxxxxxx
                # FIXME: remove orphan ACLs here? (e.g. deleted tokens?)
                uuid_acl = "%s:%s:%s" % (o_type, o_uuid, acl)
                acls.append(uuid_acl)

        acls.sort()

        if _caller == "CLIENT":
            acls = "\n".join(acls)
            return callback.ok(acls)

        return callback.ok(acls)

    def _handle_acl(self, action, acl, callback=default_callback, **kwargs):
        """ Should be overridden by child class. """
        return callback.ok()

    @object_lock()
    def add_acl(self, *args, **kwargs):
        """ Add ACL to object. """
        try:
            recursive_acls = kwargs['recursive_acls']
        except:
            recursive_acls = False
        begin_transaction = False
        if recursive_acls:
            begin_transaction = True
        # Do not start a new transaction if one exists.
        if self.no_transaction:
            begin_transaction = False
        else:
            transaction = backend.get_transaction()
            if transaction:
                begin_transaction = False
        if begin_transaction:
            backend.begin_transaction("add_acl")
        result = self.handle_acl("add", *args, **kwargs)
        if begin_transaction:
            backend.end_transaction()

        return result

    @object_lock()
    def del_acl(self, *args, **kwargs):
        """ Delete ACL from object. """
        try:
            recursive_acls = kwargs['recursive_acls']
        except:
            recursive_acls = False
        begin_transaction = False
        if recursive_acls:
            begin_transaction = True
        # Do not start a new transaction if one exists.
        if self.no_transaction:
            begin_transaction = False
        else:
            transaction = backend.get_transaction()
            if transaction:
                begin_transaction = False
        if begin_transaction:
            backend.begin_transaction("add_acl")
        result = self.handle_acl("del", *args, **kwargs)
        if begin_transaction:
            backend.end_transaction()

        return result

    @object_lock()
    @one_time_policy_run
    def handle_acl(self, action, acl, owner_type=None, owner_name=None,
        owner_uuid=None, object_types=[], recursive_acls=False,
        apply_default_acls=False, _acl_objects=[], force=False,
        verify_acls=True, run_policies=True, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Handle ACL add/del. """
        raw_acl = None
        valid_acl = True
        exception = None

        if action == "add":
            check_acl = "add:acl"
            policy_hook = "add_acl"
        else:
            check_acl = "delete:acl"
            policy_hook = "del_acl"

        if verify_acls:
            if not self.verify_acl(check_acl):
                exception = (_("Permission denied: %s") % self)
                valid_acl = False
                if _acl_objects and verbose_level > 1:
                    callback.send(exception, exception=PermissionDenied)

        first_recursive_call = True
        if _acl_objects:
            # If we where called with non-empty _acl_objects this is not the
            # first call in the recurisive call stack of this method. So we
            # do not write objects.
            first_recursive_call = False
        else:
            if run_policies:
                try:
                    self.run_policies("modify",
                                    force=force,
                                    callback=callback,
                                    _caller=_caller)
                    self.run_policies(policy_hook,
                                    force=force,
                                    callback=callback,
                                    _caller=_caller)
                except Exception as e:
                    msg = str(e)
                    return callback.error(msg)

        # Try to get object type and UUID from ACL.
        if not owner_type and not owner_uuid:
            try:
                _acl = otpme_acl.decode(acl)
            except Exception as e:
                msg = (_("Error decoding ACL: %s: %s") % (acl, e))
                logger.critical(msg)
                return callback.error(msg)

            owner_type = _acl.owner_type
            owner_uuid = _acl.owner_uuid
            if owner_type and owner_uuid:
                raw_acl = _acl.raw

        # Try to get owner UUID from backend.
        if owner_type and not owner_uuid:
            # FIXME: how to add tokens from other realms and roles from other realms/sites!?
            if owner_type == "token":
                search_attribute = "rel_path"
                search_site = None
            else:
                if "/" in owner_name:
                    search_attribute = "path"
                    search_site = None
                else:
                    search_attribute = "name"
                    search_site = self.site

            result = backend.search(attribute=search_attribute,
                                    value=owner_name,
                                    object_type=owner_type,
                                    realm=self.realm,
                                    site=search_site)
            if not result:
                msg = (_("Unknown %s: %s") % (owner_type, owner_name))
                logger.critical(msg)
                return callback.error(msg)
            if len(result) > 1:
                msg = (_("Found multiple objects for '%s': %s")
                        % (owner_name, ", ".join(result)))
                logger.critical(msg)
                return callback.error(msg)
            owner_uuid = result[0]

        # Try to get owner type from backend.
        if owner_uuid and not owner_type:
            for t in [ 'role', 'token']:
                result = backend.search(attribute="uuid",
                                        value=owner_uuid,
                                        object_type=t)
                if not result:
                    continue
                if len(result) > 1:
                    msg = (_("Found multiple %(owner_type)s's for UUID "
                            "'%(owner_uuid)s': %(result)s")
                            % {"owner_type":t,
                            "owner_uuid":owner_uuid,
                            "result":", ".join(result)})
                    logger.critical(msg)
                    return callback.error(msg)
                owner_type = t
                break
            if not owner_type:
                msg = (_("Unknown object: %s") % owner_uuid)
                return callback.error(msg)

        # If we got the required values not as attributes and not from
        # the ACL string we cannot continue.
        if not (owner_type and owner_name) and not owner_uuid:
            msg = (_("Need at least <owner_type> + "
                    "<owner_name> or <owner_uuid>"))
            raise OTPmeException(msg)

        # Build raw ACL if needed.
        if not raw_acl:
            raw_acl = "%s:%s:%s" % (owner_type, owner_uuid, acl)
            # Load raw ACL.
            try:
                _acl = otpme_acl.decode(raw_acl)
            except Exception as e:
                msg = (_("Error decoding ACL: %s: %s") % (acl, e))
                logger.critical(msg)
                return callback.error(msg)

        # Check if this object supports the ACL.
        if valid_acl:
            acl_supported = self.check_supported_acl(acl=_acl)
            if not acl_supported:
                valid_acl = False
                # An unsupported ACL is only an error if its added explicitly
                # (not recursive) to this object or if this is not the first
                # call of an recursive call of _handle_acl(). E.g. adding the
                # ACL "+token:edit" recursive to a site is a valid call because
                # the ACL will be added to all supported objects of the site
                # but not to the site itself.
                if not recursive_acls or (recursive_acls and _acl_objects):
                    exception = (_("Unsupported ACL: %s: %s")
                                % (self.oid, _acl.id))

        # Add ACL (or default ACL) to the object if there was no exception.
        if valid_acl and raw_acl:
            # FIXME: add full object path or OID instead of rel_path!!!?
            # Build resolved ACL string.
            object_desc = owner_uuid
            object_id = backend.get_oid(object_type=owner_type,
                                        uuid=owner_uuid,
                                        instance=True)
            if object_id:
                object_desc = object_id.rel_path
            resolved_acl = "%s:%s:%s" % (owner_type, object_desc, _acl.id)

            object_match = True
            if object_types and self.type not in object_types:
                object_match = False

            object_modified = False
            if object_match:
                if action == "add":
                    # Add ACL.
                    if raw_acl not in self.acls:
                        self.acls.append(raw_acl)
                        msg = (_("Adding ACL %(resolved_acl)s to %(object_id)s")
                                % {"resolved_acl":resolved_acl,
                                "object_id":self.oid})
                        object_modified = True
                        if verbose_level > 0:
                            callback.send(msg)
                else:
                    # Remove ACL.
                    if raw_acl in self.acls:
                        msg = (_("Removing ACL %(resolved_acl)s from %(object_id)s")
                                % {"resolved_acl":resolved_acl,
                                "object_id":self.oid})
                        object_modified = True
                        if verbose_level > 0:
                            callback.send(msg)
                        self.acls.remove(raw_acl)

            # Add this object to be written at the end of this
            # method call (loop).
            if object_modified:
                if not self in _acl_objects:
                    _acl_objects.append(self)

        # Call child class method (e.g. to inherit ACLs)
        add_status = self._handle_acl(action, _acl,
                                    force=force,
                                    _caller=_caller,
                                    run_policies=run_policies,
                                    verify_acls=verify_acls,
                                    object_types=object_types,
                                    recursive_acls=recursive_acls,
                                    apply_default_acls=apply_default_acls,
                                    _acl_objects=_acl_objects,
                                    verbose_level=verbose_level,
                                    callback=callback, **kwargs)
        if not add_status and not exception:
            exception = True

        if exception:
            if _acl_objects:
                if exception is True:
                    return callback.error()
            else:
                # FIXME: We need to investigate all "exception" stuff.
                #        Enabling the if-statement below hides a "Unknown ACL value:"
                #        when calling e.g.  otpme-unit -vv del_acl -r hosts token user1/pass "view:host"
                #if verbose_level <= 1 or exception is True:
                if exception is True:
                    exception = (_("Command failed. Please try (-vv) to see "
                                "all errors."))
            return callback.error(exception)

        if first_recursive_call:
            for o in list(_acl_objects):
                # Write/cache modified objects.
                if o._cache(callback=callback):
                    # Trigger ACL cache clearing.
                    cache.clear_acl_cache(object_uuid=self.uuid)
                else:
                    msg = (_("Error writing %(object_type)s config: "
                            "%(object_id)s")
                            % {"object_type":self.type,
                            "object_id":self.oid})
                    logger.critical(msg)
                    exception = True
                # Remove object from list because this list may be passed via
                # kwargs to different handle_acl() calls e.g. in
                # inherit_default_acl().
                _acl_objects.remove(o)

        return callback.ok()

    def check_auto_disable(self, **kwargs):
        """ Handle auto disable. """
        if not self.auto_disable:
            return
        if self.auto_disable_start_time == 0:
            return
        if not self._enabled:
            return
        if self.unused_disable:
            check_time = self.get_last_used_time()
        else:
            check_time = self.auto_disable_start_time
        disable_time = units.string2unixtime(self.auto_disable, check_time)
        now = time.time()
        if now >= disable_time:
            try:
                self.disable(force=True,
                            verify_acls=False,
                            run_policies=False)
                object_disabled = True
                self._write()
            except Exception as e:
                exception = e
                object_disabled = False
                config.raise_exception()
            if object_disabled:
                msg = (_("%s auto-disabled: %s") % (self.type, self.name))
                logger.warning(msg)
            else:
                msg = (_("Cannot auto-disable object: %s: %s")
                        % (self.name, exception))
                logger.critical(msg)
                return False
        return True

    @check_acls(['edit:auto_disable'])
    @object_lock()
    @backend.transaction
    def change_auto_disable(self, auto_disable, unused=False,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Change auto disable value. """
        if auto_disable != 0:
            try:
                # Check if given date string is valid.
                units.string2unixtime(auto_disable, time.time())
            except Exception as e:
                msg = "Invalid date string: %s" % e
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_auto_disable",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if auto_disable == 0:
            self.auto_disable = ""
        else:
            self.unused_disable = unused
            self.auto_disable = auto_disable
            self.auto_disable_start_time = time.time()

        return self._cache(callback=callback)

    @check_acls(acls=['edit:secret'])
    @object_lock(full_lock=True)
    def change_secret(self, auto_secret=False, secret=False,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Change object secret """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_secret",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Call child class method that may return a new secret or just do some
        # other checks. If the method returns a string its used as the new
        # secret if the method returns False we abort secret changing else we
        # continue as usual.
        try:
            x = self._change_secret(secret=secret,
                                    pre=True,
                                    callback=callback,
                                    **kwargs)
            if isinstance(x, str):
                secret = x
            if x is False:
                return callback.abort()
        except:
            pass

        if not secret and not auto_secret:
            answer = False
            while not answer:
                answer = callback.ask("Use auto-generated secret?: ")
            if answer.lower() == "y":
                auto_secret = True

        if auto_secret:
            secret = stuff.gen_secret(self.secret_len)

        if not secret:
            while True:
                new_secret1 = callback.askpass("New secret: ")
                new_secret1 = new_secret1.replace(" ", "")
                new_secret2 = callback.askpass("Re-type secret: ")
                new_secret2 = new_secret2.replace(" ", "")
                if new_secret1 == new_secret2:
                    secret = new_secret1
                    break
                else:
                    return callback.error("Sorry, secrets do not match.")

        # Make sure secret is a string.
        secret = str(secret)
        # Remove spaces from secret (e.g. when pasting from yubico tool)
        secret = secret.replace(" ", "")

        # Run child class method (e.g. handle token specific stuff when
        # changing the secret)
        try:
            if not self._change_secret(secret=secret, callback=callback, **kwargs):
                return callback.abort()
        except:
            pass

        # Set new secret
        self.secret = secret

        if auto_secret:
            msg = "New secret: %s" % secret
            callback.send(msg)

        return self._cache(callback=callback)

    @check_acls(acls=['view_all:secret'])
    def show_secret(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Show object secret. """
        if run_policies:
            try:
                self.run_policies("show_secret",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)
        try:
            self.secret
        except:
            return callback.error()
        return callback.ok(self.secret)

    def get_cert(self, callback=default_callback, **kwargs):
        """ Return certificate as base64. """
        if not self.cert:
            msg = (_("%s does not have a certificate.") % self.name)
            return callback.error(msg)
        return callback.ok(self.cert)

    @check_acls(acls=['view_all:cert_key'])
    def get_cert_key(self, passphrase=None,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Return private key. optionally encrypted with <passphrase>. """
        if not self.key:
            msg = (_("%s does not have a private key.") % self.name)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("get_cert_key",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if passphrase:
            _cert = SSLCert(key=self.key)
            key = _cert.encrypt_key(passphrase=passphrase)
        else:
            key = self.key
        return callback.ok(key)

    def get_ca_chain(self, crl=None, callback=default_callback, **kwargs):
        """ Return CA chain needed to verify object certificate. """
        from otpme.lib.pki import utils
        if not self.cert:
            msg = (_("%s does not have a certificate.") % self.name)
            return callback.error(msg)
        cert_chain = utils.get_ca_chain(self.cert, crl=crl)
        return callback.ok(cert_chain)

    @check_acls(acls=['move'])
    @object_lock(full_lock=True)
    # Besides we dont need a transaction for object moves it keeps object
    # locks longer than needed and slows down other jobs while moving.
    #@backend.transaction
    def move(self, new_unit, force=False, callback=default_callback, **kwargs):
        """ Change object unit. """
        lock_caller = "move"
        if new_unit == "":
            return callback.error("Missing unit.")
        # Remove tailing slash.
        if new_unit.endswith("/"):
            new_unit = new_unit[:-1]
        # Build absolute path.
        if not new_unit.startswith("/"):
            new_unit = "/%s/%s/%s" % (self.realm, self.site, new_unit)

        # Get regex to check if name is valid.
        if not oid.check_path("unit", new_unit):
            return callback.error("Invalid new unit.")

        # Get new unit.
        from otpme.lib.classes.unit import Unit
        try:
            _new_unit = Unit(path=new_unit)
        except Exception as e:
            msg = "Invalid unit: %s" % e
            return callback.error(msg)

        if not _new_unit.exists():
            msg = ("Unknown unit: %s: %s" % (self, new_unit))
            return callback.error(msg)

        add_acl = "add:%s" % self.type
        if not _new_unit.verify_acl(add_acl):
            msg = "Permission denied: %s" % _new_unit.path
            return callback.error(msg)

        _new_unit.acquire_lock(lock_caller=lock_caller)
        try:
            if _new_unit.rel_path == self.unit:
                object_type = "%s%s" % (self.type[0].upper(), self.type[1:])
                msg = (_("%(object_type)s already in unit '%(unit)s'.")
                        % {"object_type":object_type, "unit":new_unit})
                return callback.error(msg)
            msg = "Moving %s %s > %s..." % (self.type, self.path, new_unit)
            callback.send(msg)
            move_result = self._move(new_unit=_new_unit,
                                    lock_caller=lock_caller,
                                    callback=callback,
                                    force=force,
                                    **kwargs)
        finally:
            _new_unit.release_lock(lock_caller=lock_caller)
        return move_result

    def _move(self, new_unit, lock_caller, run_policies=True, keep_acls=None,
        verbose_level=0, callback=default_callback, _caller="API", **kwargs):
        """ Change object unit. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_unit",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        exception = None
        old_unit = self.unit
        inherit_acls = True
        inherit_acls_message = ""

        # Do not inherit ACL if object does not support it.
        if self.acl_inheritance_enabled is None:
            inherit_acls = False

        if not self.acl_inheritance_enabled:
            inherit_acls_message = "ACL inheritance disabled"
            inherit_acls = False

        if inherit_acls:
            if self.type == "user":
                if self.is_admin():
                    inherit_acls_message = (_("ACL inheritance for admin users "
                                            "not allowed"))
                    inherit_acls = False
            if self.type == "token":
                if self.is_admin():
                    inherit_acls_message = (_("ACL inheritance for admin tokens "
                                            "not allowed"))
                    inherit_acls = False

        if inherit_acls:
            if self.uuid == config.admin_role_uuid:
                inherit_acls_message = (_("ACL inheritance for admin role "
                                        "not allowed"))
                inherit_acls = False

        if inherit_acls:
            if not self.verify_acl("add:acl") \
            or not self.verify_acl("delete:acl"):
                inherit_acls_message = (_("Permission denied"))
                inherit_acls = False

        if keep_acls is not None:
            inherit_acls = True
            if keep_acls:
                inherit_acls = False

        if inherit_acls:
            callback.send(_("* Removing default ACLs of old unit..."))
            try:
                status = self.inherit_acls(remove=True,
                                            apply_default_acls=True,
                                            recursive_acls=True,
                                            verbose_level=2,
                                            callback=callback)
                if not status and not exception:
                    exception = True
            except Exception as e:
                config.raise_exception()
                exception = (_("Error removing unit default ACLs: %s" % e))
        else:
            if inherit_acls_message:
                msg = (_("* NOT applying/removing default ACLs of new/old "
                        "unit: %s") % inherit_acls_message)
                callback.send(msg)

        # Clear old object from caches.
        cache.clear(self.oid)

        # Set new unit.
        self.unit = new_unit.rel_path
        self.unit_uuid = new_unit.uuid

        # Update index.
        self.update_index('unit', self.unit_uuid)

        # Remember old OID for move.
        old_oid = self.oid

        # Reset path.
        self.path = None
        self.set_path()
        # Reset Unit.
        self.set_unit()
        # Set new OID and switch lock.
        self.set_oid(switch_lock=True, lock_caller=lock_caller)

        # Do backend move/rename.
        try:
            backend.rename_object(object_id=old_oid,
                                new_object_id=self.oid,
                                cluster=True,
                                no_transaction=self.no_transaction)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error renaming %s '%s': %s")
                    % (self.type, new_oid.name, e))
            return callback.error(msg)

        # Update extensions.
        self.update_extensions("change_unit",
                            old_unit=old_unit,
                            new_unit=self.unit,
                            verbose_level=verbose_level,
                            callback=callback)

        # FIXME: we need an inherit_acls=False + --inherit-acls n option
        if inherit_acls:
            msg = (_("* Applying default ACLs of new unit..."))
            callback.send(msg)
            try:
                status = self.inherit_acls(apply_default_acls=True,
                                            recursive_acls=True,
                                            verbose_level=2,
                                            callback=callback)
                if not status and not exception:
                    exception = True
            except Exception as e:
                config.raise_exception()
                exception = (_("Error adding unit default ACLs: %s") % e)

        if exception:
            if exception is True:
                exception = ""
            return callback.error(exception)

        # Config options may be defined per unit, so we need
        # to clear the cache.
        config_cache.invalidate()

        # Write object as soon as possible to release lock.
        return self._write(callback=callback)

    @object_lock(full_lock=True)
    def change_script(self, script_var, script_options_var,
        script=None, script_options=None, callback=default_callback, **kwargs):
        """ Change the given script and its options. """
        # Get current script and script options.
        cur_script = getattr(self, script_var)
        cur_script_opts = getattr(self, script_options_var)

        # If we got no script ask user and prefill current script.
        if script is None and cur_script:
            _script = backend.get_object(object_type="script", uuid=cur_script)
            if _script:
                script_cmdline = _script.name
                if cur_script_opts:
                    script_cmdline += " " + " ".join(cur_script_opts)
                new_script_cmdline = callback.ask(input_prefill=script_cmdline,
                                                    message="Script: ")
                script = new_script_cmdline.split(" ")[0]
                script_options = new_script_cmdline.split(" ")[1:]

        if script == "":
            script = None

        if script:
            # Check if script exists.
            result = backend.search(object_type="script",
                                    attribute="rel_path",
                                    value=script,
                                    return_type="instance",
                                    realm=self.realm,
                                    site=self.site)
            if not result:
                return callback.error(_("Unknown script: %s") % script)
            s = result[0]
            script = s.uuid

        # Set new script and options.
        setattr(self, script_var, script)
        setattr(self, script_options_var, script_options)

        self.update_index(script_var, script)

        return self._cache(callback=callback)

    def get_sign_data(self, callback=default_callback, **kwargs):
        """ Dummy method to get sign data from object. """
        return callback.error("Object not signable.")

    def get_sign_users(self, username=None, user_uuid=None,
        verbose_level=0, callback=default_callback, **kwargs):
        """
        Get user instance(s) that signed this object. If 'username' is given
        only the instance of this user is returned if there is a valid signature
        from this user.
        """
        user_list = []
        if username or user_uuid:
            user = None
            if username:
                result = backend.search(attribute="name",
                                        value=username,
                                        object_type="user",
                                        return_type="instance",
                                        realm=config.realm)
                if not result:
                    msg = (_("Unknown user: %s") % username)
                    raise OTPmeException(msg)
                user = result[0]

            if user_uuid:
                user = backend.get_object(object_type="user", uuid=user_uuid)
                if not user:
                    msg = (_("Cannot find user with UUID: %s") % user_uuid)
                    raise OTPmeException(msg)

            if user:
                if not user.uuid in self.signatures \
                or len(self.signatures[user.uuid]) == 0:
                    msg = (_("No signature found for user: %s") % user.name)
                    raise OTPmeException(msg)
                user_list.append(user)
        else:
            for uuid in self.signatures:
                user = backend.get_object(object_type="user", uuid=uuid)
                if not user:
                    if verbose_level > 0:
                        callback.send(_("Found signature of orphan user: %s")
                                        % uuid)
                    continue
                # Skip orphan user entries in signatures dict.
                if len(self.signatures[uuid]) == 0:
                    continue
                user_list.append(user)
        return user_list

    def get_default_sign_tags(self):
        """ Get default sign tags for this object. """
        # FIXME: which tags to add what do they mean????
        #       - user means, this token is allowed for user xy (prevent assigning token to an other user without new sig!!!)
        #       - options means, token is allowed to login with the given options only!!! (e.g. prevent interactive SSH login if command option is set!!!
        #       - type_tag means, this token is member of e.g. this role
        #       - role, group and accessgroup tags mean also token is member of them
        # Add default tags.
        default_tags = []
        # Realm of the object (e.g. role, script, etc.)
        realm_tag = "realm:%s" % self.realm_uuid
        default_tags.append(realm_tag)
        # Site of the object (e.g. role, script, etc.)
        site_tag = "site:%s" % self.site_uuid
        default_tags.append(site_tag)
        # Type of the object (e.g. token, script, etc.)
        type_tag = "%s:%s" % (self.type, self.uuid)
        default_tags.append(type_tag)
        return default_tags

    @object_lock(full_lock=True)
    def resign(self, force=False, run_policies=False, verbose_level=0,
        callback=default_callback, _caller="API", **kwargs):
        """ Resign all signatures of the current auth user.. """
        if not config.auth_token:
            msg = "Not logged in."
            raise NotLoggedIn(msg)
        # Get current script signatures of the logged in user.
        auth_user_uuid = config.auth_token.owner_uuid
        script_signs = self.search_sign(user_uuid=auth_user_uuid,
                                        callback=callback,
                                        _caller=_caller)
        try:
            user_signs = script_signs[auth_user_uuid]
        except:
            msg = "No signatures found."
            return callback.error(msg, exception=NoSignature)

        # Recreate each signature.
        for sign_id in user_signs:
            # Get signature object.
            signature = script_signs[auth_user_uuid][sign_id]
            # Add new signature. This will also revoke the old signature.
            resign_status = self.sign(tags=signature.tags,
                                    sign_ref=signature.sign_ref,
                                    callback=callback,
                                    force=True)
            if not resign_status:
                sign_info = signature.get_sign_info()
                if verbose_level > 0:
                    sign_info = pprint.pformat(sign_info)
                else:
                    sign_info = sign_info['sign_ref']
                msg = "Failed to create signature: %s" % sign_info
                callback.error(msg)

        return callback.ok()

    @object_lock(full_lock=True)
    def sign(self, tags=None, sign_ref=None, force=False, run_policies=False,
        callback=default_callback, _caller="API", **kwargs):
        """ Sign the given object. """
        from otpme.lib.classes.signing import OTPmeSignature
        if tags and not isinstance(tags, list):
            msg = (_("<tags> must be list."))
            return callback.error(msg)

        signer = config.auth_user
        if not signer:
            msg = "Not logged in."
            raise NotLoggedIn(msg)

        # Reload auth user (e.g. new keys).
        signer._load()

        # Make sure tags is a list.
        if not tags:
            tags = []

        # By default we use the object itself as sign reference
        # (e.g. the script).
        if not sign_ref:
            sign_ref = self.uuid

        # Add default object tags.
        sign_tags = list(tags)
        default_tags = self.get_default_sign_tags()
        for x in default_tags:
            if x in sign_tags:
                continue
            sign_tags.append(x)

        # Get sign data from object.
        sign_data = self.get_sign_data()

        # The signature object.
        sig = OTPmeSignature(signer_uuid=signer.uuid,
                            signer_oid=signer.oid.full_oid,
                            sign_obj=self.uuid,
                            sign_data=sign_data,
                            sign_ref=sign_ref,
                            tags=sign_tags)

        # The data to be signed by users private key.
        sign_template = sig.get_sign_template()
        # The sign info with OIDs instead of UUIDs.
        sign_info = sig.get_sign_info()
        # Build sign request.
        sign_request = {
                            'sign_mode' : signer.sign_mode,
                            'sign_info' : sign_info,
                            'sign_data' : sign_template,
                        }
        # Request user (key script) to sign the data.
        signature = callback.sign(sign_request)

        if signature is False:
            return callback.abort()

        if not signature:
            msg = (_("Got empty signature."))
            return callback.error(msg)

        # Add signature data.
        sig.add_sign(signature)

        # Verify signature.
        try:
            sig.verify(signer.public_key, sign_data, tags=sign_tags)
        except VerificationFailed as e:
            msg = (_("Got invalid signature: %s") % e)
            logger.warning(msg)
            return callback.error(msg)
        except Exception as e:
            config.raise_exception()
            msg = (_("Failed to verify signature: %s") % e)
            logger.critical(msg)
            msg = (_("Failed to verify signature"))
            return callback.error(msg)

        # Add signature to object.
        status = self.add_sign(sig,
                            tags=sign_tags,
                            force=force,
                            callback=callback,
                            _caller=_caller)
        return status

    def load_sign(self, user_uuid, sign_id):
        """ Load signature object. """
        from otpme.lib.classes.signing import OTPmeSignature
        signature = self.signatures[user_uuid][sign_id]['signature']
        signature = OTPmeSignature(signature=signature)
        return signature

    @check_acls(acls=['add:signature'])
    @object_lock()
    def add_sign(self, signature, tags=None, force=False,
        run_policies=True, callback=default_callback,
        _caller="API", **kwargs):
        """ Add signature to object. """
        from otpme.lib.classes.signing import OTPmeSignature
        if not config.auth_token:
            return callback.error("Not logged in.")

        if not config.auth_user:
            return callback.error("Unable to find login user")

        if not isinstance(signature, OTPmeSignature):
            msg = (_("Invalid signature type: %s") % type(signature))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_sign",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        sign_id = signature.sign_id
        # Check if a valid signature already exists (via sign ID).
        if not force:
            callback.disable()
            try:
                verify_status = self.verify_sign(username=config.auth_token.owner,
                                                sign_id=sign_id,
                                                verify_acls=False,
                                                callback=callback)
            except Exception as e:
                verify_status = False
            callback.enable()
            if verify_status:
                msg = (_("A valid signature already exists. "
                        "Use -f to override."))
                return callback.error(msg)
        # Try to delete/revoke old signature.
        if self.auto_revoke:
            if config.auth_user.uuid in self.signatures:
                if sign_id in self.signatures[config.auth_user.uuid]:
                    msg = ("Auto revoking of signatures enabled.")
                    logger.debug(msg)
                    # Delete and revoke signature.
                    callback.disable()
                    try:
                        self.del_sign(user_uuid=config.auth_user.uuid,
                                        sign_id=sign_id,
                                        verify_acls=False,
                                        callback=callback)
                    except Exception as e:
                        config.raise_exception()
                        msg = (_("Failed to revoke old signature: %s") % e)
                        return callback.error(msg)
                    callback.enable()

        # Add new signature.
        try:
            user_signs = self.signatures[config.auth_user.uuid]
        except:
            user_signs = {}

        signer_uuid = config.auth_user.uuid

        # Get signature as string.
        sign_string = signature.dumps()

        sign_entry = {
                    'signature' : sign_string,
                    'tags'      : signature.tags,
                    }
        user_signs[sign_id] = sign_entry
        self.signatures[signer_uuid] = user_signs
        # Update index.
        self.del_index('signature', signer_uuid)
        self.add_index('signature', signer_uuid)

        return self._cache(callback=callback)

    @check_acls(acls=['delete:signature'])
    @object_lock()
    def del_sign(self, username=None, user_uuid=None, tags=None,
        sign_id=None, run_policies=True, _caller="API",
        callback=default_callback, **kwargs):
        """ Delete object signature. """
        if not self.signable:
            return callback.error(_("Object is not signable."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_sign",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Make sure tags is a list.
        if tags is None:
            tags = []

        # Add default tags.
        sign_tags = list(tags)
        default_tags = self.get_default_sign_tags()
        for x in default_tags:
            if x in sign_tags:
                continue
            sign_tags.append(x)

        sign_tags.sort()

        if not sign_id:
            sign_id = stuff.gen_md5(",".join(sign_tags))

        if username:
            result = backend.search(attribute="name",
                                        value=username,
                                        object_type="user",
                                        return_type="instance",
                                        realm=config.realm)
            if result:
                user = result[0]
            else:
                user = None
        elif user_uuid:
            user = backend.get_object(object_type="user", uuid=user_uuid)
        else:
            if not config.auth_token:
                return callback.error("Not logged in.")
            username = config.auth_user.name
            user = config.auth_user

        if not user:
            msg = (_("Unable to find user: %s") % username)
            return callback.error(msg)

        try:
            user_signs = self.signatures[user.uuid]
        except:
            user_signs = {}

        if not user_signs:
            msg = (_("No signature found for user: %s") % user.name)
            return callback.error(msg)

        # Load signature.
        try:
            signature = self.load_sign(user.uuid, sign_id)
        except:
            if sign_tags:
                msg = (_("No signature with given tags found: %s")
                        % ",".join(sign_tags))
            else:
                msg = (_("No signature without tags found."))
            return callback.error(msg)

        # Revoke signature.
        try:
            signature.revoke()
        except Exception as e:
            config.raise_exception()
            msg = (_("Failed to revoke signature: %s") % e)
            return callback.error(msg)

        # Remove signature from object.
        user_signs.pop(sign_id)
        # Remove user from self.signatures dict if no more signature exist.
        if not user_signs:
            self.signatures.pop(user.uuid)
            # Update index.
            self.del_index('signature', user.uuid)

        return self._cache(callback=callback)

    @object_lock()
    def verify_sign(self, signature=None, sign_id=None, username=None,
        user_uuid=None, tags=None, verify_acls=True, verbose_level=0,
        _caller="API", callback=default_callback, **kwargs):
        """ Verify object signature(s). """
        from otpme.lib.classes.signing import resolve_tags
        if verify_acls:
            # Everyone who is allowed to view the object is also allowed to
            # view its signatures. So it does not make sense to deny a user
            # with view:object permission to verify its signatures. But the
            # other way around it may be useful to allow one to verify object
            # signatures without the permission to view the object.
            if not self.verify_acl("verify_signature"):
                msg = ("Permission denied.")
                return callback.error(msg, exception=PermissionDenied)

        if tags:
            # We may get tags as comma separated list from command line.
            if type(tags) != list:
                tags = tags.split(",")

        # Get list with users signed this object.
        try:
            user_list = self.get_sign_users(username=username,
                                            user_uuid=user_uuid,
                                            callback=callback)
        except Exception as e:
            msg = str(e)
            return callback.error(msg)

        if not user_list:
            msg = ("No signature exists for this object.")
            return callback.error(msg)

        if sign_id:
            found_valid_sign_id = False

        # Make sure tags is a list.
        if tags is None:
            tags = []

        # Add default object tags.
        check_tags = list(tags)
        default_tags = self.get_default_sign_tags()
        for x in default_tags:
            if x in check_tags:
                continue
            check_tags.append(x)

        if check_tags:
            found_valid_sign_tags = False

        verify_status = False
        for user in user_list:
            for x_id in self.signatures[user.uuid]:
                # If we got a signature object use it.
                if signature:
                    # No need to check if signer UUID does not match.
                    if user.uuid != signature.signer_uuid:
                        continue
                    # No need to check if sign ID does not match.
                    if x_id != signature.sign_id:
                        continue
                    _sig = signature
                else:
                    # Load signature.
                    _sig = self.load_sign(user.uuid, x_id)
                # If we got a sign_id check only signatures with the right ID.
                if sign_id:
                    if _sig.sign_id == sign_id:
                        found_valid_sign_id = True
                    else:
                        continue
                # If we got tags we have to check if the current signature
                # includes all the requested tags.
                if check_tags:
                    tag_missing = False
                    for x in check_tags:
                        if not x in _sig.tags:
                            tag_missing = True
                            break
                    if tag_missing:
                        continue
                    found_valid_sign_tags = True

                sign_info = _sig.get_sign_info()
                if verbose_level > 0:
                    sign_info = pprint.pformat(sign_info)
                else:
                    sign_info = sign_info['sign_ref']
                # Verify if signature.
                sign_data = self.get_sign_data()
                try:
                    _sig.verify(public_key=user.public_key,
                                sign_data=sign_data,
                                tags=check_tags)
                    verify_status = True
                except VerificationFailed:
                    msg = ("%s: signature verification failed (%s)"
                            % (user.name, sign_info))
                    callback.send(msg)
                    verify_status = False
                    continue
                except InvalidPublicKey:
                    msg = "%s: Unable to load public key." % user.name
                    callback.send(msg)
                    verify_status = False
                    continue
                except SignatureRevoked:
                    msg = "%s: Signature revoked (%s)" % (user.name, sign_info)
                    callback.send(msg)
                    verify_status = False
                    continue
                except FaultySignature:
                    msg = "%s: Faulty signature (%s)" % (user.name, sign_info)
                    callback.send(msg)
                    verify_status = False
                    continue
                except Exception as e:
                    config.raise_exception()
                    msg = "%s: Invalid signature (%s)" % (user.name, sign_info)
                    callback.send(msg)
                    verify_status = False
                    continue

                msg = "%s: Signature OK (%s)" % (user.name, sign_info)
                callback.send(msg)

        msg = ""
        if sign_id and not found_valid_sign_id:
            verify_status = False
            msg = (_("No signature found with ID: %s") % sign_id)

        if tags and not found_valid_sign_tags:
            verify_status = False
            tags_str = resolve_tags(tags)
            tags_str = ",".join(tags_str)
            msg = (_("No signature found with tags: %s") % tags_str)

        if verify_status:
            return callback.ok()

        return callback.error(msg)

    # NOTE: No need to check ACLs for this method. Any user needs access
    #       to signatures, at least to verify them on key script execution.
    def get_sign(self, username=None, user_uuid=None, tags=None,
        verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Return object signature(s). """
        try:
            user_list = self.get_sign_users(username=username,
                                            user_uuid=user_uuid,
                                            callback=callback)
        except Exception as e:
            msg = str(e)
            return callback.error(msg)

        # If we got a user and tags we can search by sign ID.
        if (username or user_uuid) and tags:
            # Create signature ID.
            tags.sort()
            sign_id = stuff.gen_md5(",".join(tags))
        else:
            sign_id = None

        if _caller == "CLIENT":
            result = []
        else:
            result = {}

        for user in user_list:
            try:
                user_signs = self.signatures[user.uuid].copy()
            except:
                continue

            if sign_id:
                if not sign_id in user_signs:
                    continue
                if _caller == "CLIENT":
                    signature = "%s:%s" % (user.uuid,
                                user_signs[sign_id]['signature'])
                    result.append(signature)
                else:
                    signature = { sign_id : user_signs[sign_id] }
                    result[user.uuid] = signature
            else:
                for x_id in user_signs:
                    if _caller == "CLIENT":
                        signature = "%s:%s" % (user.uuid,
                                    user_signs[x_id]['signature'])
                        result.append(signature)
                    else:
                        if not user.uuid in result:
                            result[user.uuid] = {}
                        result[user.uuid][x_id] = user_signs[x_id]

        if _caller == "CLIENT":
            if not result:
                if tags:
                    msg = (_("No signature found with tags: %s") % ",".join(tags))
                else:
                    msg = (_("No signature found."))
                return callback.error(msg)
            result = "\n".join(result)

        return callback.ok(result)

    def search_sign(self, username=None, user_uuid=None, tags=None,
        sign_object=None, callback=default_callback, _caller="API", **kwargs):
        """ Search signature by attr/value. """
        result = {}
        for signer_uuid in self.signatures:
            if username:
                user_oid = backend.get_oid(object_type="user",
                                            uuid=signer_uuid,
                                            instance=True)
                if user_oid.name != username:
                    continue
            if user_uuid:
                if signer_uuid != user_uuid:
                    continue
            user_signatures = self.signatures[signer_uuid]
            for sign_id in user_signatures:
                signature = self.load_sign(signer_uuid, sign_id)
                if not signer_uuid in result:
                    result[signer_uuid] = {}
                if sign_object is not None:
                    if sign_object != signature.sign_ref:
                        continue

                if tags is not None:
                    found_sig = False
                    sign_tags = user_signatures[sign_id]['tags']
                    for tag in tags:
                        if tag in sign_tags:
                            found_sig = True
                        else:
                            found_sig = False
                            break
                    if not found_sig:
                        continue
                result[signer_uuid][sign_id] = signature
        return result

    @check_acls(acls=['edit:description'])
    @object_lock()
    def change_description(self, description=None,
        run_policies=True, callback=default_callback,
        verbose_level=0, _caller="API", **kwargs):
        """ Change object description. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_description",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        # Check if we got description as argument.
        if description is None:
            description = callback.ask(input_prefill=self.description,
                                        message="New description: ")
        self.description = str(description)

        # Update extensions.
        self.update_extensions("change_description",
                            verbose_level=verbose_level,
                            callback=callback)

        self.update_index('description', self.description)

        return self._cache(callback=callback)

    @object_lock()
    def add_default_policies(self, callback=default_callback):
        """ Add default policies to object. """
        # Sites do not inherit policies.
        if self.type == "site":
            return
        # Inherit policicies based on DefaultPolicies().
        if self.type == "unit":
            if self.unit_uuid:
                parent_type = "unit"
                parent_uuid = self.unit_uuid
            else:
                parent_type = "site"
                parent_uuid = self.site_uuid
        elif self.type == "token":
            # Our parent object is the token owner which may already be locked
            # if this is a token add/del. So we have to acquire no lock.
            token_owner = backend.get_object(object_type="user",
                                            uuid=self.owner_uuid)
            parent_type = "unit"
            parent_uuid = token_owner.unit_uuid
        else:
            parent_type = "unit"
            parent_uuid = self.unit_uuid

        if not parent_uuid:
            return

        parent = backend.get_object(uuid=parent_uuid,
                                object_type=parent_type)
        policies = parent.get_policies(policy_type="defaultpolicies",
                                        return_type="instance")
        for policy in policies:
            if self.type not in policy.default_policies:
                continue
            for x in policy.default_policies[self.type]:
                x_policy = backend.get_object(uuid=x, object_type="policy")
                if x_policy.uuid in self.policies:
                    continue
                self.add_policy(x_policy.name,
                                verify_acls=False,
                                callback=callback)
        return self._cache(callback=callback)

    def _run_parent_object_policies(self, policy_hook, parent_object=None,
        child_object=None, callback=default_callback, _caller="API", **kwargs):
        """ Run parent object policies (e.g. AuthOnAction()). """
        # Get parent object to check ACLs and run policies.
        if not parent_object:
            parent_object = self.get_parent_object()
        if not parent_object:
            msg = (_("Cannot run policies without parent object: %s")
                    % self.oid)
            return callback.error(msg)
        # Run policies for the given hook. Policy exceptions handling in calling
        # method!
        parent_object.run_policies(policy_hook,
                                child_object=child_object,
                                callback=callback,
                                _caller=_caller)

    def _prepare_add(self, uuid=None, handle_uuid=True,
        add_acl=None, verify_acls=True, need_exact_acl=False,
        check_exists=True, policy_hook=None, run_policies=True,
        template=None, callback=default_callback,
        verbose_level=0, _caller="API", **kwargs):
        """ Will do some basic stuff like lock the object, verify ACLs etc. """
        if check_exists:
            realm = config.realm
            site = config.site
            if self.type == "user" \
            or self.type == "group":
                realm = None
                site = None
            if backend.object_exists(self.oid, realm=realm, site=site):
                msg = (_("%s%s already exists.")
                    % (self.type[0].upper(), self.type[1:]))
                return callback.error(msg)

        # Get parent object to check ACLs and run policies.
        parent_object = self.get_parent_object()

        if verify_acls:
            if not parent_object:
                msg = (_("Cannot verify ACLs without parent object: %s")
                        % self.oid)
                return callback.error(msg)
            if add_acl is None:
                add_acl = "add:%s" % self.type
            if not parent_object.verify_acl(add_acl,
                        need_exact_acl=need_exact_acl):
                if not self.sub_type:
                    msg = (_("Permission denied: %s") % parent_object.path)
                    return callback.error(msg, exception=PermissionDenied)
                sub_type_acl = "add:%s:%s" % (self.type, self.sub_type)
                if not parent_object.verify_acl(sub_type_acl,
                                need_exact_acl=need_exact_acl):
                    msg = (_("Permission denied: %s") % parent_object.path)
                    return callback.error(msg, exception=PermissionDenied)

        msg = "Adding %s: %s" % (self.type, self.name)
        callback.send(msg)

        # Add policies from template.
        if template:
            for x in template.get_policies():
                policy = backend.get_object(object_type="policy",
                                            uuid=x)
                if x in self.policies:
                    self.remove_policy(policy_name=policy.name,
                                        verify_acls=False,
                                        callback=callback)
                    continue
                msg = "Adding policy: %s" % policy.name
                callback.send(msg)
                self.add_policy(policy_name=policy.name,
                                verify_acls=False,
                                callback=callback)

        # We have to run unit policies before adding an object e.g. to reauth.
        if run_policies:
            if policy_hook is None:
                policy_hook = "prepare_add_%s" % self.type
            try:
                self._run_parent_object_policies(policy_hook,
                                                parent_object=parent_object,
                                                child_object=self,
                                                callback=callback,
                                                _caller=_caller)
            except PolicyException as e:
                msg = str(e)
                return callback.error(msg)
            except Exception as e:
                config.raise_exception()
                msg = str(e)
                return callback.error(msg)

        if handle_uuid:
            if self.uuid is None:
                if uuid:
                    for t in config.tree_object_types:
                        x = backend.get_object(object_type=t, uuid=uuid)
                        if x:
                            msg = (_("UUID conflict: %s <> %s") % (self.oid, x.oid))
                            return callback.error(msg)
                    self.uuid = uuid
                else:
                    self.uuid = stuff.gen_uuid()

        # Make sure object is updated in modified objects (e.g. transaction).
        # We need a object UUID for this!!
        self._cache(callback=callback)

        return callback.ok()

    @object_lock(full_lock=True)
    @load_object(force=False)
    def add(self, creator=None, resolver=None, extensions=[], enabled=True,
        default_attributes={}, inherit_acls=True, template=None,
        template_object=False, verbose_level=0, run_policies=True,
        _caller="API", callback=default_callback, **kwargs):
        """ Should be called from child class to add default extensions etc. """
        # The resolver this object was added by.
        if resolver is not None:
            self.set_resolver(resolver)

        if creator is not None:
            self.creator = creator
        elif config.auth_token:
            # Use user UUID as creator instead of token UUID because token may
            # be deleted etc.
            self.creator = config.auth_token.owner_uuid
        else:
            if config.realm_init:
                self.creator = config.realm_uuid
                self.creator_cache = "Created on realm init."
            elif config.site_init:
                self.creator = config.site_uuid
                self.creator_cache = "Created on site init."
            elif config.use_api:
                self.creator_cache = "Created in API mode."

        if self.creator and not self.creator_cache:
            if not stuff.is_uuid(self.creator):
                msg = (_("Creator must be a UUID."))
                raise OTPmeException(msg)
            for x in config.tree_object_types:
                creator_oid = backend.get_oid(object_type=x,
                                            uuid=self.creator,
                                            full=False)
                if creator_oid:
                    break
            self.creator_cache = creator_oid

        # Check if object is a internal user.
        internal_user = False
        if self.type == "user":
            internal_users = config.get_internal_objects("user")
            if self.name in internal_users:
                internal_user = True

        # Update index.
        self.add_index("template", self.template_object)
        if self.unit_uuid is not None:
            self.update_index('unit', self.unit_uuid)
        self.update_index('acl_inheritance_enabled',
                        self.acl_inheritance_enabled)

        # For internal users (e.g. TOKENSTORE) we are done here.
        if internal_user:
            # Call base class add method.
            return super(OTPmeObject, self).add(verbose_level=verbose_level,
                                                    callback=callback,
                                                    **kwargs)
        # Extensions to add.
        try:
            add_extensions = config.default_extensions[self.type]
        except:
            add_extensions = []

        # Add extensions from template.
        if template:
            for x in template.extensions:
                if x in add_extensions:
                    continue
                add_extensions.append(x)

        # Merge extensions.
        for x in extensions:
            if x in add_extensions:
                continue
            add_extensions.append(x)

        # Actually add extensions to object.
        for e in add_extensions:
            if e in self.extensions:
                continue
            if verbose_level > 0:
                msg = (_("Adding default extension: %s") % e)
                callback.send(msg)
            try:
                e_default_attributes = default_attributes[e]
            except:
                e_default_attributes = {}
            try:
                self.add_extension(extension=e,
                                default_attributes=e_default_attributes,
                                verify_acls=False,
                                callback=callback,
                                verbose_level=verbose_level)
            except Exception as e:
                #config.raise_exception()
                callback.error(str(e))

        if template:
            # Add object classes from template.
            ocs = self.get_object_classes()
            for x in template.get_object_classes():
                if x in ocs:
                    continue
                self.add_object_class(x)

            # Add attributes from template.
            for ext in template.extensions:
                x_attrs = self.get_extension_attributes(ext)
                for attr in template.get_extension_attributes(ext):
                    x_vals = template.get_extension_attribute(ext, attr)
                    x_auto_val = template.get_extension_attribute(extension=ext,
                                                                attribute=attr,
                                                                auto_value=True,
                                                                callback=default_callback)
                    for x in x_vals:
                        if x not in x_auto_val:
                            self.add_attribute(attr, x, ignore_ro=True, callback=callback)
                            continue
                        if attr in x_attrs:
                            continue
                        self.add_attribute(attr, ignore_ro=True, callback=callback)

        # Add default policies.
        self.add_default_policies(callback=callback)

        # Inherit ACLs. Use force because on object add all objects will
        # inherit ACLs.
        if inherit_acls:
            try:
                inherit_status = self.inherit_acls(force=True,
                                                verify_acls=False,
                                                verbose_level=verbose_level,
                                                callback=callback)
                inherit_error = ""
            except Exception as e:
                config.raise_exception()
                inherit_status = False
                inherit_error = (_("WARNING: Unable to inherit ACLs from parent "
                                    "object: %s") % e)
            if not inherit_status:
                return callback.error(inherit_error)

        # Call base class add method.
        add_result = super(OTPmeObject, self).add(verbose_level=verbose_level,
                                                    callback=callback,
                                                    **kwargs)
        if run_policies:
            self._run_post_add_policies(callback=callback, _caller=_caller,
                                        verbose_level=verbose_level)
        # Set enabled status.
        if enabled and not internal_user:
            self.enable(force=True,
                    run_policies=False,
                    verify_acls=False,
                    callback=callback)
            #self.enabled = enabled
            #self.update_index('enabled', self.enabled)

        # Handle object creation by template.
        if template:
            # Set ACL inheritance.
            if template.acl_inheritance_enabled:
                if not self.acl_inheritance_enabled:
                    self.enable_acl_inheritance(force=True, callback=callback)
            else:
                if self.acl_inheritance_enabled:
                    self.disable_acl_inheritance(force=True, callback=callback)
            # FIXME: Where to get ACLs from????
            ## Add ACLs from template.
            #for x in template.acls:
            #    if x in self.acls:
            #        continue
            #    self.acls.append(x)

        # Write object.
        self._write(callback=callback)

        return add_result

    def _run_pre_add_policies(self, callback=default_callback,
        verbose_level=0, _caller="API", **kwargs):
        """ Run pre add policies (e.g. objecttemplates). """
        parent_object = self.get_parent_object()
        if not parent_object:
            return
        policy_hook = "pre_add_%s" % self.type
        self._run_parent_object_policies(policy_hook,
                                        parent_object=parent_object,
                                        child_object=self,
                                        callback=callback,
                                            _caller=_caller)

    def _run_post_add_policies(self, callback=default_callback,
        verbose_level=0, _caller="API", **kwargs):
        """ Run post add policies (e.g defaultgroups). """
        # We have to run unit policies before adding an object e.g. to reauth.
        parent_object = self.get_parent_object()
        if not parent_object:
            return
        policy_hook = "post_add_%s" % self.type
        self._run_parent_object_policies(policy_hook,
                                        parent_object=parent_object,
                                        child_object=self,
                                        callback=callback,
                                        _caller=_caller)

    @check_acls(acls=['rename:object'])
    @object_lock(recursive=True, full_lock=True)
    @backend.transaction
    def _rename(self, new_oid, force=False, run_policies=True,
        verbose_level=0, callback=default_callback,
        _caller="API", **kwargs):
        """ Rename object. """
        lock_caller = "_rename"
        if not self._object_lock:
            msg = "Cannot rename without object lock."
            raise OTPmeException(msg)
        if self._object_lock.outdated:
            msg = "Cannot rename object with expired lock: %s" % self
            return callback.error(msg)

        if self.name == new_oid.name:
            msg = (_("New name matches current name: %s")
                    % new_oid.name)
            return callback.error(msg)

        if backend.object_exists(object_id=new_oid):
            msg = (_("Cannot rename. %s%s '%s' exists.")
                    % (self.type[0].upper(), self.type[1:], new_oid.name))
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("rename",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                msg = str(e)
                return callback.error(msg)

        try:
            backend.rename_object(object_id=self.oid,
                                new_object_id=new_oid,
                                cluster=True,
                                no_transaction=self.no_transaction)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error renaming %s '%s': %s")
                    % (self.type, new_oid.name, e))
            return callback.error(msg)

        # Remember old name to update extensions.
        old_name = self.name

        # Set new object ID.
        self.set_oid(new_oid=new_oid,
                    switch_lock=True,
                    lock_caller=lock_caller)
        # Set new name etc.
        self.realm = new_oid.realm
        self.site = new_oid.site
        self.unit = new_oid.unit
        self.name = new_oid.name
        self.path = new_oid.path
        self.rel_path = new_oid.rel_path
        # Set new path.
        self.set_path()

        # Update extensions.
        self.update_extensions("rename",
                            old_name=old_name,
                            new_name=new_oid.name,
                            verbose_level=verbose_level,
                            callback=callback)

        # Update object config.
        self.update_object_config()

        self._write(callback=callback)

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def delete(self, force=False, run_policies=True,
        verbose_level=0, _caller="API",
        callback=default_callback, **kwargs):
        """ Delete object from backend. """
        if not self._object_lock:
            msg = "Cannot delete without object lock."
            raise OTPmeException(msg)
        if self._object_lock.outdated:
            msg = "Cannot delete object with expired lock: %s" % self
            return callback.error(msg)

        # Make sure all signatures are revoked before deleting the object.
        if self.auto_revoke and len(self.signatures) > 0:
            logger.debug("Auto revoking of signatures enabled.")
            for user_uuid in dict(self.signatures):
                for sign_id in dict(self.signatures[user_uuid]):
                    callback.disable()
                    try:
                        self.del_sign(user_uuid=user_uuid,
                                        sign_id=sign_id,
                                        callback=callback)
                    except Exception as e:
                        msg = (_("Failed to revoke signature: %s") % e)
                        return callback.error(msg)
                    callback.enable()

        if run_policies:
            parent_object = self.get_parent_object()
            if parent_object:
                policy_hook = "post_del_%s" % self.type
                try:
                    self._run_parent_object_policies(policy_hook,
                                                    child_object=self,
                                                    callback=callback,
                                                    _caller=_caller)
                except PolicyException as e:
                    msg = str(e)
                    return callback.error(msg)
                except Exception as e:
                    config.raise_exception()
                    msg = str(e)
                    return callback.error(msg)

        # Call base class write method.
        result = super(OTPmeObject, self).delete(verbose_level=verbose_level,
                                                callback=callback,
                                                force=force,
                                                **kwargs)
        return result

    def get_orphan_acls(self):
        """ Get orphan ACLs of this object. """
        acl_list = []
        for x in self.acls:
            _acl = otpme_acl.decode(x)
            acl_oid = backend.get_oid(object_types=['role', 'user'],
                                        uuid=_acl.owner_uuid)
            if not acl_oid:
                acl_list.append(x)
        return acl_list

    @check_acls(acls=['remove:orphans'])
    @object_lock()
    def remove_orphan_acls(self, force=False, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Remove orphan ACLs. """
        acl_list = self.get_orphan_acls()

        if not force:
            msg = None
            if acl_list:
                msg = (_("%s|%s: Found the following orphan ACLs: %s\nRemove?: ")
                        % (self.type, self.name, ",".join(acl_list)))
            if msg:
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        object_changed = False
        for i in acl_list:
            if verbose_level > 0:
                callback.send(_("Removing orphan ACL: %s") % i)
            object_changed = True
            self.acls.remove(i)

        msg = None
        if not object_changed:
            if verbose_level > 0:
                msg = (_("No orphan ACLs found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def get_orphan_policies(self):
        """ Get orphan policies of this object. """
        policy_list = []
        for x in self.policies:
            policy_oid = backend.get_oid(object_type="policy", uuid=x)
            if not policy_oid:
                policy_list.append(x)
        return policy_list

    @check_acls(acls=['remove:orphans'])
    @object_lock()
    def remove_orphan_policies(self, force=False, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Remove orphan policies. """
        policy_list = self.get_orphan_policies()

        if not force:
            msg = ""
            if policy_list:
                msg = (_("%s|%s: Found the following orphan policies: %s\nRemove?: ")
                        % (self.type, self.name, ",".join(policy_list)))
            if msg:
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        object_changed = False
        for i in policy_list:
            if verbose_level > 0:
                msg = (_("Removing orphan policy: %s") % i)
                callback.send(msg)
            object_changed = True
            self.policies.remove(i)
            # Update index.
            self.del_index('policy', i)

        msg = None
        if not object_changed:
            if verbose_level > 0:
                msg = (_("No orphan policies found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    def get_orphan_signatures(self):
        """ Get orphan signatures of this object. """
        signers_list = []
        for i in self.signatures:
            user_oid = backend.get_oid(object_type="user", uuid=i)
            if not user_oid:
                signers_list.append(i)
        return signers_list

    @check_acls(acls=['remove:orphans'])
    @object_lock()
    def remove_orphan_signatures(self, force=False, verbose_level=0,
        callback=default_callback, **kwargs):
        """ Remove orphan signatures. """
        if not self.signable:
            return callback.ok()

        signers_list = self.get_orphan_signatures()

        if not force:
            msg = None
            if signers_list:
                msg = (_("%s|%s: Found the following orphan signer UUIDs: "
                        "%s\nRemove?: ")
                        % (self.type, self.name, ",".join(signers_list)))

            if msg:
                answer = callback.ask(msg)
                if answer.lower() != "y":
                    return callback.abort()

        object_changed = False
        for i in signers_list:
            if verbose_level > 0:
                msg = (_("Removing orphan signature: %s") % i)
                callback.send(msg)
            object_changed = True
            self.signatures.pop(i)
            # Update index.
            self.del_index('signature', i)

        if not object_changed:
            msg = None
            if verbose_level > 0:
                msg = (_("No orphan objects found for %s: %s")
                        % (self.type, self.name))
            return callback.ok(msg)

        return self._cache(callback=callback)

    @object_lock()
    def remove_orphans(self, force=False, callback=default_callback, **kwargs):
        """
        Remove orphan UUIDs. This method could be overridden by the child class
        e.g. to remove orphan tokens. But then the child class must take care of
        removing orphan ACLs!
        """
        return_status = True
        status = self.remove_orphan_acls(force=force, callback=callback, **kwargs)
        if return_status:
            return_status = status
        status = self.remove_orphan_policies(force=force, callback=callback, **kwargs)
        if return_status:
            return_status = status
        status = self.remove_orphan_signatures(force=force, callback=callback, **kwargs)
        if return_status:
            return_status = status
        return return_status

    def show_config_parameters(self, callback=default_callback, **kwargs):
        result = self.config_params.copy()
        return callback.ok(result)

    def show_config(self, config_lines=[],
        callback=default_callback, **kwargs):
        """ Show object config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []
        lines.append('UUID="%s"' % self.uuid)

        if self.verify_acl("view:status") \
        or self.verify_acl("enable:object") \
        or self.verify_acl("disable:object"):
            lines.append('ENABLED="%s"' % self.enabled)
        else:
            lines.append('ENABLED=""')

        if self.verify_acl("view:auto_disable") \
        or self.verify_acl("edit:auto_disable"):
            lines.append('AUTO_DISABLE="%s"' % self.auto_disable_time)
            lines.append('UNUSED_DISABLE="%s"' % self.unused_disable)
        else:
            lines.append('AUTO_DISABLE=""')
            lines.append('UNUSED_DISABLE=""')

        if self.verify_acl("view:extension") \
        or self.verify_acl("add:extension") \
        or self.verify_acl("remove:extension"):
            lines.append('EXTENSIONS="%s"' % ",".join(self.extensions))
        else:
            lines.append('EXTENSIONS=""')

        if self.realm:
            lines.append('REALM="%s"' % self.realm)
        if self.site:
            lines.append('SITE="%s"' % self.site)

        if self.unit:
            lines.append('UNIT="%s"' % self.unit)

        if self.secret:
            if self.verify_acl("view_all:secret"):
                lines.append('SECRET="%s"' % self.secret)
            else:
                lines.append('SECRET=""')

        if self.cert:
            if self.verify_acl("view:cert") \
            or self.verify_acl("edit:cert") \
            or self.verify_acl("view_public"):
                lines.append('CERT="%s"' % self.cert)
            else:
                lines.append('CERT=""')

        # Include config lines from child class.
        if config_lines:
            lines += config_lines

        if self.acl_inheritance_enabled != None:
            if self.verify_acl("view:acl_inheritance") \
            or self.verify_acl("enable:acl_inheritance") \
            or self.verify_acl("disable:acl_inheritance"):
                lines.append('ACL_INHERITANCE_ENABLED="%s"'
                            % self.acl_inheritance_enabled)
            else:
                lines.append('ACL_INHERITANCE_ENABLED=""')

        pol_list = []
        for x in self.policies:
            p = backend.get_object(object_type="policy", uuid=x)
            if p:
                pol_list.append(p.name)
            else:
                pol_list.append(x)

        policies = ",".join(pol_list)
        if self.verify_acl("view:policy") \
        or self.verify_acl("add:policy") \
        or self.verify_acl("remove:policy"):
            lines.append('POLICIES="%s"' % policies)
        else:
            lines.append('POLICIES=""')

        policy_options = {}
        for uuid in self.policy_options:
            policy = backend.get_object(object_type="policy", uuid=uuid)
            # Skip orphan policies.
            if not policy:
                continue
            policy_options[policy.name] = self.policy_options[uuid]
        lines.append('POLICY_OPTIONS="%s"' % policy_options)

        if self.signatures:
            signatures = []
            for uuid in self.signatures:
                user = backend.get_object(object_type="user", uuid=uuid)
                if user:
                    username = user.name
                else:
                    username = uuid
                for sign_id in self.signatures[uuid]:
                    signature = self.load_sign(uuid, sign_id)
                    sign_info = signature.get_sign_info()
                    sign_info = sign_info['tags']
                    sign_info = ", ".join(sign_info)
                    x = "%s:[%s]" % (username, sign_info)
                    signatures.append(x)
            lines.append('SIGNATURES="%s"' % ",".join(signatures))

        resolver = ""
        if self.verify_acl("view:resolver"):
            if self.resolver:
                r = backend.get_object(object_type="resolver",
                                        uuid=self.resolver)
                if r:
                    resolver = r.name
        lines.append('RESOLVER="%s"' % resolver)

        resolver_key = ""
        if self.verify_acl("view:resolver_key"):
            if self.resolver_key:
                resolver_key = self.resolver_key
        lines.append('RESOLVER_KEY="%s"' % resolver_key)

        resolver_checksum = ""
        if self.verify_acl("view:resolver_checksum"):
            if self.resolver_checksum:
                resolver_checksum = self.resolver_checksum
        lines.append('RESOLVER_CHECKSUM="%s"' % resolver_checksum)

        config_params = ""
        if self.verify_acl("view:config") \
        or self.verify_acl("add:config") \
        or self.verify_acl("del:config") \
        or self.verify_acl("edit:config"):
            if self.config_params:
                config_params = self.config_params
        lines.append('CONFIG_PARAMS="%s"' % config_params)


        if self.verify_acl("view:description") \
        or self.verify_acl("edit:description"):
            lines.append('DESCRIPTION="%s"' % self.description)
        else:
            lines.append('DESCRIPTION=""')

        origin = backend.get_object(uuid=self.origin)
        if not origin:
            origin = self.origin_cache
        lines.append('ORIGIN="%s"' % origin)
        lines.append('CHECKSUM="%s"' % self.checksum)
        lines.append('SYNC_CHECKSUM="%s"' % self.sync_checksum)

        creator = ""
        if self.creator:
            if self.verify_acl("view:creator"):
                if self.creator:
                    for x in config.tree_object_types:
                        creator = backend.get_oid(object_type=x,
                                                uuid=self.creator)
                        if creator:
                            break
                if not creator:
                    if self.creator_cache:
                        creator = "%s (deleted)" % self.creator_cache
                    else:
                        creator = "Unknown"
        lines.append('CREATOR="%s"' % creator)

        create_time = ""
        if self.create_time:
            if self.verify_acl("view:create_time"):
                create_time = datetime.datetime.fromtimestamp(self.create_time)
        lines.append('CREATE_TIME="%s"' % create_time)

        last_modified = ""
        if self.last_modified:
            if self.verify_acl("view:last_modified"):
                last_modified = datetime.datetime.fromtimestamp(self.last_modified)
        lines.append('LAST_MODIFIED="%s"' % last_modified)

        if self.track_last_used:
            last_used = ""
            if self.verify_acl("view:last_used"):
                last_used = self.get_last_used_time(return_type="date")
            lines.append('LAST_USED="%s"' % last_used)

        output = ""
        count = 0
        for line in lines:
            count += 1
            if count == len(lines):
                output_line = str(line)
            else:
                output_line = str(line + "\n")
            output += str(output_line)

        return callback.ok(output)

class OTPmeClientObject(OTPmeObject):
    """ OTPme client object class. """
    def __init__(self, *args, **kwargs):
        self.logins_limited = False
        # Call parent class init.
        super(OTPmeClientObject, self).__init__(*args, **kwargs)

    def _get_object_config(self, object_config=None):
        """ Get object config dict """
        base_config = {
                        'LOGINS_LIMITED'       : {
                                                        'var_name'  : 'logins_limited',
                                                        'type'      : bool,
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

        return _object_config

    def add(self, *args, **kwargs):
        """ Add object. """
        self.update_index('logins_limited', self.logins_limited)
        return super(OTPmeClientObject, self).add(*args, **kwargs)

    @check_acls(['limit_logins'])
    @object_lock()
    def limit_logins(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Limit logins. """
        if self.logins_limited:
            return callback.error(_("Logins already limited."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("limit_logins",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.logins_limited = True
        self.update_index('logins_limited', self.logins_limited)
        return self._cache(callback=callback)

    @check_acls(['unlimit_logins'])
    @object_lock()
    def unlimit_logins(self, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Unlimit logins. """
        if not self.logins_limited:
            return callback.error(_("Logins already unlimited."))
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("unlimit_logins",
                                callback=callback,
                                _caller=_caller)
            except Exception as e:
                return callback.error()
        self.logins_limited = False
        self.update_index('logins_limited', self.logins_limited)
        return self._cache(callback=callback)

    def authorize_token(self, token, login_interface=None):
        """
        Check if given token is allowed to login to this host/node/client.
        """
        success_policy_types = []
        login_interface_valid_by = None
        login_interface_neg = "-%s" % login_interface

        if self.type != "client" \
        and self.type != "node" \
        and self.type != "host":
            msg = (_("Invalid object type: %s" % self.type))
            raise OTPmeException(msg)

        if token.is_admin():
            return True

        if self.type != "client":
            if login_interface is not None:
                if login_interface not in config.valid_token_login_interfaces:
                    msg = (_("Unknown login interface: %s") % login_interface)
                    raise LoginInterfaceException(msg)

        if self.logins_limited:
            if not self.is_assigned_token(token.uuid):
                msg = "Logins limited: Token not assigned: %s" % token
                raise LoginsLimited(msg)

        # Try to get valid login interfaces of this object.
        try:
            x_login_interface_opts = self.token_login_interfaces[token.uuid]
        except:
            x_login_interface_opts = []

        def split_opts(opts):
            """ Split login interface options in pos/neg (e.g. -gui). """
            pos_opts = []
            neg_otps = []
            for x in opts:
                if x.startswith("-"):
                    neg_otps.append(x)
                    continue
                pos_opts.append(x)
            return pos_opts, neg_otps

        # Check login interface config option of this object.
        if x_login_interface_opts:
            pos_opts, neg_otps = split_opts(x_login_interface_opts)
            if neg_otps and login_interface_neg in neg_otps:
                msg = (_("Access denied by login interface option: %s: %s")
                        % (self.oid, login_interface_neg))
                raise LoginInterfaceException(msg)
            if pos_opts and login_interface not in pos_opts:
                msg = (_("Access denied: Login interface not allowed: %s: %s")
                        % (self.oid, login_interface))
                raise LoginInterfaceException(msg)
            if pos_opts:
                login_interface_valid_by = self.oid

        # Check login interface config option of accessgroup.
        if not login_interface_valid_by:
            if self.type == "client":
                auth_access_group = self.access_group
            else:
                auth_access_group = config.realm_access_group

            # Get auth accessgroup.
            result = backend.search(object_type="accessgroup",
                                    attribute="name",
                                    value=auth_access_group,
                                    return_type="instance",
                                    realm=self.realm,
                                    site=self.site)
            if not result:
                msg = (_("Unable to find accessgroup: %s") % auth_access_group)
                raise OTPmeException(msg)
            auth_ag = result[0]

            # Get valid login interfaces from accessgroup.
            try:
                x_login_interface_opts = auth_ag.token_login_interfaces[token.uuid]
            except:
                x_login_interface_opts = []

            if x_login_interface_opts:
                pos_opts, neg_otps = split_opts(x_login_interface_opts)
                if neg_otps and login_interface_neg in neg_otps:
                    msg = (_("Access denied by login interface option: %s: %s")
                            % (auth_ag.oid, login_interface_neg))
                    raise LoginInterfaceException(msg)
                if pos_opts and login_interface not in pos_opts:
                    msg = (_("Access denied: Login interface not allowed: %s: %s")
                            % (auth_ag.oid, login_interface))
                    raise LoginInterfaceException(msg)
                if pos_opts:
                    login_interface_valid_by = auth_ag.oid

        # Check roles the token is a member of.
        token_assigned_roles = []
        token_roles = token.get_roles(return_type="instance")
        for role in token_roles:
            if not role.enabled:
                continue
            # Skip roles that are not assigned to this object.
            if not self.is_assigned_role(role.uuid):
                continue
            token_assigned_roles.append(role)
        if not login_interface_valid_by:
            for role in token_assigned_roles:
                if token.uuid not in role.token_login_interfaces:
                    continue
                x_login_interface_opts = role.token_login_interfaces[token.uuid]
                if not x_login_interface_opts:
                    continue
                pos_opts, neg_otps = split_opts(x_login_interface_opts)
                if neg_otps and login_interface_neg in neg_otps:
                    msg = (_("Access denied by login interface option: %s: %s")
                            % (role.oid, login_interface_neg))
                    raise LoginInterfaceException(msg)
                if pos_opts and login_interface not in pos_opts:
                    msg = (_("Access denied: Login interface not allowed: %s: %s")
                            % (role.oid, login_interface))
                    raise LoginInterfaceException(msg)
                if not pos_opts:
                    continue
                login_interface_valid_by = role.oid

        # Check roles directly assigned to this object.
        object_assigned_roles = []
        object_roles = self.get_roles(return_type="instance")
        for role in object_roles:
            if not role.enabled:
                continue
            # Skip roles the token is not a member of.
            if not role.is_assigned_token(token.uuid):
                continue
            object_assigned_roles.append(role)

        # Log some useful debug message.
        if login_interface_valid_by:
            msg = (_("Login interface valid by: %s: %s")
                % (login_interface_valid_by, login_interface))
            logger.debug(msg)

        # Check host/node/client policies.
        self.run_policies("authenticate")
        self.run_policies("authorize", token=token)

        # Check role policies.
        auth_roles = list(set(token_assigned_roles)
                        & set(object_assigned_roles))
        for role in auth_roles:
            success_policy_types += role.run_policies("authenticate")
            success_policy_types += role.run_policies("authorize",
                                                    token=token)

class OTPmeDataObject(OTPmeBaseObject):
    """ Generic OTPme object. """
    def __init__(self, object_id=None, realm=None,
        site=None, object_config=None, **kwargs):
        # Call parent class init.
        super(OTPmeDataObject, self).__init__(object_config=object_config, **kwargs)

        self._base_sync_fields = {
                    'node'  : {
                        'trusted'  : [
                            "UUID",
                            "REALM",
                            "SITE",
                            "TYPE",
                            "INDEX",
                            "CHECKSUM",
                            "SYNC_CHECKSUM",
                            "SALT",
                            "CREATE_TIME",
                            "LAST_MODIFIED",
                            ],
                        },
                    'host'  : {
                        'trusted'  : [
                            "UUID",
                            "REALM",
                            "SITE",
                            "TYPE",
                            "INDEX",
                            "CHECKSUM",
                            "SYNC_CHECKSUM",
                            "SALT",
                            "CREATE_TIME",
                            "LAST_MODIFIED",
                            ],
                        },
                    }

        # Set realm if given or use own.
        if realm:
            self.realm = realm
        else:
            self.realm = config.realm

        if config.realm:
            if self.realm != config.realm:
                r = backend.get_object(object_type="realm",
                                        name=self.realm)
                if not r:
                    msg = (_("Unknown realm '%s'.") % self.realm)
                    raise OTPmeException(msg)
                self.realm_uuid = r.uuid
            else:
                self.realm_uuid = config.realm_uuid

        if object_id:
            self.oid = object_id
            self.realm = object_id.realm
            self.site = object_id.site
        else:
            self.realm = realm
            self.site = site

        # Set our object ID.
        if not self.oid:
            self.set_oid()

        # Make sure we got a valid OID.
        self.oid.verify()

        # Set object config.
        self.object_config = ObjectConfig(self.oid)

        # Set site UUID if we have one.
        if self.site and config.site:
            if self.site != config.site:
                site_oid = oid.get(object_type="site",
                                    realm=self.realm,
                                    name=self.site)
                if not site_oid:
                    msg = (_("Unknown site '%s'.") % self.site)
                    raise OTPmeException(msg)
                site_uuid = backend.get_uuid(site_oid)
                self.site_uuid = site_uuid
            else:
                self.site_uuid = config.site_uuid

    def is_locked(self):
        """ Not available for data objects. """
        return False

    def exists(self, load_object=True, **kwargs):
        """ Check if object exists. """
        if not load_object:
            return backend.object_exists(self.oid)

        if self.object_config:
            object_exists = backend.object_exists(self.oid)
        else:
            try:
                object_exists = self._load()
            except Exception as e:
                msg = "Failed to read object config: %s: %s" % (self, e)
                logger.critical(msg, exc_info=True)
                raise

        if not object_exists:
            return False

        return True

    @object_lock(full_lock=True)
    def add(self, creator=None, resolver=None, extensions=[],
        enabled=True, verbose_level=0, callback=default_callback,
        write=True, **kwargs):
        """ Add the object. """
        if backend.object_exists(self.oid):
            msg = (_("%s%s already exists.")
                % (self.type[0].upper(), self.type[1:]))
            return callback.error(msg, exception=AlreadyExists)
        # Generate object UUID.
        self.uuid = stuff.gen_uuid()
        # Call base class add method.
        return super(OTPmeDataObject, self).add(verbose_level=verbose_level,
                                                callback=callback,
                                                **kwargs)

    def _get_base_config(self):
        """ Get base object config """
        base_config = {
            'UUID'                      : {
                                            'var_name'      : 'uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'TYPE'                      : {
                                            'var_name'      : 'type',
                                            'type'          : str,
                                            'required'      : True,
                                        },

            'REALM'                     : {
                                            'var_name'      : 'realm_uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'SITE'                      : {
                                            'var_name'      : 'site_uuid',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'INDEX'                     : {
                                            'var_name'      : 'index',
                                            'type'          : list,
                                            'required'      : False,
                                        },
            'CREATE_TIME'               : {
                                            'var_name'      : 'create_time',
                                            'type'          : int,
                                            'required'      : True,
                                        },

            'LAST_MODIFIED'             : {
                                            'var_name'      : 'last_modified',
                                            'type'          : int,
                                            'required'      : True,
                                        },
            'ORIGIN'                    : {
                                            'var_name'      : 'origin',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },
            }
        return base_config

    def is_special_object(self, **kwargs):
        """ Check if object is a base or internal object. """
        return False
