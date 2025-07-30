# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import random as _random

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib import otpme_acl
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.classes.policy import Policy
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.unit import register_subtype_add_acl
from otpme.lib.classes.unit import register_subtype_del_acl

from otpme.lib.classes.policy \
            import get_acls \
            as _get_acls
from otpme.lib.classes.policy \
            import get_value_acls \
            as _get_value_acls
from otpme.lib.classes.policy \
            import get_default_acls \
            as _get_default_acls
from otpme.lib.classes.policy \
            import get_recursive_default_acls \
            as _get_recursive_default_acls

from otpme.lib.exceptions import *

LOCK_TYPE = "idrange"
logger = config.logger
default_callback = config.get_callback()

POLICY_TYPE = "idrange"
BASE_POLICY_NAME = "id_range"
REGISTER_BEFORE = ['otpme.lib.policy.defaultpolicies.defaultpolicies']
REGISTER_AFTER = []

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "idrange",
                            "id_check",
                            ],
            }

write_value_acls = {
                "add"      : [
                            "idrange",
                            ],
                "delete"    : [
                            "idrange",
                            ],
                "enable"    : [
                            "id_check",
                            ],
                "disable"   : [
                            "id_check",
                            ],
                }

default_acls = [
                'unit:add:policy:%s' % POLICY_TYPE,
                'unit:del:policy:%s' % POLICY_TYPE,
            ]

recursive_default_acls = default_acls

commands = {
    'add'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : 'add',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_id_range'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_id_range',
                    'args'              : ['id_range'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_id_range'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_id_range',
                    'args'              : ['id_range'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_id_check'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_id_check',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_id_check'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_id_check',
                    'job_type'          : 'thread',
                    },
                },
            },
    'enable_id_range_recheck'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_id_range_recheck',
                    'job_type'          : 'thread',
                    },
                },
            },
    'disable_id_range_recheck'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_id_range_recheck',
                    'job_type'          : 'thread',
                    },
                },
            },
    }

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_policy_read_acls, \
        otpme_policy_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_policy_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_policy_write_acls)
        return _read_acls, _write_acls
    otpme_policy_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_policy_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_policy_read_value_acls, \
        otpme_policy_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_policy_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(write_value_acls,
                                                        otpme_policy_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_policy_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_policy_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    policy_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, policy_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    policy_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                policy_recursive_default_acls)
    return _acls

def register():
    """ Registger policy type. """
    register_hooks()
    register_policy_type()
    register_policy_object()
    register_commands("policy",
                    commands,
                    sub_type=POLICY_TYPE,
                    sub_type_attribute="policy_type")
    locking.register_lock_type(LOCK_TYPE, module=__file__)
    policy_acl = 'policy:%s' % POLICY_TYPE
    register_subtype_add_acl(policy_acl)
    register_subtype_del_acl(policy_acl)

def register_hooks():
    config.register_auth_on_action_hook("policy", "add_id_range")
    config.register_auth_on_action_hook("policy", "del_id_range")

def register_policy_type():
    """ Register policy type. """
    config.register_sub_object_type("policy", POLICY_TYPE)

def register_policy_object():
    """ Registger policy object. """
    # Register base policy.
    config.register_base_object(object_type="policy",
                                name=BASE_POLICY_NAME,
                                stype=POLICY_TYPE)
    # Register policy as default policy for new objects.
    config.register_default_policy("site", BASE_POLICY_NAME)

class IdrangePolicy(Policy):
    """ Class that implements OTPme ID range policy. """
    def __init__(self, object_id=None, name=None,
    realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(IdrangePolicy, self).__init__(object_id=object_id,
                                                    realm=realm,
                                                    site=site,
                                                    name=name,
                                                    path=path,
                                                    **kwargs)
        # Set policy type.
        self.policy_type = POLICY_TYPE
        self.sub_type = POLICY_TYPE

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Verify new free IDs? This will result in slower processing but will
        # ensure an ID is not already used by an other object.
        self.verify_new_id = True
        # Check already used ID ranges for free numbers. May slow down finding of free IDs.
        self.recheck_id_ranges = False
        # Last assigned IDs.
        self.last_assigned_ids = {}

        # Set default values.
        self.hooks = {
                    'all'   : [
                            'get_next_free_id',
                            ],
                    }
        self.object_types = [
                    'realm',
                    'site',
                    'unit',
                    ]

        #self.id_ranges = {}

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "ID_RANGES",
                            "VERIFY_NEW_ID",
                            ],
                        },
                    'node'  : {
                        'untrusted'  : [
                            "ID_RANGES",
                            "VERIFY_NEW_ID",
                            ],
                        },
                    }

    # Needed to allow copy.deepcopy()!
    @property
    def idrange_re(self):
        # ID range format.
        idrange_re = re.compile('^[rs][:][0-9]*[-][0-9]*$')
        return idrange_re

    def _get_object_config(self):
        """ Merge policy config with config from parent class. """
        policy_config = {
            'ID_RANGES'                 : {
                                            'var_name'      : 'id_ranges',
                                            'type'          : dict,
                                            'required'      : False,
                                        },
            'VERIFY_NEW_ID'             : {
                                            'var_name'      : 'verify_new_id',
                                            'type'          : bool,
                                            'required'      : False,
                                        },
            'RECHECK_ID_RANGES'         : {
                                            'var_name'      : 'recheck_id_ranges',
                                            'type'          : bool,
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge policy configs.
        return Policy._get_object_config(self, policy_config=policy_config)

    def set_variables(self):
        """ Set instance variables """
        # Run parent class method that may override default values with those
        # read from config.
        Policy.set_variables(self)

    def test(self, force=False, verbose_level=0,
        _caller="API", callback=default_callback):
        """ Test the policy """
        return callback.ok(self.id_ranges)

    def handle_hook(self, hook_name, callback=default_callback, **kwargs):
        """ Handle policy hooks """
        if hook_name == "get_next_free_id":
            result = self.get_next_free_id(callback=callback, **kwargs)
            return result
        msg = (_("Unknown policy hook: %s") % hook_name)
        return callback.error(msg)

    @check_acls(['enable:id_check'])
    @object_lock()
    @backend.transaction
    def enable_id_check(self, callback=default_callback, **kwargs):
        """ Enable ID check. """
        if self.verify_new_id:
            msg = "ID check already enabled."
            return callback.error(msg)
        self.verify_new_id = True
        return self._cache(callback=callback)

    @check_acls(['disable:id_check'])
    @object_lock()
    @backend.transaction
    def disable_id_check(self, callback=default_callback, **kwargs):
        """ Disable ID check. """
        if not self.verify_new_id:
            msg = "ID check already disabled."
            return callback.error(msg)
        self.verify_new_id = False
        return self._cache(callback=callback)

    @check_acls(['enable:id_range_recheck'])
    @object_lock()
    @backend.transaction
    def enable_id_range_recheck(self, callback=default_callback, **kwargs):
        """ Enable ID range re-check. """
        if self.recheck_id_ranges:
            msg = "ID range re-check already enabled."
            return callback.error(msg)
        self.recheck_id_ranges = True
        return self._cache(callback=callback)

    @check_acls(['disable:id_range_recheck'])
    @object_lock()
    @backend.transaction
    def disable_id_range_recheck(self, callback=default_callback, **kwargs):
        """ Disable ID range re-check. """
        if not self.recheck_id_ranges:
            msg = "ID range re-check already disabled."
            return callback.error(msg)
        self.recheck_id_ranges = False
        return self._cache(callback=callback)

    def _lock_idrange_attribute(method):
        """
        Decorator to prevent race with other process when getting/adding
         "last assigend ID" objects.
        """
        def wrapper(self, *args, **kwargs):
            try:
                attribute = kwargs['attribute']
            except:
                attribute = args[1]
            try:
                callback = kwargs['callback']
            except:
                callback = None
            _lock = locking.acquire_lock(LOCK_TYPE, attribute, callback=callback)
            try:
                result = method(self, *args, **kwargs)
            finally:
                _lock.release_lock()
            return result
        return wrapper

    @_lock_idrange_attribute
    def get_free_ids(self, object_type, attribute,
        count=3, callback=default_callback, **kwargs):
        """ Return free IDs for given attribute """
        if not attribute in self.id_ranges:
            msg = (_("No range configured for attribute: %s")
                % attribute)
            return callback.error(msg, exception=self.policy_exception)

        free_ids = []
        last_assigned_id = None
        id_ranges = self.id_ranges[attribute]
        for x in id_ranges:
            try:
                r = x.split(":")[1]
                range_type = x.split(":")[0]
                range_start = int(r.split("-")[0])
                range_end = int(r.split("-")[1])
            except:
                msg = ("Invalid ID range: %s: %s" % (self.name, x))
                logger.warning(msg)
                continue

            random_range = False
            if range_type == "r":
                random_range = True

            # Get all used IDs.
            ldif_attribute = "ldif:%s" % attribute
            used_ids = backend.search(object_type=object_type,
                                        attribute=ldif_attribute,
                                        greater_than=-1,
                                        return_attributes=[ldif_attribute])
            used_ids += backend.search(object_type=object_type,
                                        attribute=ldif_attribute,
                                        greater_than=-1,
                                        return_attributes=[ldif_attribute],
                                        template=True)
            # Make sure IDs are int.
            used_ids = [int(x) for x in used_ids]
            # Get IDs of range.
            x_range = list(range(range_start, range_end+1))
            unused_ids = list(set(x_range) - set(used_ids))

            if random_range:
                while True:
                    if len(x_range) == 0:
                        break
                    free_id = _random.choice(x_range)
                    try:
                        x_range.remove(free_id)
                    except ValueError:
                        pass
                    free_ids.append(free_id)
                    if len(free_ids) == count:
                        break
            else:
                need_ids = count - len(free_ids)
                free_ids += unused_ids[0:need_ids]
                try:
                    x_last_id = sorted(free_ids)[-1]
                except IndexError:
                    x_last_id = None
                if x_last_id:
                    if last_assigned_id:
                        if x_last_id > last_assigned_id:
                            last_assigned_id = x_last_id
                    else:
                        last_assigned_id = x_last_id

            if len(free_ids) == count:
                break

        if len(free_ids) != count:
            msg = "Unable to find %s free IDs: %s" % (count, attribute)
            raise OTPmeException(msg)

        # For sequential ID ranges we need to remember the last
        # assigned ID.
        if last_assigned_id:
            self.last_assigned_ids[attribute] = last_assigned_id
            self._write(no_transaction=True, callback=callback)

        return free_ids

    @_lock_idrange_attribute
    def get_next_free_id(self, object_type, attribute,
        callback=default_callback, **kwargs):
        """ Return free ID for given attribute """
        if not attribute in self.id_ranges:
            msg = (_("No range configured for attribute: %s")
                % attribute)
            return callback.error(msg, exception=self.policy_exception)
        id_ranges = self.id_ranges[attribute]

        id_range_rechecked = False
        while True:
            errors = []
            new_id = None
            for x in id_ranges:
                try:
                    r = x.split(":")[1]
                    range_type = x.split(":")[0]
                    range_start = int(r.split("-")[0])
                    range_end = int(r.split("-")[1])
                except:
                    msg = ("Invalid ID range: %s: %s" % (self.name, x))
                    logger.warning(msg)
                    continue
                new_id = None
                start_id = None
                random_range = False
                restart_on_end = False
                if range_type == "r":
                    random_range = True
                # For sequentially ID ranges we have to get the last assigned ID
                # as start ID to improve performance of find_free_number().
                if not random_range:
                    last_assigend = self.get_last_assigned(idrange=x,
                                                        attribute=attribute,
                                                        callback=callback)
                    start_id = last_assigend + 1
                    # Make sure start ID is within ID range.
                    if start_id >= range_start and start_id <= range_end:
                        if not self.verify_new_id:
                            new_id = start_id
                            break
                    else:
                        # If the start ID is not from this range check remaining.
                        found_valid_range = False
                        for i in id_ranges:
                            try:
                                r = i.split(":")[1]
                                x_range_start = int(r.split("-")[0])
                                x_range_end = int(r.split("-")[1])
                            except:
                                msg = ("Invalid ID range: %s: %s" % (self.name, i))
                                logger.warning(msg)
                                continue
                            if start_id >= x_range_start and start_id <= x_range_end:
                                found_valid_range = True
                                break
                        # If we found a other valid range skip this range.
                        if found_valid_range:
                            continue
                        start_id = range_start
                        restart_on_end = True
                if self.verify_new_id or random_range or restart_on_end:
                    try:
                        ldif_attribute = "ldif:%s" % attribute
                        msg = ("Searching free ID for attribute: %s" % attribute)
                        callback.send(msg)
                        new_id = self.find_free_number(object_type=object_type,
                                                        attribute=ldif_attribute,
                                                        range_start=range_start,
                                                        range_end=range_end,
                                                        start_id=start_id,
                                                        restart_on_end=restart_on_end,
                                                        random=random_range)
                    except Exception as e:
                        errors.append(str(e))
                        continue
                # If we found a free ID break loop through ID ranges.
                if new_id:
                    break

            # If we found a free ID break loop.
            if new_id:
                break

            # If ID range re-check is enabled continue.
            if self.recheck_id_ranges:
                if not id_range_rechecked:
                    id_range_rechecked = True
                    continue

            # Without free ID throw exception.
            for x in errors:
                callback.send(x)
            msg = "Unable to find free ID: %s" % attribute
            raise OTPmeException(msg)

        # For non-random ID range we need to remember the last
        # assigned ID.
        if last_assigend != new_id:
            self.last_assigned_ids[attribute] = new_id
            self._write(no_transaction=True, callback=callback)

        msg = "Using %s: %s" % (attribute, new_id)
        callback.send(msg)

        return new_id

    def find_free_number(self, attribute, object_type, range_start=1,
        range_end=999999, start_id=None, restart_on_end=False, random=False):
        """ Find free number (e.g. uid/gid) for the given attribute. """
        # Get all used numbers.
        used_ids = backend.search(object_type=object_type,
                                    attribute=attribute,
                                    greater_than=-1,
                                    return_attributes=[attribute])
        used_ids += backend.search(object_type=object_type,
                                    attribute=attribute,
                                    greater_than=-1,
                                    return_attributes=[attribute],
                                    template=True)
        used_ids = [int(x) for x in used_ids]

        free_number = None
        if random:
            random_range = list(range(range_end, range_start+1))
            for x in used_ids:
                try:
                    random_range.remove(x)
                except ValueError:
                    pass
            if len(random_range) > 0:
                free_number = _random.choice(random_range)
        else:
            # If we got a start ID use it as start point within the given range.
            if start_id is None:
                number = range_start
            else:
                number = start_id
            while True:
                end_reached = False
                # If we reached the range end check if we have to restart the search.
                if number > range_end:
                    if restart_on_end:
                        restart_on_end = False
                        number = range_start
                    else:
                        end_reached = True

                if end_reached:
                    break

                if number not in used_ids:
                    free_number = number
                    break

                number += 1

        if free_number is None:
            msg = (_("No free number in range: %s: %s-%s")
                    % (attribute, range_start, range_end))
            raise OTPmeException(msg)
        return free_number

    def check_range_overlap(self, attribute, range_start, range_end):
        """ Check if given range overlaps with an existing policy. """
        id_policies = backend.search(object_type="policy",
                                attribute="policy_type",
                                value="idrange",
                                return_type="instance")
        overlap_attr = None
        overlap_policy = None
        overlap_range = False
        test_range = list(range(range_start, range_end+1))
        for x_policy in id_policies:
            for x_attr in x_policy.id_ranges:
                if x_attr != attribute:
                    continue
                x_ranges = x_policy.id_ranges[x_attr]
                for x in x_ranges:
                    x_range_split = x.split(":")[1]
                    x_range_start = int(x_range_split.split("-")[0])
                    x_range_end = int(x_range_split.split("-")[1])
                    found_overlap = False
                    if x_range_start in test_range:
                        found_overlap = True
                    if x_range_end in test_range:
                        found_overlap = True
                    if found_overlap:
                        overlap_range = x
                        overlap_policy = x_policy
                        overlap_attr = x_attr
                        break
        if overlap_range:
            msg = ("Detected range overlap: %s: %s: %s"
                    % (overlap_policy, overlap_attr, overlap_range))
            raise OverlapDetected(msg)

    @check_acls(['add:idrange'])
    @object_lock()
    @backend.transaction
    def add_id_range(self, id_range, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Add ID range. """
        if not id_range:
            return callback.error("Got empty ID range.")

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("add_id_range",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        for x in id_range.split(","):
            # Decode ID range.
            try:
                attribute = x.split(":")[0]
                idrange = ":".join(x.split(":")[1:])
                range_split = idrange.split(":")[1]
                range_start = int(range_split.split("-")[0])
                range_end = int(range_split.split("-")[1])
            except:
                msg = (_("Unable to read ID range: %s") % idrange)
                return callback.error(msg)
            # Check for valid ID range.
            if not self.idrange_re.match(idrange):
                msg = (_("Invalid ID range: %s") % idrange)
                return callback.error(msg)
            # Check if range already exists in this policy.
            if not attribute in self.id_ranges:
                self.id_ranges[attribute] = []
            if idrange in self.id_ranges[attribute]:
                return callback.error("ID range already exists.")
            # Check for overlapping ID range.
            try:
                self.check_range_overlap(attribute, range_start, range_end)
            except OverlapDetected as e:
                msg = str(e)
                return callback.error(msg)
            # Add new ID range.
            self.id_ranges[attribute].append(idrange)
        return self._cache(callback=callback)

    @check_acls(['delete:idrange'])
    @object_lock()
    @backend.transaction
    def del_id_range(self, id_range, run_policies=True,
        callback=default_callback, _caller="API", **kwargs):
        """ Delete ID range. """
        if not id_range:
            return callback.error("Got empty ID range.")

        try:
            attribute = id_range.split(":")[0]
            idrange = ":".join(id_range.split(":")[1:])
        except:
            msg = (_("Invalid value: %s") % id_range)
            return callback.error(msg)

        if not attribute in self.id_ranges:
            msg = (_("No ID range for attribute: %s") % attribute)
            return callback.error(msg)

        if not idrange in self.id_ranges[attribute]:
            msg = (_("ID range does not exist: %s") % idrange)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("del_id_range",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.id_ranges[attribute].remove(idrange)

        return self._cache(callback=callback)

    @backend.transaction
    def get_last_assigned(self, idrange, attribute,
        callback=default_callback, **kwargs):
        """ Get last assigend ID. """
        if attribute not in self.id_ranges:
            msg = (_("No range configured for attribute: %s")
                % attribute)
            return callback.error(msg, exception=self.policy_exception)
        try:
            last_id = self.last_assigned_ids[attribute]
        except KeyError:
            # Get range start.
            r = idrange.split(":")[1]
            range_start = int(r.split("-")[0])
            # By default we start with the first ID.
            last_id = range_start
        return last_id

    @object_lock(full_lock=True)
    def _add(self, callback=default_callback, **kwargs):
        """ Add a policy """
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show policy config. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []
        id_ranges = []
        if self.verify_acl("view:idrange") \
        or self.verify_acl("add:idrange") \
        or self.verify_acl("delete:idrange"):
            for attribute in self.id_ranges:
                for idrange in self.id_ranges[attribute]:
                    id_ranges.append("%s:%s" % (attribute, idrange))
        lines.append('ID_RANGES="%s"' % ",".join(id_ranges))

        if self.verify_acl("view:id_check") \
        or self.verify_acl("enable:id_check") \
        or self.verify_acl("disable:id_check"):
            lines.append('VERIFY_NEW_ID="%s"' % self.verify_new_id)

        return Policy.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        """ Show policy details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
