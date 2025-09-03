# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

class OTPmeACL(object):
    def __init__(self):
        pass

def check_acls(acls):
    """ Decorator to check ACLs in class methods. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            try:
                callback = f_kwargs['callback']
            except:
                callback = default_callback
            try:
                verify_acls = f_kwargs['verify_acls']
            except:
                verify_acls = True

            if verify_acls:
                access_granted = False
                for acl in acls:
                    if self.verify_acl(acl):
                        access_granted = True
                        break
                if not access_granted:
                    msg = ("Permission denied.")
                    return callback.error(msg, exception=PermissionDenied)

            # Call given class method.
            return f(self, *f_args, **f_kwargs)
        return wrapped
    return wrapper

def check_special_user():
    """ Decorator to check if special user method is called. """
    def wrapper(f, **kwargs):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            try:
                callback = f_kwargs['callback']
            except:
                callback = default_callback

            internal_users = config.get_internal_objects("user")
            if self.type == "user" and self.name in internal_users:
                msg = (_("Action disabled for special user: %s") % self.name)
                return callback.error(msg)

            # Call given class method.
            return f(self, *f_args, **f_kwargs)
        return wrapped
    return wrapper

def decode(acl):
    """ Decode ACL string. """
    default = False
    recursive = False
    acl_owner_type = None
    acl_owner_uuid = None
    acl_value = None

    if "::" in acl:
        msg = (_("Malformed ACL: %s") % acl)
        raise OTPmeException(msg)

    if acl.startswith(":") or acl.endswith(":"):
        msg = (_("Malformed ACL: %s") % acl)
        raise OTPmeException(msg)

    if acl.startswith("role") or acl.startswith("token"):
        # ACL owner type (role or token)
        acl_owner_type = acl.split(":")[0]
        # ACL owners UUID or resolved name/path
        x = acl.split(":")[1]
        if stuff.is_uuid(x):
            acl_owner_uuid = x
        else:
            if acl_owner_type == "role":
                # Role from other realm (e.g. /otpme.org/berlin/Role1)
                if x.startswith("/"):
                    object_realm = x.split("/")[0]
                    object_site = x.split("/")[1]
                    object_name = x.split("/")[2]
                else:
                    # Role from own realm (e.g. berlin/Role1)
                    object_realm = config.realm
                    object_site = x.split("/")[0]
                    object_name = x.split("/")[1]
                search_attr = "name"
                search_value = object_name
            if acl_owner_type == "token":
                # Token from other realm (e.g. /otpme.org/user1/token1)
                if x.startswith("/"):
                    object_realm = x.split("/")[0]
                    object_site = None
                    object_rel_path = "/".join(x.split("/")[1:])
                else:
                    # Token from own realm (e.g. user1/token1)
                    object_realm = config.realm
                    object_site = None
                    object_rel_path = x
                search_attr = "rel_path"
                search_value = object_rel_path

            result = backend.search(realm=object_realm,
                                    site=object_site,
                                    attribute=search_attr,
                                    value=search_value,
                                    object_type=acl_owner_type,
                                    return_type="uuid")
            if not result:
                msg = (_("Unable to find UUID for %s: %s")
                        % (acl_owner_type, x))
                raise OTPmeException(msg)

            acl_owner_uuid = result[0]

        acl = ":".join(acl.split(":")[2:])

    #logger.critical("Found malformed ACL: %s" % acl)
    x = acl.split(":")[0]

    if x.startswith("++"):
        recursive = True
    if x.startswith("+"):
        default = True

    if default:
        x = x.replace("+", "")

    # Check if ACL is an object ACL (e.g. ++user:edit).
    if x in config.tree_object_types:
        acl_object_type = x
        acl_name = acl.split(":")[1].replace("+", "")
        try:
            acl_value = acl.split(":")[2:]
            acl_value = ":".join(acl_value)
        except:
            pass
        try:
            _acl_value = acl.split(":")[2]
        except:
            _acl_value = None
        try:
            _acl_sub_value = acl.split(":")[3:]
            _acl_sub_value = ":".join(_acl_sub_value)
        except:
            _acl_sub_value = None
    else:
        acl_object_type = None
        acl_name = acl.split(":")[0].replace("+", "")
        try:
            acl_value = acl.split(":")[1:]
            acl_value = ":".join(acl_value)
        except:
            pass
        try:
            _acl_value = acl.split(":")[1]
        except:
            _acl_value = None
        try:
            _acl_sub_value = acl.split(":")[2:]
            _acl_sub_value = ":".join(_acl_sub_value)
        except:
            _acl_sub_value = None

    acl_name_re = re.compile('^[a-zA-Z0-9]+[a-zA-Z0-9_]*[a-zA-Z0-9]+$')
    if not acl_name_re.match(acl_name):
        msg = (_("Malformed ACL: %s") % acl)
        raise OTPmeException(msg)

    if acl_value:
        acl_value_re = re.compile('^[a-zA-Z0-9]+[a-zA-Z0-9:_]*[a-zA-Z0-9]+$')
        if not acl_value_re.match(acl_value):
            msg = (_("Malformed ACL value: %s") % acl)
            raise OTPmeException(msg)
        acl_apply_id = "%s:%s" % (acl_name, acl_value)
    else:
        acl_apply_id = acl_name

    # Get ACL ID.
    acl_id = ":".join(acl.split(":")[0:])
    # Build raw ACL.
    raw_acl = "%s:%s:%s" % (acl_owner_type, acl_owner_uuid, acl_id)

    _acl = OTPmeACL()

    _acl.default = default
    _acl.recursive = recursive
    _acl.owner_type = acl_owner_type
    _acl.owner_uuid = acl_owner_uuid
    _acl.object_type = acl_object_type
    _acl.name = acl_name
    _acl.value = acl_value
    _acl.id = acl_id
    _acl.apply_id = acl_apply_id
    _acl.raw = raw_acl
    _acl._value = _acl_value
    _acl._sub_value = _acl_sub_value

    return _acl

def merge_acls(list1, list2):
    """ Merge two ACL lists without duplicates. """
    new_list = list(set(list1 + list2))
    return new_list

def merge_value_acls(dict1, dict2):
    """ Merge two value ACL dicts/lists without duplicates. """
    if len(dict1) > len(dict2):
        iter_dict = dict1
        new_dict = dict(dict2)
    else:
        iter_dict = dict2
        new_dict = dict(dict1)

    for a in iter_dict:
        if not a in new_dict:
            new_dict[a] = []
        for v in iter_dict[a]:
            if not v in new_dict[a]:
                new_dict[a].append(v)
    return new_dict

def check_access(check_admin_user=True, check_admin_role=True, auth_token=None):
    """
    Check if we need objects ACLs to verify if access is
    allowed and return access status if no ACL check is needed.
    """
    need_acls = True
    access_granted = False

    if not auth_token:
        auth_token = config.auth_token

    # There may be no user/token we can check ACLs for when running in API mode.
    # So its not possible to do any ACL check and access should be granted.
    if config.use_api and not auth_token:
        need_acls = False
        access_granted = True
    elif not auth_token:
        # If the user is not authenticated we can not check any ACLs and access
        # should be denied.
        logger.warning("Access denied: User not authenticated")
        need_acls = False
    else:
        if check_admin_user:
            if auth_token.uuid == config.admin_token_uuid:
                # If the authenticated token is the admin token all access
                # should be granted and theres no need to check any ACL.
                need_acls = False
                access_granted = True

        if not access_granted:
            if check_admin_role:
                token_roles = auth_token.get_roles(return_type="uuid")
                if token_roles and config.admin_role_uuid in token_roles:
                    need_acls = False
                    access_granted = True

    return need_acls, access_granted

def access_granted(acl, object_id=None, uuid=None, check_admin_user=True,
    check_admin_role=True, auth_token=None):
    """ Check if the current user is allowd to access the given object. """
    if not object_id and not uuid:
        msg = ("Need at least 'object_id' or 'uuid'.")
        raise OTPmeException(msg)

    if not auth_token:
        auth_token = config.auth_token

    if not object_id:
        object_id = backend.get_oid(uuid, instance=True)

    if not uuid:
        uuid = backend.get_uuid(object_id)

    # Check if we can grant access without object ACLs.
    need_acls, access_granted = check_access(check_admin_user=check_admin_user,
                                            check_admin_role=check_admin_role,
                                            auth_token=auth_token)
    if need_acls:
        acl_list = None
        try:
            object_acls = backend.read_config(object_id=object_id)['ACLS']
            if object_acls:
                acl_list = object_acls.split(",")
        except:
            pass

        return verify(uuid=uuid,
                    acl_list=acl_list,
                    acl=acl,
                    auth_token=auth_token,
                    force_acl_check=True)
    else:
        return access_granted

    # This point should never be reached. But its saver to return "Failure" in
    # an authorization method if something goes wrong (e.g. a BUG) :)
    logger.critical("WARNING: You may have hit a BUG in acl.access_granted().")
    return False

def verify(uuid, acl_list, acl, force_acl_check=False, need_exact_acl=False,
    check_admin_user=True, check_admin_role=True, auth_token=None):
    """ Check if current user is authorized by the given ACL. """
    if not force_acl_check:
        if not auth_token:
            auth_token = config.auth_token
        need_acls, \
        access_granted = check_access(check_admin_user=check_admin_user,
                                        check_admin_role=check_admin_role,
                                        auth_token=auth_token)
        if not need_acls and access_granted:
            return True
        if not need_acls and not access_granted:
            return False

    if not acl_list:
        return False

    # Try to get ACL result from cache
    cached_acl_result = cache.get_acl(object_uuid=uuid,
                                    token_uuid=auth_token.uuid,
                                    acl=acl)
    if cached_acl_result is not None:
        return cached_acl_result

    # Get token roles.
    token_roles = auth_token.get_roles(return_type="uuid",
                                        recursive=True)

    # Check ACLs.
    access_granted = None
    for a in acl_list:
        access_granted = check_acl(acl=a, verify_acl=acl,
                                auth_token=auth_token,
                                token_roles=token_roles,
                                need_exact_acl=need_exact_acl)
        if access_granted is not None:
            break

    # If no ACL matches access must be denied.
    if access_granted is None:
        access_granted = False

    # Add ACL result to cache
    cache.add_acl(object_uuid=uuid,
                token_uuid=auth_token.uuid,
                acl=acl, status=access_granted)

    return access_granted

def check_acl(acl, verify_acl, token_roles, need_exact_acl=False, auth_token=None):
    """ Actually check the given ACL.

        view_public: View public object attributes (e.g. username, groupname...)
                     Public attributes those who are anonymously accessable via
                     LDAP or getent(1) for example.

        view:       View non-private object attributes (e.g. status or description)

        view_all:   View all object attributes including private ones (e.g. cert key)

    """
    if not auth_token:
        auth_token = config.auth_token

    requested_acl_name = verify_acl.split(":")[0]
    try:
        requested_acl_value = verify_acl.split(":")[1]
    except:
        requested_acl_value = None
    try:
        requested_acl_sub_value = ":".join(verify_acl.split(":")[2:])
    except:
        requested_acl_sub_value = None

    if requested_acl_sub_value:
        acl_check_value = "%s:%s" % (requested_acl_value,
                                    requested_acl_sub_value)
    else:
        acl_check_value = requested_acl_value

    acl_match = False
    acl_uuid = acl.split(":")[1]

    if auth_token.uuid == acl_uuid:
        acl_match = True

    for r in token_roles:
        if r == acl_uuid:
            acl_match = True

    if not acl_match:
        return None

    _acl = decode(acl)

    # Skip default ACLs
    if _acl.default:
        return None

    #print("VVVVVVVVVVVVVVVV", verify_acl, acl)
    # Skip not matching ACLs if need_exact_acl is set.
    if need_exact_acl:
        if _acl.name != requested_acl_name:
            return None
        if _acl.value != requested_acl_value:
            return None

    # ACL "all" means full access
    if _acl.name == "all":
        return True

    # If the current ACL has a value we have to do some more checks.
    if _acl.value:
        # Check if the requested ACL matches exactly.
        x_acl = "%s:%s" % (_acl.name, _acl.value)
        if x_acl == verify_acl:
            return True
        elif requested_acl_sub_value:
            if _acl.name == "view" and _acl.value == requested_acl_value:
                # The statement above covers the following:
                # "view:attribute" covers e.g. "view:attribute:uidNumber"
                return True
        elif requested_acl_name == "view_public" \
        and (_acl.name == "view" or _acl.name == "view_all") \
        and _acl.value == acl_check_value:
            # The statement above covers the following:
            # "view:value" and "view_all:value" also
            # covers "view_public:value" permission.
            return True
        elif requested_acl_name == "view_all" \
        and (_acl.name == "view" or _acl.name == "view_all") \
        and _acl.value == acl_check_value:
            # The statement above covers the following:
            # "view:value" also covers "view_all:value" permission.
            return True
    else:
        # If the current ACL does not have a
        # value checks are less complicated.
        if requested_acl_name == "view" and _acl.name == "view_all":
            # The statement above covers the following:
            # "view_all" also covers "view" permission.
            return True
        elif requested_acl_name == "view_public" \
        and (_acl.name == "view_all" or _acl.name == "view"):
            # The statement above covers the following:
            # "view_all" and "view" also covers "view_public" permission.
            return True
        elif requested_acl_name == _acl.name:
            # Check if the requested ACL matches exactly
            return True

    # Default should be None -> ACL does not match
    return None

def get_raw_acls(acls, token):
    """ Build RAW ACLs. """
    acl_list = []
    for acl in acls:
        # Decode ACL.
        acl_name = acl.split(":")[0]
        try:
            acl_value = acl.split(":")[1]
        except:
            acl_value = None
        try:
            acl_sub_value = ":".join(acl.split(":")[2:])
        except:
            acl_sub_value = None

        # Add the "all" ACL.
        acl_list.append("all")

        # Add complete ACL to check for.
        acl_list.append(acl)

        # Add "edit" ACL.
        if acl_name == "edit" and acl_value  is None:
            acl_list.append("edit")
            acl_list.append("edit:attribute")

        # Add "view" ACL.
        if acl_name == "view" and acl_value  is None:
            acl_list.append("view")
            acl_list.append("view_all")
            acl_list.append("view:attribute")
            acl_list.append("view_all:attribute")

        # Add value ACLs.
        if acl_name == "view":
            if acl_value:
                x = "view:%s" % (acl_value)
                acl_list.append(x)
            if acl_sub_value:
                x = "view:%s:%s" % (acl_value, acl_sub_value)
                acl_list.append(x)
        if acl_name == "edit":
            if acl_value:
                x = "edit:%s" % (acl_value)
                acl_list.append(x)
            if acl_sub_value:
                x = "edit:%s:%s" % (acl_value, acl_sub_value)
                acl_list.append(x)

        # For value ACL checks with sub value
        # (e.g. view:attribute:ldif:uidNumber) we also need to get all
        # objects with the "view:attribute" ACL.
        if acl_sub_value:
            x = "%s:%s" % (acl_name, acl_value)
            acl_list.append(x)

        # For value ACL checks (e.g. view:description) we also need to get
        # all objects with the "view" ACL.
        if acl_value:
            acl_list.append(acl_name)

        # When checking for view_public ACLs we also need to get objects
        # with "view" and "view_all" ACLs.
        if acl_name == "view_public":
            acl_list.append("view")
            acl_list.append("view_all")
            acl_list.append("view_public")
            acl_list.append("view:attribute")
            acl_list.append("view_all:attribute")
            acl_list.append("view_public:attribute")
            if acl_value:
                x = "view:%s" % (acl_value)
                acl_list.append(x)
                x = "view_all:%s" % (acl_value)
                acl_list.append(x)
            if acl_sub_value:
                x = "view:%s:%s" % (acl_value, acl_sub_value)
                acl_list.append(x)
                x = "view_all:%s:%s" % (acl_value, acl_sub_value)
                acl_list.append(x)

        # When checking for view_all:* ACLs we also need to get objects
        # with "view:*" ACLs.
        if acl_name == "view_all":
            if acl_value:
                x = "view:%s" % (acl_value)
                acl_list.append(x)
            if acl_sub_value:
                x = "view:%s:%s" % (acl_value, acl_sub_value)
                acl_list.append(x)

    # We also have to build raw ACLs for each role the token is in.
    token_roles = token.get_roles(return_type="instance", recursive=True)

    raw_acls = []
    for acl in acl_list:
        # We need to get objects that have a matching ACL of the auth token.
        token_acl = "token:%s:%s" % (token.uuid, acl)
        raw_acls.append(token_acl)
        # And we need to check for ACLs of any of the token roles.
        for r in token_roles:
            role_acl = "role:%s:%s" % (r.uuid, acl)
            raw_acls.append(role_acl)

    # Build raw ACL lists.
    raw_acls = sorted(list(set(raw_acls)))
    return raw_acls
