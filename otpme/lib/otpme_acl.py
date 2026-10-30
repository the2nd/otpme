# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.audit import emit_audit
from otpme.lib.cache import decode_acl_cache

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

class OTPmeACL(object):
    def __init__(self):
        pass

def acl_object_name(o):
    """ An object as a refusal names it: its type and its path. """
    o_type = getattr(o, 'type', None) or o.__class__.__name__
    o_name = getattr(o, 'rel_path', None) or getattr(o, 'name', None)
    return f"{o_type} {o_name}"

def denied_msg(o, acls, others=None):
    """ The message for a refusal for want of an ACL.

    It names what would have done: any of <acls> on <o>, and each
    (object, acls) of <others>, e.g. delete:object on a group or
    delete:group on its unit. "Permission denied." alone left the user
    to guess. The ACLs are no secret, otpme-acls(7) lists them, and a
    refusal says the object is there anyway.
    """
    if isinstance(acls, str):
        acls = [acls]
    ways = [_(" or ").join(acls)]
    for x_object, x_acls in others or []:
        if isinstance(x_acls, str):
            x_acls = [x_acls]
        way = _("{acls} on {object}")
        way = way.format(acls=_(" or ").join(x_acls),
                        object=acl_object_name(x_object))
        ways.append(way)
    msg = _("Permission denied: {object}: needs {acls}")
    msg = msg.format(object=acl_object_name(o), acls=_(" or ").join(ways))
    return msg

def check_acls(acls, need_exact_acl=False):
    """ Decorator to check ACLs in class methods.

    need_exact_acl: require the ACL to be granted verbatim, so a value-less
    ACL of the same name does not cover it (a plain "enable" must not
    imply "enable:admin_access").
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            try:
                callback = f_kwargs['callback']
            except Exception:
                callback = default_callback
            try:
                verify_acls = f_kwargs['verify_acls']
            except Exception:
                verify_acls = True
            try:
                verify_acls_only = f_kwargs['verify_acls_only']
            except Exception:
                verify_acls_only = False

            if verify_acls_only:
                verify_acls = True

            if verify_acls:
                access_granted = False
                for acl in acls:
                    acl_status = self.verify_acl(acl,
                                    need_exact_acl=need_exact_acl)
                    if not acl_status:
                        continue
                    access_granted = True
                    break
                if not access_granted:
                    actor = None
                    try:
                        if config.auth_token:
                            actor = config.auth_token.rel_path
                    except Exception:
                        pass
                    obj_type = getattr(self, 'type', None) \
                            or self.__class__.__name__
                    obj_name = getattr(self, 'rel_path', None) \
                            or getattr(self, 'name', None)
                    emit_audit("AuthZ", "denied",
                               level='warning',
                               actor=actor,
                               object_type=obj_type,
                               object=obj_name,
                               method=f.__name__,
                               required_acls=','.join(acls))
                    msg = denied_msg(self, acls)
                    return callback.error(msg, exception=PermissionDenied)

            if verify_acls_only:
                msg = _("Permission granted.")
                return callback.ok(msg)

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
            except Exception:
                callback = default_callback

            internal_users = config.get_internal_objects("user")
            if self.type == "user" and self.name in internal_users:
                msg = _("Action disabled for special user: {name}")
                msg = msg.format(name=self.name)
                return callback.error(msg)

            # Call given class method.
            return f(self, *f_args, **f_kwargs)
        return wrapped
    return wrapper

@decode_acl_cache.cache_function()
def decode(acl):
    """ Decode ACL string. """
    default = False
    recursive = False
    acl_owner_type = None
    acl_owner_uuid = None
    acl_value = None

    if "::" in acl:
        msg = _("Malformed ACL: {acl}")
        msg = msg.format(acl=acl)
        raise OTPmeException(msg)

    if acl.startswith(":") or acl.endswith(":"):
        msg = _("Malformed ACL: {acl}")
        msg = msg.format(acl=acl)
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
                msg = _("Unable to find UUID for {acl_owner_type}: {x}")
                msg = msg.format(acl_owner_type=acl_owner_type, x=x)
                raise OTPmeException(msg)

            acl_owner_uuid = result[0]

        acl = ":".join(acl.split(":")[2:])

    #log_msg = _("Found malformed ACL: {}", log=True)[1]
    #log_msg = log_msg.format(acl)
    #logger.critical(log_msg)
    x = acl.split(":")[0]

    if x.startswith("++"):
        recursive = True
    if x.startswith("+"):
        default = True

    if default:
        x = x.replace("+", "")

    # An ACL group (e.g. ++@it-user-manager): grants what the group holds
    # for the type of the object it is on, see expand_aclgroups(). Given
    # by name like the owner above, kept by UUID.
    if x.startswith("@"):
        if ":" in acl:
            msg = _("Malformed ACL: {acl}")
            msg = msg.format(acl=acl)
            raise OTPmeException(msg)
        aclgroup_uuid = get_aclgroup_uuid(x[1:])
        acl_prefix = "+" * acl.count("+", 0, len(acl) - len(x))
        acl_id = f"{acl_prefix}@{aclgroup_uuid}"
        _acl = OTPmeACL()
        _acl.default = default
        _acl.recursive = recursive
        _acl.owner_type = acl_owner_type
        _acl.owner_uuid = acl_owner_uuid
        _acl.object_type = None
        _acl.name = f"@{aclgroup_uuid}"
        _acl.value = None
        _acl.id = acl_id
        _acl.apply_id = f"@{aclgroup_uuid}"
        _acl.raw = f"{acl_owner_type}:{acl_owner_uuid}:{acl_id}"
        _acl._value = None
        _acl._sub_value = None
        _acl.aclgroup_uuid = aclgroup_uuid
        return _acl

    # Check if ACL is an object ACL (e.g. ++user:edit).
    if x in config.tree_object_types:
        acl_object_type = x
        acl_name = acl.split(":")[1].replace("+", "")
        try:
            acl_value = acl.split(":")[2:]
            acl_value = ":".join(acl_value)
        except Exception:
            pass
        try:
            _acl_value = acl.split(":")[2]
        except Exception:
            _acl_value = None
        try:
            _acl_sub_value = acl.split(":")[3:]
            _acl_sub_value = ":".join(_acl_sub_value)
        except Exception:
            _acl_sub_value = None
    else:
        acl_object_type = None
        acl_name = acl.split(":")[0].replace("+", "")
        try:
            acl_value = acl.split(":")[1:]
            acl_value = ":".join(acl_value)
        except Exception:
            pass
        try:
            _acl_value = acl.split(":")[1]
        except Exception:
            _acl_value = None
        try:
            _acl_sub_value = acl.split(":")[2:]
            _acl_sub_value = ":".join(_acl_sub_value)
        except Exception:
            _acl_sub_value = None

    acl_name_re = re.compile('^[a-zA-Z0-9]+[a-zA-Z0-9_]*[a-zA-Z0-9]+$')
    if not acl_name_re.match(acl_name):
        msg = _("Malformed ACL: {acl}")
        msg = msg.format(acl=acl)
        raise OTPmeException(msg)

    if acl_value:
        acl_value_re = re.compile('^[a-zA-Z0-9]+[a-zA-Z0-9:_]*[a-zA-Z0-9]+$')
        if not acl_value_re.match(acl_value):
            msg = _("Malformed ACL value: {acl}")
            msg = msg.format(acl=acl)
            raise OTPmeException(msg)
        acl_apply_id = f"{acl_name}:{acl_value}"
    else:
        acl_apply_id = acl_name

    # Get ACL ID.
    acl_id = ":".join(acl.split(":")[0:])
    # Build raw ACL.
    raw_acl = f"{acl_owner_type}:{acl_owner_uuid}:{acl_id}"

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
    _acl.aclgroup_uuid = None

    return _acl

def get_aclgroup_uuid(aclgroup):
    """ The UUID of the ACL group given by UUID, by <name> on our site or
    by <site>/<name>. """
    if stuff.is_uuid(aclgroup):
        return aclgroup
    aclgroup_site = config.site
    aclgroup_name = aclgroup
    if "/" in aclgroup:
        aclgroup_site, aclgroup_name = aclgroup.split("/", 1)
    result = backend.search(object_type="aclgroup",
                            attribute="name",
                            value=aclgroup_name,
                            realm=config.realm,
                            site=aclgroup_site,
                            return_type="uuid")
    if not result:
        msg = _("Unknown ACL group: {aclgroup}")
        msg = msg.format(aclgroup=aclgroup)
        raise OTPmeException(msg)
    return result[0]

def resolve_aclgroup_acl(acl_id):
    """ An ACL ID as it is shown: an ACL group (@<uuid>, +@<uuid>,
    ++@<uuid>) by its name, <site>/<name> for one of another site, the
    way decode() takes it back. Any other ACL as it is. """
    prefix, sep, aclgroup_uuid = acl_id.partition("@")
    if not sep or prefix.strip("+"):
        return acl_id
    object_id = backend.get_oid(uuid=aclgroup_uuid,
                                object_type="aclgroup",
                                instance=True)
    if not object_id:
        return acl_id
    aclgroup_name = object_id.name
    if object_id.site != config.site:
        aclgroup_name = f"{object_id.site}/{aclgroup_name}"
    return f"{prefix}@{aclgroup_name}"

ACLGROUP_ATTRIBUTES = ['uuid', 'enabled', 'entry', 'aclgroup']

def get_aclgroup_acls(aclgroup_uuid, object_type):
    """ What the ACL group grants on an object of the given type: its
    entries for the type, and those of the groups it is a member of, and
    so on up. A disabled group grants nothing, and passes nothing on.
    Groups may come round to one seen before: every group counts once.

    Read from the index, so the search cache keeps it, and a write of an
    ACL group throws it away (backend.outdate_object()). """
    prefix = f"{object_type}:"
    acls = []
    seen = []
    result = backend.search(object_type="aclgroup",
                            attribute="uuid",
                            value=aclgroup_uuid,
                            return_attributes=ACLGROUP_ATTRIBUTES)
    while result:
        check_uuids = []
        for x_uuid in result:
            if x_uuid in seen:
                continue
            seen.append(x_uuid)
            x_data = result[x_uuid]
            try:
                x_enabled = x_data['enabled'][0]
            except Exception:
                x_enabled = False
            if not x_enabled:
                continue
            for x_entry in x_data.get('entry') or []:
                if not x_entry.startswith(prefix):
                    continue
                x_acl = x_entry[len(prefix):]
                if x_acl not in acls:
                    acls.append(x_acl)
            check_uuids.append(x_uuid)
        if not check_uuids:
            break
        # The groups these are members of.
        result = backend.search(object_type="aclgroup",
                                attribute="aclgroup",
                                values=check_uuids,
                                return_attributes=ACLGROUP_ATTRIBUTES)
    return acls

def get_entry_aclgroups(entries):
    """ The ACL groups that grant one of the given entries
    (<object_type>:<acl>): those that hold it, if enabled, and the
    enabled groups that are members of those, and so on down. The other
    way round of get_aclgroup_acls(), for a search by ACL. """
    aclgroups = []
    seen = []
    result = backend.search(object_type="aclgroup",
                            attribute="entry",
                            values=list(entries),
                            return_attributes=ACLGROUP_ATTRIBUTES)
    while result:
        member_uuids = []
        for x_uuid in result:
            if x_uuid in seen:
                continue
            seen.append(x_uuid)
            x_data = result[x_uuid]
            try:
                x_enabled = x_data['enabled'][0]
            except Exception:
                x_enabled = False
            if not x_enabled:
                continue
            aclgroups.append(x_uuid)
            for x_member in x_data.get('aclgroup') or []:
                if x_member not in seen:
                    member_uuids.append(x_member)
        if not member_uuids:
            break
        result = backend.search(object_type="aclgroup",
                                attribute="uuid",
                                values=member_uuids,
                                return_attributes=ACLGROUP_ATTRIBUTES)
    return aclgroups

def get_view_aclgroups(object_types):
    """ The ACL groups that grant a view or an edit ACL of some kind on
    one of the given object types, for a search that asks whether an
    object can be seen at all (see the LDAP server). """
    view_verbs = ("view", "view_all", "view_public", "edit")
    result = backend.search(object_type="aclgroup",
                            attribute="uuid",
                            value="*",
                            return_attributes=ACLGROUP_ATTRIBUTES)
    entries = set()
    for x_uuid in result:
        for x_entry in result[x_uuid].get('entry') or []:
            x_type, _sep, x_acl = x_entry.partition(":")
            if x_type not in object_types:
                continue
            if x_acl.split(":")[0] not in view_verbs:
                continue
            entries.add(x_entry)
    if not entries:
        return []
    return get_entry_aclgroups(entries)

def expand_aclgroups(acl_list, object_type):
    """ The given raw ACLs with each ACL group (owner:@<uuid>) replaced by
    what it grants on an object of the given type. A default one
    (owner:+@<uuid>, owner:++@<uuid>) stays as it is: it is handed down,
    and grants nothing on the object it is on. """
    expanded = []
    for raw_acl in acl_list:
        x_parts = raw_acl.split(":", 2)
        if len(x_parts) < 3 or not x_parts[2].startswith("@"):
            expanded.append(raw_acl)
            continue
        owner = f"{x_parts[0]}:{x_parts[1]}"
        for x_acl in get_aclgroup_acls(x_parts[2][1:], object_type):
            expanded.append(f"{owner}:{x_acl}")
    return expanded

def merge_acls(list1, list2):
    """ Merge two ACL lists without duplicates. """
    new_list = list(set(list1 + list2))
    return new_list

def merge_value_acls(dict1, dict2):
    """ Merge two value ACL dicts/lists without duplicates. """
    if len(dict1) > len(dict2):
        iter_dict = dict1
        new_dict = stuff.copy_object(dict2)
    else:
        iter_dict = dict2
        new_dict = stuff.copy_object(dict1)

    for a in iter_dict:
        if a not in new_dict:
            new_dict[a] = []
        for v in iter_dict[a]:
            if v not in new_dict[a]:
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
        log_msg = _("Access denied: User not authenticated", log=True)[1]
        logger.warning(log_msg)
        need_acls = False
    else:
        if check_admin_user:
            if auth_token.is_superuser():
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
        msg = _("Need at least 'object_id' or 'uuid'.")
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
        except Exception:
            pass

        return verify(uuid=uuid,
                    acl_list=acl_list,
                    acl=acl,
                    auth_token=auth_token,
                    force_acl_check=True,
                    object_type=object_id.object_type)
    else:
        return access_granted

    # This point should never be reached. But its saver to return "Failure" in
    # an authorization method if something goes wrong (e.g. a BUG) :)
    log_msg = _("WARNING: You may have hit a BUG in acl.access_granted().", log=True)[1]
    logger.critical(log_msg)
    return False

def verify(uuid, acl_list, acl, force_acl_check=False, need_exact_acl=False,
    check_admin_user=True, check_admin_role=True, auth_token=None,
    object_type=None):
    """ Check if current user is authorized by the given ACL.

    <object_type> is the type of the object, which says what an ACL group
    on it grants. Looked up where it is not given and needed. """
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

    # Put what the ACL groups grant in their place.
    if [x for x in acl_list if ":@" in x]:
        if object_type is None:
            object_id = backend.get_oid(uuid, instance=True)
            if object_id:
                object_type = object_id.object_type
        acl_list = expand_aclgroups(acl_list, object_type)

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
    except Exception:
        requested_acl_value = None
    try:
        requested_acl_sub_value = ":".join(verify_acl.split(":")[2:])
    except Exception:
        requested_acl_sub_value = None

    if requested_acl_sub_value:
        acl_check_value = f"{requested_acl_value}:{requested_acl_sub_value}"
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

    # ACL "all" means full access. Checked before need_exact_acl, which is
    # there to stop a value-less ACL from covering a more specific one of
    # the same name (a global "add" must not allow "add:unit"). "all" is
    # not that -- it is the deliberate full grant, and excluding it would
    # leave its holder unable to do things they may do everywhere else.
    if _acl.name == "all":
        return True

    # Skip not matching ACLs if need_exact_acl is set.
    if need_exact_acl:
        if _acl.name != requested_acl_name:
            return None
        if _acl.value != requested_acl_value:
            return None

    # If the current ACL has a value we have to do some more checks.
    if _acl.value:
        # Check if the requested ACL matches exactly.
        x_acl = f"{_acl.name}:{_acl.value}"
        if x_acl == verify_acl:
            return True
        elif requested_acl_sub_value:
            if _acl.name == requested_acl_name \
            and _acl.value == requested_acl_value:
                # The statement above covers the following:
                # "view:attribute" covers e.g. "view:attribute:uidNumber"
                # "set:config" covers e.g. "set:config:allow_temp_passwords"
                # The ACL name must match. Otherwise a read ACL like
                # "view:config" would cover a write request like
                # "set:config:vlan".
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

def get_raw_acls(acls, token, object_types=None):
    """ Build RAW ACLs.

    <object_types> are the types searched for: an ACL group on an object
    grants by the type of the object, so only with them the groups that
    grant one of the ACLs are found. """
    acl_list = []
    for acl in acls:
        # Decode ACL.
        acl_name = acl.split(":")[0]
        try:
            acl_value = acl.split(":")[1]
        except Exception:
            acl_value = None
        try:
            acl_sub_value = ":".join(acl.split(":")[2:])
        except Exception:
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
                x = f"view:{acl_value}"
                acl_list.append(x)
            if acl_sub_value:
                x = f"view:{acl_value}:{acl_sub_value}"
                acl_list.append(x)
        if acl_name == "edit":
            if acl_value:
                x = f"edit:{acl_value}"
                acl_list.append(x)
            if acl_sub_value:
                x = f"edit:{acl_value}:{acl_sub_value}"
                acl_list.append(x)

        # For value ACL checks with sub value
        # (e.g. view:attribute:ldif:uidNumber) we also need to get all
        # objects with the "view:attribute" ACL.
        if acl_sub_value:
            x = f"{acl_name}:{acl_value}"
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
                x = f"view:{acl_value}"
                acl_list.append(x)
                x = f"view_all:{acl_value}"
                acl_list.append(x)
            if acl_sub_value:
                x = f"view:{acl_value}:{acl_sub_value}"
                acl_list.append(x)
                x = f"view_all:{acl_value}:{acl_sub_value}"
                acl_list.append(x)

        # When checking for view_all:* ACLs we also need to get objects
        # with "view:*" ACLs.
        if acl_name == "view_all":
            if acl_value:
                x = f"view:{acl_value}"
                acl_list.append(x)
            if acl_sub_value:
                x = f"view:{acl_value}:{acl_sub_value}"
                acl_list.append(x)

    # And the ACL groups that grant one of them on the searched types.
    if object_types:
        entries = set()
        for x_type in object_types:
            for x_acl in acl_list:
                entries.add(f"{x_type}:{x_acl}")
        for x_uuid in get_entry_aclgroups(entries):
            acl_list.append(f"@{x_uuid}")

    # We also have to build raw ACLs for each role the token is in.
    token_roles = token.get_roles(return_type="instance", recursive=True)

    raw_acls = []
    for acl in acl_list:
        # We need to get objects that have a matching ACL of the auth token.
        token_acl = f"token:{token.uuid}:{acl}"
        raw_acls.append(token_acl)
        # And we need to check for ACLs of any of the token roles.
        for r in token_roles:
            role_acl = f"role:{r.uuid}:{acl}"
            raw_acls.append(role_acl)

    # Build raw ACL lists.
    raw_acls = sorted(list(set(raw_acls)))
    return raw_acls
