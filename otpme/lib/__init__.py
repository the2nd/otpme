# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

import os
import sys
import pwd
import grp
import resource

POSIX_MSGSIZE_MAX = "/proc/sys/fs/mqueue/msgsize_max"

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

def get_api_auth_token():
    """ Load given token as login token (API mode). """
    from otpme.lib import backend
    if not config.api_auth_token:
        msg = (_("No API login token given."))
        raise OTPmeException(msg)
    result = backend.search(realm=config.realm,
                        object_type="token",
                        attribute="rel_path",
                        value=config.api_auth_token,
                        return_type="instance")
    if not result:
        msg = (_("Unknown token: %s") % config.api_auth_token)
        raise OTPmeException(msg)
    token = result[0]
    return token

def set_realm_site():
    """ Set realm and site. """
    from otpme.lib import backend
    from otpme.lib.classes.site import Site
    from otpme.lib.classes.realm import Realm
    if not config.realm or not config.site:
        try:
            config.realm = config.host_data['realm']
            config.site = config.host_data['site']
        except:
            pass

    if not config.realm or not config.site:
        return_attrs = ['realm', 'site']
        result = backend.search(attribute="uuid",
                                value=config.uuid,
                                object_types=['host', 'node'],
                                return_attributes=return_attrs)
        if not result:
            msg = "Unknown host: %s" % config.uuid
            raise OTPmeException(msg)
        try:
            config.realm = result[config.uuid]['realm']
            config.site = result[config.uuid]['site']
        except KeyError:
            msg = "Host misses realm/site. Maybe corrupt index?"
            raise OTPmeException(msg)

    # Check if realm exists, set realm and realm master.
    try:
        _realm = Realm(name=config.realm)
    except Exception as e:
        msg = "Failed to load realm: %s" % e
        raise OTPmeException(msg)
    if not _realm.exists():
        msg = (_("Unknown realm: %s") % config.realm)
        raise OTPmeException(msg)

    config.set_realm(name=_realm.name, uuid=_realm.uuid)

    # Check if site exists and set it.
    if config.site:
        _site = Site(realm=config.realm, name=config.site)
        if not _site.exists():
            msg = (_("Unknown site: %s") % config.site)
            raise OTPmeException(msg)

        config.cluster_key = _site.cluster_key
        config.admin_token_uuid = _site.admin_token_uuid
        config.admin_role_uuid = _site.admin_role_uuid
        config.realm_users_group_uuid = _site.realm_users_group_uuid
        config.set_site(name=_site.name,
                        uuid=_site.uuid,
                        address=_site.address,
                        auth_fqdn=_site.auth_fqdn,
                        mgmt_fqdn=_site.mgmt_fqdn)
    else:
        if config.tool_name !=  "%s-site" % config.my_name.lower() \
        and config.tool_name != "%s-realm" % config.my_name.lower() \
        and config.tool_name != "%s-tool" % config.my_name.lower():
            msg = ("Missing site!")
            raise OTPmeException(msg)

def do_direct_init():
    """ Init OTPme via direct backend access. """
    # Register modules (e.g. OID schema of objects).
    from otpme.lib import host
    from otpme.lib import backend
    from otpme.lib.extensions import utils
    from otpme.lib.messages import error_message
    from otpme.lib.register import register_module
    register_module("otpme.lib.classes.otpme_object")
    register_module("otpme.lib.classes.realm")
    register_module("otpme.lib.classes.site")
    register_module("otpme.lib.classes.node")
    register_module("otpme.lib.classes.host")
    register_module("otpme.lib.classes.ca")
    register_module("otpme.lib.classes.user")
    register_module("otpme.lib.filetools")
    register_module("otpme.lib.host")
    # Initialize backend (e.g. set file permissions)
    init_file_dir_perms = False
    if config.use_api:
        init_file_dir_perms = True
    if config.realm_init:
        init_file_dir_perms = True
    if backend.is_available():
        init_file_dir_perms = True
    backend.init(init_file_dir_perms=init_file_dir_perms)

    # Load extension schemas.
    if config.use_api:
        utils.load_schemas()

    # Set realm/site.
    if not config.realm_init:
        try:
            set_realm_site()
        except Exception as e:
            error_message(e)
            config.raise_exception()
            sys.exit(1)

    # Update realm data cache file.
    config.update_realm_data()

    # Try to update our host data.
    try:
        host.update_data()
    except:
        config.raise_exception()
        raise

def do_hostd_init():
    """ Init OTPme by getting infos from hostd. """
    from otpme.lib import host
    #from otpme.lib import connections
    from otpme.lib.messages import error_message
    # Try to get realm data from users environment
    try:
        config.realm = os.environ['OTPME_REALM']
    except:
        pass
    try:
        config.realm_uuid = os.environ['OTPME_REALM_UUID']
    except:
        pass
    try:
        config.site = os.environ['OTPME_SITE']
    except:
        pass
    try:
        config.site_uuid = os.environ['OTPME_SITE_UUID']
    except:
        pass
    try:
        config.site_address = os.environ['OTPME_SITE_ADDRESS']
    except:
        pass

    ignore_missing = False
    if config.realm_init:
        ignore_missing = True

    # Try to set our host data.
    try:
        host.load_data(ignore_missing)
    except:
        config.raise_exception()
        raise

    # Get realm data from file.
    try:
        realm_data = config.get_realm_data()
    except Exception as e:
        msg = "Failed to get realm data: %s" % e
        error_message(msg)
        sys.exit(1)

    realm = realm_data['realm']
    realm_uuid = realm_data['realm_uuid']
    site = realm_data['site']
    site_uuid = realm_data['site_uuid']
    site_address = realm_data['site_address']
    site_auth_fqdn = realm_data['site_auth_fqdn']
    site_mgmt_fqdn = realm_data['site_mgmt_fqdn']

    config.set_realm(name=realm, uuid=realm_uuid)
    config.set_site(name=site,
                    uuid=site_uuid,
                    address=site_address,
                    auth_fqdn=site_auth_fqdn,
                    mgmt_fqdn=site_mgmt_fqdn)

def init_otpme(use_backend=None):
    """ Init OTPme. """
    from otpme.lib import backend
    #from otpme.lib.messages import message
    from otpme.lib.messages import error_message
    from otpme.lib.register import register_module
    register_module('otpme.lib.host')
    register_module('otpme.lib.cache')
    # FIXME: Migrate to register_at_fork() when on python3.
    #from otpme.lib.multiprocessing import atfork
    ## Register forking stuff.
    #os.register_at_fork(atfork)
    # Get logger.
    logger = config.logger

    try:
        pwd.getpwnam(config.user)
    except KeyError:
        error_message(_("Missing OTPme user: %s") % config.user)
        sys.exit(1)

    try:
        grp.getgrnam(config.group)
    except KeyError:
        error_message(_("Missing OTPme group: %s") % config.group)
        sys.exit(1)

    # Get posix messages queue max message size.
    if config._posix_msgsize_max == "auto":
        fd = open(POSIX_MSGSIZE_MAX, "r")
        try:
            x = fd.read()
        finally:
            fd.close()
        config.posix_msgsize_max = int(x)
    else:
        config.posix_msgsize_max = config._posix_msgsize_max

    # Set posix message queue size limit.
    try:
        resource.setrlimit(resource.RLIMIT_MSGQUEUE,
                        (config.rlimit_msgqueue,
                        config.rlimit_msgqueue))
    except ValueError:
        pass

    # Always need to use the backed in API mode but not on realm init.
    if config.use_api and not config.realm_init:
        if not backend.is_available():
            msg = (_("Cannot run in API mode: backend not available"))
            raise OTPmeException(msg)

    # Set default based on backend status.
    if use_backend is None:
        use_backend = False
        if backend.is_available():
            use_backend = True

    # Already set config parameter overrides!
    if config.use_backend is not None:
        use_backend = config.use_backend

    # Always need to use backend on realm init.
    if config.realm_init:
        use_backend = True

    # API mode always needs direct backend access.
    if config.use_api:
        use_backend = True

    # Set config parameter.
    config.use_backend = use_backend

    if not config.realm_init:
        if not os.path.exists(config.uuid_file):
            msg = (_("Host is not a realm member."))
            raise OTPmeException(msg)
        if config.use_backend:
            if not config.master_key:
                msg = (_("Missing master encryption key."))
                raise OTPmeException(msg)

    if use_backend:
        msg = "Doing direct init..."
        logger.debug(msg)
        do_direct_init()
    else:
        msg = "Doing hostd init..."
        logger.debug(msg)
        do_hostd_init()

    # Reload config after realm/site was set.
    config.reload()

    # Set config parameter.
    config.use_backend = use_backend

    # Handle API mode stuff.
    if config.use_api:
        config.use_backend = True
        # When running in API mode we may load a fake login token.
        if config.api_auth_token:
            register_module('otpme.lib.classes.user')
            config.auth_token = get_api_auth_token()
            config.auth_user = backend.get_object(object_type="user",
                                            uuid=config.auth_token.owner_uuid)
            config.debug_user = config.auth_user.name
            config.login_user = config.auth_user.name

    if not config.realm:
        if config.tool_name != "%s-realm" % config.my_name.lower() \
        and config.tool_name != "%s-tool" % config.my_name.lower():
            error_message(_("We do not have a realm. You must first init the "
                            "realm."))
            sys.exit(1)
