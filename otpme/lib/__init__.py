# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
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

# Must be loaded by executing script (e.g. command.py).
config = None

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
    _realm = Realm(name=config.realm)
    if not _realm.exists():
        msg = (_("Unknown realm: %s") % config.realm)
        raise OTPmeException(msg)

    config.set_realm(name=_realm.name, uuid=_realm.uuid)
    #realm_master = backend.get_object(object_type="site",
    #                                uuid=_realm.master)
    #if realm_master:
    #    config.set_realm_master(name=realm_master.name,
    #                            uuid=realm_master.uuid,
    #                            address=realm_master.address)

    # Check if site exists and set it.
    if config.site:
        _site = Site(realm=config.realm, name=config.site)
        if not _site.exists():
            msg = (_("Unknown site: %s") % config.site)
            raise OTPmeException(msg)

        config.admin_token_uuid = _site.admin_token_uuid
        config.admin_role_uuid = _site.admin_role_uuid
        config.set_site(name=_site.name,
                        uuid=_site.uuid,
                        address=_site.address)
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
            config.raise_exception()
            error_message(e)
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
    site_fqdn = realm_data['site_fqdn']
    site_address = realm_data['site_address']

    config.set_realm(name=realm, uuid=realm_uuid)
    config.set_site(name=site,
                    uuid=site_uuid,
                    address=site_address,
                    fqdn=site_fqdn)

    ## Set node stuff.
    #try:
    #    host_type = config.host_data['type']
    #except:
    #    host_type = None
    #need_hostd_conn = False
    #set_site_master = False
    #set_realm_master = False
    #if host_type == "node" and not config.site_master_uuid:
    #    set_site_master = True
    #if host_type == "node" and not config.realm_master_uuid:
    #    set_realm_master = True

    #if need_hostd_conn:
    #    try:
    #        hostd_conn = connections.get("hostd")
    #    except Exception as e:
    #        config.raise_exception()
    #        msg = (_("Unable to get connection to hostd: %s") % e)
    #        raise OTPmeException(msg)

    #if set_site_master:
    #    # Try to get master node UUID.
    #    status, \
    #    status_code, \
    #    reply =  hostd_conn.send("get_site_master_uuid")
    #    if status:
    #        site_master_uuid = reply
    #    # Try to get master node name.
    #    status, \
    #    status_code, \
    #    reply =  hostd_conn.send("get_site_master_name")
    #    if status:
    #        site_master_name = reply
    #        config.set_site_master(name=site_master_name,
    #                                uuid=site_master_uuid)

    #if set_realm_master:
    #    realm_master_uuid = None
    #    realm_master_name = None
    #    realm_master_address = None
    #    # Try to get master node UUID.
    #    status, \
    #    status_code, \
    #    reply =  hostd_conn.send("get_realm_master_uuid")
    #    if status:
    #        realm_master_uuid = reply
    #    # Try to get master node name.
    #    status, \
    #    status_code, \
    #    reply =  hostd_conn.send("get_realm_master_name")
    #    if status:
    #        realm_master_name = reply
    #    # Try to get master node address.
    #    status, \
    #    status_code, \
    #    reply =  hostd_conn.send("get_realm_master_address")
    #    if status:
    #        realm_master_address = reply

    #    if realm_master_uuid and realm_master_name and realm_master_address:
    #        config.set_realm_master(name=realm_master_name,
    #                                uuid=realm_master_uuid,
    #                                address=realm_master_address)

def init_otpme(use_backend=None):
    """ Init OTPme. """
    from otpme.lib import backend
    #from otpme.lib.messages import message
    from otpme.lib.messages import error_message
    from otpme.lib.register import register_module
    register_module('otpme.lib.host')
    register_module('otpme.lib.cache')
    register_module('otpme.lib.classes.user')
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
    if config.system_user() == "root":
        resource.setrlimit(resource.RLIMIT_MSGQUEUE,
                        (config.rlimit_msgqueue,
                        config.rlimit_msgqueue))

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
            config.auth_token = get_api_auth_token()
            config.auth_user = backend.get_object(object_type="user",
                                            uuid=config.auth_token.owner_uuid)
            config.debug_user = config.auth_user.name
            config.login_user = config.auth_user.name

    if not config.realm:
        if config.tool_name != "%s-realm" % config.my_name.lower() \
        and config.tool_name != "%s-tool" % config.my_name.lower():
            error_message(_("We do not have a realm. You must first init the own "
                            "realm."))
            sys.exit(1)

    # FIXME: does it make sense to get a global command handler when not running as daemon?
    #if not config.daemon_mode:
    #    from otpme.lib.classes.command_handler import CommandHandler
    #    config.command_handler = CommandHandler()
