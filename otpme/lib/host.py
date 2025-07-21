# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import socket

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = []

def host_data_getter(self):
    """ Host data (e.g. cert, key, secret, CRLs etc.). """
    from otpme.lib.multiprocessing import host_data
    # Make sure host data is (re)loaded (e.g. if cache was down).
    try:
        host_data['name']
    except:
        try:
            update_data()
        except Exception as e:
            if not config.realm_join:
                msg = "Failed to load host data: %s" % e
                logger.critical(msg)
                config.raise_exception()
    return host_data

def register():
    multiprocessing.register_shared_dict("host_data")
    config.register_property(name="host_data", getx=host_data_getter)

def get_file_owner_group():
    # Permissions for cert/key files.
    file_mode = 0o640
    files = {
            config.ssl_cert_file        : file_mode,
            config.ssl_key_file         : file_mode,
            config.ssl_ca_file          : file_mode,
            config.ssl_site_cert_file   : file_mode,
            config.host_key_file        : 0o600,
            }
    # File owner.
    file_owner = config.user
    # Realm users group may not exist (e.g. on realm init)
    try:
        stuff.group_exists(config.realm_users_group)
        file_group = config.realm_users_group
    except:
        file_group = config.group
    return files, file_owner, file_group, file_mode

def set_ssl_file_perms():
    files, file_owner, file_group, file_mode = get_file_owner_group()
    filetools.ensure_fs_permissions(files=files,
                                    user=file_owner,
                                    group=file_group)


def update_ssl_files(host_cert=None, host_key=None,
    ca_data=None, site_cert=None, host_auth_key=None):
    """ Update SSL cert/key files. """
    # File owner/group.
    files, file_owner, file_group, file_mode = get_file_owner_group()

    # Create cert file if it does not exist.
    if host_cert:
        cert_dir = os.path.dirname(config.ssl_cert_file)
        if not os.path.exists(cert_dir):
            if not config.handle_files_dirs:
                msg = ("Unable to write SSL cert: No such file or directory: %s"
                        % cert_dir)
                raise OTPmeException(msg)
            try:
                filetools.create_dir(path=cert_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o775)
            except IOError as e:
                if e.errno != e.errno.EACCES:
                    raise
        try:
            filetools.create_file(path=config.ssl_cert_file,
                                    content=host_cert,
                                    user=file_owner,
                                    group=file_group,
                                    mode=file_mode)
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Create key file if it does not exist.
    if host_key:
        key_dir = os.path.dirname(config.ssl_key_file)
        if not os.path.exists(key_dir):
            if not config.handle_files_dirs:
                msg = ("Unable to write SSL key: No such file or directory: %s"
                        % key_dir)
                raise OTPmeException(msg)
            try:
                filetools.create_dir(path=key_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o775)
            except IOError as e:
                if e.errno != e.errno.EACCES:
                    raise
        try:
            filetools.create_file(path=config.ssl_key_file,
                                    content=host_key,
                                    user=file_owner,
                                    group=file_group,
                                    mode=file_mode)
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Create CA file if it does not exist.
    if ca_data:
        ca_data_dir = os.path.dirname(config.ssl_ca_file)
        if not os.path.exists(ca_data_dir):
            if not config.handle_files_dirs:
                msg = ("Unable to write SSL CA data: "
                        "No such file or directory: %s"
                        % ca_data_dir)
                raise OTPmeException(msg)
            try:
                filetools.create_dir(path=ca_data_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o775)
            except IOError as e:
                if e.errno != e.errno.EACCES:
                    raise
        try:
            filetools.create_file(path=config.ssl_ca_file,
                                        content=ca_data,
                                        user=file_owner,
                                        group=file_group,
                                        mode=file_mode)
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Create site cert file if it does not exist.
    if site_cert:
        site_cert_dir = os.path.dirname(config.ssl_site_cert_file)
        if not os.path.exists(site_cert_dir):
            if not config.handle_files_dirs:
                msg = ("Unable to write site certficate: "
                        "No such file or directory: %s"
                        % site_cert_dir)
                raise OTPmeException(msg)
            try:
                filetools.create_dir(path=site_cert_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o775)
            except IOError as e:
                if e.errno != e.errno.EACCES:
                    raise
        try:
            filetools.create_file(path=config.ssl_site_cert_file,
                                        content=site_cert,
                                        user=file_owner,
                                        group=file_group,
                                        mode=file_mode)
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Create host key file if it does not exist.
    if host_auth_key:
        key_dir = os.path.dirname(config.host_key_file)
        if not os.path.exists(key_dir):
            if not config.handle_files_dirs:
                msg = ("Unable to write host key: "
                        "No such file or directory: %s"
                        % key_dir)
                raise OTPmeException(msg)
            try:
                filetools.create_dir(path=key_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o775)
            except IOError as e:
                if e.errno != e.errno.EACCES:
                    raise
        try:
            filetools.create_file(path=config.host_key_file,
                                    content=host_auth_key,
                                    user=file_owner,
                                    group=file_group,
                                    mode=file_mode)
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Make sure files have sane permissions.
    set_ssl_file_perms()


def load_data(ignore_missing=False):
    """
    Update data of our host "host_data" dictionary as well
    as SSL cert/key files.
    """
    f_host_cert = None
    f_host_key = None
    f_ca_data = None
    f_site_cert = None
    f_host_auth_key = None

    if not config.realm_init:
        if not os.path.exists(config.uuid_file):
            raise Exception("Host is not a realm member.")

    # Try to read hosts SSL cert from file.
    if os.access(config.ssl_cert_file, os.R_OK):
        try:
            fd = open(config.ssl_cert_file, "r")
            f_host_cert = fd.read()
            fd.close()
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Try to read hosts SSL cert key from file.
    if os.access(config.ssl_key_file, os.R_OK):
        try:
            fd = open(config.ssl_key_file, "r")
            f_host_key = fd.read()
            fd.close()
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Try to read hosts CA data from file,
    if os.access(config.ssl_ca_file, os.R_OK):
        try:
            fd = open(config.ssl_ca_file, "r")
            f_ca_data = fd.read()
            fd.close()
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Try to read site cert from file,
    if os.access(config.ssl_site_cert_file, os.R_OK):
        try:
            fd = open(config.ssl_site_cert_file, "r")
            f_site_cert = fd.read()
            fd.close()
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise

    # Try to read hosts RSA private key from file.
    if os.access(config.host_key_file, os.R_OK):
        try:
            fd = open(config.host_key_file, "r")
            f_host_auth_key = fd.read()
            fd.close()
        except IOError as e:
            if e.errno != e.errno.EACCES:
                raise
    try:
        host_fqdn = socket.getfqdn()
    except Exception as e:
        msg = (_("Unable to get host FQDN: %s") % e)
        raise OTPmeException(msg)
    try:
        host_name = socket.gethostname()
    except Exception as e:
        msg = (_("Unable to get host FQDN: %s") % e)
        raise OTPmeException(msg)

    if not ignore_missing:
        if not f_host_cert:
            msg = (_("Unable to get host certificate from file: %s")
                    % config.ssl_cert_file)
            raise OTPmeException(msg)
        if not f_host_key:
            msg = (_("Unable to get host key from file: %s")
                    % config.ssl_key_file)
            raise OTPmeException(msg)
        if not f_ca_data:
            msg = (_("Unable to get host CA data from file: %s")
                    % config.ssl_ca_file)
            raise OTPmeException(msg)
        if not f_site_cert:
            msg = (_("Unable to get site certificate from file: %s")
                    % config.ssl_site_cert_file)
            raise OTPmeException(msg)

    try:
        multiprocessing.host_data['type']
    except:
        multiprocessing.host_data['type'] = None
    try:
        multiprocessing.host_data['realm']
    except:
        multiprocessing.host_data['realm'] = None
    try:
        multiprocessing.host_data['site']
    except:
        multiprocessing.host_data['site'] = None
    multiprocessing.host_data['name'] = host_name
    multiprocessing.host_data['fqdn'] = host_fqdn
    multiprocessing.host_data['site_cert'] = f_site_cert
    multiprocessing.host_data['cert'] = f_host_cert
    multiprocessing.host_data['key'] = f_host_key
    multiprocessing.host_data['ca_data'] = f_ca_data
    multiprocessing.host_data['auth_key'] = f_host_auth_key
    return

def update_data(host_cert=None, host_key=None,
    ca_data=None, site_cert=None, host_auth_key=None):
    """
    Update data of our host "host_data" dictionary as well
    as SSL cert/key files.
    """
    if not config.realm_init:
        if not os.path.exists(config.uuid_file):
            raise Exception("Host is not a realm member.")

    ignore_missing = False
    if config.realm_init:
        ignore_missing = True
    if config.realm_join:
        ignore_missing = True

    # Load host data.
    load_data(ignore_missing)
    # Get data from files.
    f_host_cert = multiprocessing.host_data['cert']
    f_host_key = multiprocessing.host_data['key']
    f_host_auth_key = multiprocessing.host_data['auth_key']
    f_ca_data = multiprocessing.host_data['ca_data']
    f_site_cert = multiprocessing.host_data['site_cert']

    # Update SSL cert file if needed.
    if host_cert is None:
        host_cert = f_host_cert

    # Update SSL key file if needed.
    if host_key is None:
        host_key = f_host_key

    # Update RSA key file if needed.
    if host_auth_key is None:
        host_auth_key = f_host_auth_key

    update_files = False
    if host_key:
        if host_key != f_host_key:
            update_files = True
    else:
        host_key = f_host_key

    if host_cert:
        if host_cert != f_host_cert:
            update_files = True
    else:
        host_cert = f_host_cert

    if ca_data:
        if ca_data != f_ca_data:
            update_files = True
    else:
        ca_data = f_ca_data

    if site_cert:
        if site_cert != f_site_cert:
            update_files = True
    else:
        site_cert = f_site_cert

    if host_auth_key:
        if host_auth_key != f_host_auth_key:
            update_files = True
    else:
        host_auth_key = f_host_auth_key

    if update_files:
        update_files = False
        update_ssl_files(host_cert=host_cert,
                        host_key=host_key,
                        ca_data=ca_data,
                        site_cert=site_cert,
                        host_auth_key=host_auth_key)

    if config.realm_init:
        multiprocessing.host_data['type'] = None
        return

    # Try to get host object from backend.
    myhost = None
    if config.uuid:
        for t in ['node', 'host']:
            myhost = backend.get_object(object_type=t, uuid=config.uuid)
            if myhost:
                break

    if not myhost:
        msg = (_("Don't know who i am :(. Please make sure %s points to the "
                "correct OTPme object UUID.") % config.uuid_file)
        raise OTPmeException(msg)
    if not myhost.name:
        msg = (_("Uuhh don't know my hostname. This is most likely a result of "
                "a broken object configuration."))
        raise OTPmeException(msg)
    if not myhost.type:
        msg = (_("Uuhh, '%s' does not have host type set. This is most likely "
                "a result of a broken object configuration.") % myhost.name)
        raise OTPmeException(msg)

    if host_cert != myhost.cert:
        update_ssl_files(host_cert=host_cert)

    if not host_cert:
        host_cert = myhost.cert
        update_ssl_files(host_cert=host_cert)

    myrealm = backend.get_object(object_type="realm", name=myhost.realm)
    if not myrealm:
        msg = (_("Realm '%s' does does not exists.") % myhost.realm)
        raise OTPmeException(msg)

    # Update SSL CA file if needed.
    if myrealm.ca_data:
        if myrealm.ca_data != ca_data:
            ca_data = myrealm.ca_data
            update_ssl_files(ca_data=ca_data)

    # Update site SSL cert file if needed.
    mysite = backend.get_object(object_type="site", uuid=myhost.site_uuid)
    if not mysite:
        raise Exception("Unknown site: %s" % myhost.site_uuid)
    if mysite.cert:
        if mysite.cert != site_cert:
            site_cert = mysite.cert
            update_ssl_files(site_cert=site_cert)

    # Make sure files have sane permissions.
    set_ssl_file_perms()

    host_name = myhost.name
    host_fqdn = myhost.fqdn
    host_type = myhost.type
    host_realm = myhost.realm
    host_site = myhost.site

    config.host_type = host_type

    # Update host data in config.
    multiprocessing.host_data['name'] = host_name
    multiprocessing.host_data['fqdn'] = host_fqdn
    multiprocessing.host_data['type'] = host_type
    multiprocessing.host_data['realm'] = host_realm
    multiprocessing.host_data['site'] = host_site
    multiprocessing.host_data['site_cert'] = site_cert
    multiprocessing.host_data['cert'] = host_cert
    multiprocessing.host_data['key'] = host_key
    multiprocessing.host_data['ca_data'] = ca_data
    multiprocessing.host_data['auth_key'] = host_auth_key
