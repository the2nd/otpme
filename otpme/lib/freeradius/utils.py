# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import system_command

from otpme.lib.exceptions import *

# Get PYTHONPATH.
PYTHONPATH = os.path.dirname(__file__)
PYTHONPATH = os.path.dirname(PYTHONPATH)
PYTHONPATH = os.path.dirname(PYTHONPATH)
PYTHONPATH = os.path.dirname(PYTHONPATH)

freeradius_dir = os.path.join(config.run_dir, "freeradius")
freeradius_conf = os.path.join(freeradius_dir, "radiusd.conf")
freeradius_custom_conf = os.path.join(config.config_dir, "freeradius", "radiusd.conf")
freeradius_clients = os.path.join(freeradius_dir, "clients.conf")
freeradius_cert_file = "/var/run/otpme/freeradius/cert.pem"
freeradius_key_file = "/var/run/otpme/freeradius/key.pem"
freeradius_ca_cert_file = "/var/run/otpme/freeradius/ca.pem"
freeradius_pidfile = os.path.join(config.pidfile_dir, "freeradius.pid")

LOCK_TYPE = "freeradius"
locking.register_lock_type(LOCK_TYPE, module=__file__)

def get_user():
    """ The user and group FreeRADIUS runs as.

    With the Python module it is FREERADIUS_USER: the module asks hostd
    for the clients and sessions it needs. Without it every request runs
    otpme-auth, which reads the auth cache of the node, and that takes
    the OTPme user.
    """
    if config.use_radius_mod:
        return config.freeradius_user, config.freeradius_group
    return config.user, config.group

def get_log_dir():
    """ Where FreeRADIUS writes its log. """
    user, group = get_user()
    if user == config.user:
        return config.log_dir
    return config.freeradius_log_dir

def create_dirs():
    """ Make the config directory readable for FreeRADIUS and give it a
    log directory it can write. """
    user, group = get_user()
    if not os.path.exists(freeradius_dir):
        filetools.create_dir(freeradius_dir)
    # It holds the secrets of the clients and the RADIUS key: the OTPme
    # user writes, FreeRADIUS reads, nobody else.
    filetools.set_fs_ownership(freeradius_dir, user=config.user, group=group)
    filetools.set_fs_permissions(freeradius_dir, mode=0o750)
    log_dir = get_log_dir()
    if not os.path.exists(log_dir):
        filetools.create_dir(log_dir, user=user, group=group, mode=0o750)

def write_file(path, content):
    """ Write a file FreeRADIUS reads. """
    user, group = get_user()
    filetools.create_file(path,
                        content=content,
                        user=config.user,
                        group=group,
                        mode=0o640)
    # create_file() gives a file that is there already what it had, and
    # one from before FREERADIUS_USER is otpme:otpme 0660, which
    # FreeRADIUS could not read.
    filetools.set_fs_ownership(path, user=config.user, group=group)
    filetools.set_fs_permissions(path, mode=0o640)

# The clear-text password is handed to otpme-auth via the USER_PASSWORD
# environment variable, NOT via "%{User-Password}" argv substitution.
# FreeRADIUS 3.x's backtick-exec exports every request attribute as an
# env var (uppercased, "-" -> "_"), so User-Password is reachable as
# $USER_PASSWORD inside the fork without ever appearing on argv /
# /proc/<pid>/cmdline. The --env-password flag must sit immediately
# before <username> -- see bin/command.py for the resolution path.
PASSWORD_CONFIG_CMD = '''
                Auth-Type := `otpme-auth verify --socket --cache --env-password USER_PASSWORD '%{User-Name}' '%{NAS-Identifier}' '%{%{Client-IP-Address}:-%{Packet-Src-IPv6-Address}}'`
                '''

PASSWORD_CONFIG_MOD = '''
                Auth-Type := python_otpme
                '''

MSCHAP_CONFIG_CMD = '''
        Auth-Type MS-CHAP {
            mschap_otp
        }
        '''

MSCHAP_CONFIG_MOD = '''
        Auth-Type MS-CHAP {
            python_otpme
        }
        python_otpme
        '''

PYTHON_MOD_CONFIG_TEMPLATE = '''
    python3 python_otpme {
    	python_path="${modconfdir}/${.:name}:''' + PYTHONPATH + '''"
        module = otpme.lib.freeradius.otpme
    	#pass_all_vps = no
    	#pass_all_vps_dict = no

    	mod_instantiate = ${.module}
    	func_instantiate = instantiate

    	#mod_detach = ${.module}
    	#func_detach = detach

    	mod_authorize = ${.module}
    	func_authorize = authorize

    	mod_authenticate = ${.module}
    	func_authenticate = authenticate

    	#mod_preacct = ${.module}
    	#func_preacct = preacct

    	#mod_accounting = ${.module}
    	#func_accounting = accounting

    	#mod_checksimul = ${.module}
    	#func_checksimul = checksimul

    	#mod_pre_proxy = ${.module}
    	#func_pre_proxy = pre_proxy

    	#mod_post_proxy = ${.module}
    	#func_post_proxy = post_proxy

        mod_post_auth = ${.module}
        func_post_auth = post_auth

    	#mod_recv_coa = ${.module}
    	#func_recv_coa = recv_coa

    	#mod_send_coa = ${.module}
    	#func_send_coa = send_coa
    }
    '''

PYTHON_MOD_POSTAUTH_TEMPLATE = '''
        post-auth {
          python_otpme
      }
      '''

def create_freeradius_conf():
    # FreeRADIUS is started as root and changes to this user itself.
    radius_user, radius_group = get_user()
    if config.use_radius_mod:
        PYTHON_MOD_CONFIG = PYTHON_MOD_CONFIG_TEMPLATE
        PYTHON_MOD_POSTAUTH_CONFIG = PYTHON_MOD_POSTAUTH_TEMPLATE
        PASSWORD_CONFIG = PASSWORD_CONFIG_MOD
        MSCHAP_CONFIG = MSCHAP_CONFIG_MOD
    else:
        PYTHON_MOD_CONFIG = ""
        PYTHON_MOD_POSTAUTH_CONFIG = ""
        PASSWORD_CONFIG = PASSWORD_CONFIG_CMD
        MSCHAP_CONFIG = MSCHAP_CONFIG_CMD

    freeradius_conf_template = '''# -*- text -*-
    prefix = /usr
    exec_prefix = /usr
    sysconfdir = /etc
    localstatedir = /var
    sbindir = ${exec_prefix}/sbin
    logdir = ''' + get_log_dir() + '''
    raddbdir = /var/run/otpme/freeradius/
    radacctdir = ${logdir}/radacct
    name = freeradius
    confdir = ${raddbdir}
    modconfdir = ${confdir}/mods-config
    #certdir = /etc/otpme/ssl/
    #cadir   = /etc/otpme/ssl/
    #run_dir = ${localstatedir}/run/${name}
    run_dir = /var/run/otpme
    db_dir = ${raddbdir}
    #libdir = /usr/lib/freeradius
    pidfile = ${run_dir}/pidfiles/${name}.pid
    correct_escapes = true
    max_request_time = 30
    cleanup_delay = 5
    max_requests = 16384
    hostname_lookups = no
    log {
        destination = files
        colourise = yes
        file = ${logdir}/radius.log
        syslog_facility = daemon
        stripped_names = no
        auth = no
        auth_badpass = no
        auth_goodpass = no
        msg_denied = "You are already logged in - access denied"
    }
    checkrad = ${sbindir}/checkrad

    ENV {
    }

    security {
        user = ''' + radius_user + '''
        group = ''' + radius_group + '''
        allow_core_dumps = no
        max_attributes = 200
        reject_delay = 1
        status_server = yes
    }

    proxy_requests  = no

    thread pool {
        start_servers = ''' + str(config.radius_start_servers) + '''
        max_servers = ''' + str(config.radius_max_servers) + '''
        min_spare_servers = ''' + str(config.radius_min_spare_servers) + '''
        max_spare_servers = ''' + str(config.radius_max_spare_servers) + '''
        max_requests_per_server = 0
        auto_limit_acct = no
    }

    modules {
        mschap {
            pool {
                start = ${thread[pool].start_servers}
                min = ${thread[pool].min_spare_servers}
                max = ${thread[pool].max_servers}
                spare = ${thread[pool].max_spare_servers}
                uses = 0
                retry_delay = 30
                lifetime = 86400
                cleanup_interval = 300
                idle_timeout = 600
            }
        }

        eap {
            #default_eap_type = md5
            default_eap_type = mschapv2
            timer_expire = 60
            ignore_unknown_eap_types = no
            cisco_accounting_username_bug = no
            max_sessions = ${max_requests}
            md5 {
            }
            leap {
            }
            tls-config tls-common {
                #private_key_password = whatever
                private_key_file = /var/run/otpme/freeradius/key.pem
                certificate_file = /var/run/otpme/freeradius/cert.pem
                ca_file = /var/run/otpme/freeradius/ca.pem
                #dh_file = ${certdir}/dh
                #ca_path = ${cadir}
                cipher_list = "DEFAULT"
                cipher_server_preference = no
                disable_tlsv1_1 = yes
                disable_tlsv1 = yes
                tls_min_version = "1.2"
                tls_max_version = "1.2"
                ecdh_curve = "prime256v1"
                cache {
                    enable = no
                    lifetime = 24 # hours
                    store {
                        Tunnel-Private-Group-Id
                    }
                }
                verify {
                }
            }

            tls {
                tls = tls-common
            }

            ttls {
                tls = tls-common
                #default_eap_type = md5
                default_eap_type = mschapv2
                copy_request_to_tunnel = yes
                use_tunneled_reply = yes
                virtual_server = "otpme"
            }

            peap {
                tls = tls-common
                default_eap_type = mschapv2
                copy_request_to_tunnel = yes
                use_tunneled_reply = yes
                virtual_server = "otpme"
            }

            mschapv2 {
            }
        }

        mschap mschap_otp {
            ntlm_auth = "otpme-auth verify_mschap --socket '%{%{Stripped-User-Name}:-%{%{User-Name}:-None}}' '%{%{mschap_otp:Challenge}:-00}' '%{%{mschap_otp:NT-Response}:-00}' '%{NAS-Identifier}' '%{%{Client-IP-Address}:-%{Packet-Src-IPv6-Address}}'"
        }

        ''' + PYTHON_MOD_CONFIG + '''
    }

    # otpme virtualhost
    server otpme {
        # IPv4 wildcard. FreeRADIUS does not have a single "any-family"
        # listen, so we declare v4 and v6 sockets separately.
        listen {
            ipaddr = *
            port = 1812
            type = auth
        }
        listen {
            ipv6addr = ::
            port = 1812
            type = auth
        }

        $INCLUDE clients.conf

        authenticate {
            Auth-Type EAP {
                eap
            }

            ''' + MSCHAP_CONFIG + '''
        }

        authorize {
            eap

            # Use OTPme for clear-text passwords.
            if (!control:Auth-Type) {
                update control {
                    ''' + PASSWORD_CONFIG + '''
                }
            }
        }
        ''' + PYTHON_MOD_POSTAUTH_CONFIG + '''
    }
    '''

    create_dirs()
    if os.path.exists(freeradius_custom_conf):
        with open(freeradius_custom_conf, "r") as fd:
            x = fd.read()
    else:
        otpme_auth_path = os.path.join(config.bin_dir, "otpme-auth")
        x = freeradius_conf_template.replace("otpme-auth", otpme_auth_path)
    write_file(freeradius_conf, x)

def create_cert_files():
    site = backend.get_object(object_type="site",
                            uuid=config.site_uuid)
    radius_cert = site.cert
    if site.radius_cert:
        radius_cert = site.radius_cert
    write_file(freeradius_cert_file, radius_cert)
    radius_key = site.key
    if site.radius_key:
        radius_key = site.radius_key
    write_file(freeradius_key_file, radius_key)
    if site.radius_ca_cert:
        ca_data = site.radius_ca_cert
    else:
        realm = backend.get_object(object_type="realm",
                                uuid=config.realm_uuid)
        ca_data = realm.ca_data
    write_file(freeradius_ca_cert_file, ca_data)

def create_clients_conf():
    clients = backend.search(object_type="client",
                            attribute="uuid",
                            value="*",
                            return_type="instance")
    lines = []
    for client in clients:
        if not client.secret:
            continue
        counter = 0
        for address in client.addresses:
            counter += 1
            client_name = f"{client.name}-{counter}"
            # IPv6 literal/CIDR -> ipv6addr; else ipv4addr (also works for
            # IPv4 CIDR like '10.0.0.0/8').
            addr_directive = "ipv6addr" if ":" in str(address) else "ipv4addr"
            lines.append(f"client {address}"+"{")
            lines.append(f"\t{addr_directive}\t\t= {address}")
            lines.append(f"\tsecret\t\t= {client.secret}")
            lines.append(f"\tshortname\t= {client_name}")
            lines.append("}")

    lines = "\n".join(lines)

    write_file(freeradius_clients, lines)

def get_pid():
    fd = open(freeradius_pidfile, "r")
    pid = fd.read().replace("\n", "")
    fd.close()
    return pid

def start():
    try:
        status()
        freeradius_running = True
    except Exception:
        freeradius_running = False
    if freeradius_running:
        msg = _("Freeradius already running.")
        raise Exception(msg)
    lock_caller = "start"
    lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                lock_id=lock_caller,
                                lock_caller=lock_caller,
                                write=True, timeout=10)
    try:
        create_freeradius_conf()
        create_cert_files()
        create_clients_conf()
        run_freeradius()
    finally:
        lock.release_lock(lock_caller=lock_caller)

def run_freeradius():
    """ Start the FreeRADIUS program. """
    # No user/group here on purpose: FreeRADIUS changes to the user of
    # "security" in the config we write, and only root may do that. So
    # it is started by otpme-controld, see send_command().
    # The callers made sure it is not running. A PID file left behind
    # may belong to another user, and in the sticky PID directory
    # FREERADIUS_USER could not replace it.
    if os.path.exists(freeradius_pidfile):
        os.remove(freeradius_pidfile)
    start_cmd = [config.freeradius_bin, "-d", freeradius_dir]
    # The parent waits until the server is up and exits with how that
    # went. Not looked at, it was "Started freeradius." for one that
    # failed to load a module, every round of the quorum check.
    returncode = system_command.run(command=start_cmd,
                                    close_fds=True,
                                    return_proc=True,
                                    shell=False,
                                    call=True)
    if returncode != 0:
        log_file = os.path.join(get_log_dir(), "radius.log")
        msg = _("FreeRADIUS exited with {returncode}, see {log_file}")
        msg = msg.format(returncode=returncode, log_file=log_file)
        raise OTPmeException(msg)

def send_command(command):
    """ Ask otpme-controld to start, stop or reload FreeRADIUS.

    The daemons run as the OTPme user and can neither start FreeRADIUS
    as root nor stop it once it runs as FREERADIUS_USER.
    """
    from otpme.lib.daemon.controld import send_daemon_command
    send_daemon_command(daemon="freeradius", command=command)

def stop():
    try:
        status()
        freeradius_running = True
    except Exception:
        freeradius_running = False
    if not freeradius_running:
        return
    pid = get_pid()
    stuff.kill_pid(pid)
    while stuff.check_pid(pid):
        time.sleep(0.1)

def status():
    if not os.path.exists(freeradius_pidfile):
        msg = _("Freeradius not running.")
        raise Exception(msg)
    pid = get_pid()
    if not stuff.check_pid(pid):
        msg = _("Freeradius not running.")
        raise Exception(msg)
    return True

#def reload():
#    if not os.path.exists(freeradius_pidfile):
#        msg = _("Freeradius not running.")
#        raise NotRunning(msg)
#    lock_caller = "reload"
#    lock = locking.acquire_lock(lock_type=LOCK_TYPE,
#                                lock_id=lock_caller,
#                                lock_caller=lock_caller,
#                                write=True, timeout=10)
#    try:
#        create_freeradius_conf()
#        create_cert_files()
#        create_clients_conf()
#        pid = get_pid()
#        stuff.kill_pid(pid, signal=1)
#    finally:
#        lock.release_lock(lock_caller=lock_caller)

def reload():
    if not os.path.exists(freeradius_pidfile):
        msg = _("Freeradius not running.")
        raise NotRunning(msg)
    lock_caller = "reload"
    lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                lock_id=lock_caller,
                                lock_caller=lock_caller,
                                write=True, timeout=10)
    try:
        create_freeradius_conf()
        create_cert_files()
        create_clients_conf()
        # FreeRADIUS SIGHUP cannot reload clients.conf; a full restart
        # is the only option per upstream:
        # https://lists.freeradius.org/pipermail/freeradius-users/2022-November/102639.html
        pid = get_pid()
        stuff.kill_pid(pid)
        while stuff.check_pid(pid):
            time.sleep(0.1)
        run_freeradius()
    finally:
        lock.release_lock(lock_caller=lock_caller)
