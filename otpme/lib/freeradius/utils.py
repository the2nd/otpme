# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import shutil

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

PASSWORD_CONFIG_CMD = '''
                Auth-Type := `otpme-auth verify --socket --cache ''' + str(config.radius_cache_time) + ''' '%{User-Name}' '%{User-Password}' '%{NAS-Identifier}' '%{Client-IP-Address}'`
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

    	#mod_post_auth = ${.module}
    	#func_post_auth = post_auth

    	#mod_recv_coa = ${.module}
    	#func_recv_coa = recv_coa

    	#mod_send_coa = ${.module}
    	#func_send_coa = send_coa
    }
    '''

def create_freeradius_conf():
    if config.use_radius_mod:
        PYTHON_MOD_CONFIG = PYTHON_MOD_CONFIG_TEMPLATE
        PASSWORD_CONFIG = PASSWORD_CONFIG_MOD
        MSCHAP_CONFIG = MSCHAP_CONFIG_MOD
    else:
        PYTHON_MOD_CONFIG = ""
        PASSWORD_CONFIG = PASSWORD_CONFIG_CMD
        MSCHAP_CONFIG = MSCHAP_CONFIG_CMD

    freeradius_conf_template = '''# -*- text -*-
    prefix = /usr
    exec_prefix = /usr
    sysconfdir = /etc
    localstatedir = /var
    sbindir = ${exec_prefix}/sbin
    logdir = /var/log/otpme
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
        user = otpme
        group = otpme
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
            default_eap_type = md5
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
                default_eap_type = md5
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
            ntlm_auth = "otpme-auth verify_mschap --socket '%{%{Stripped-User-Name}:-%{%{User-Name}:-None}}' '%{%{mschap_otp:Challenge}:-00}' '%{%{mschap_otp:NT-Response}:-00}' '%{NAS-Identifier}' '%{Client-IP-Address}'"
        }

        ''' + PYTHON_MOD_CONFIG + '''
    }

    # otpme virtualhost
    server otpme {
        listen {
            # listen on localhost only by default
            ipaddr = *

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
    }
    '''

    if not os.path.exists(freeradius_dir):
        filetools.create_dir(freeradius_dir)
    if os.path.exists(freeradius_custom_conf):
        shutil.copyfile(freeradius_custom_conf, freeradius_conf)
    else:
        otpme_auth_path = os.path.join(config.bin_dir, "otpme-auth")
        x = freeradius_conf_template.replace("otpme-auth", otpme_auth_path)
        filetools.create_file(freeradius_conf,
                            content=x,
                            mode=0o660)

def create_cert_files():
    site = backend.get_object(object_type="site",
                            uuid=config.site_uuid)
    radius_cert = site.cert
    if site.radius_cert:
        radius_cert = site.radius_cert
    filetools.create_file(freeradius_cert_file,
                        content=radius_cert,
                        mode=0o660)
    radius_key = site.key
    if site.radius_key:
        radius_key = site.radius_key
    filetools.create_file(freeradius_key_file,
                        content=radius_key,
                        mode=0o660)
    realm = backend.get_object(object_type="realm",
                            uuid=config.realm_uuid)
    ca_data = realm.ca_data
    # FIXME: add radius CA cert to site.
    #if site.radius_ca_cert:
    #    ca_data = site.radius_ca_cert
    filetools.create_file(freeradius_ca_cert_file,
                        content=ca_data,
                        mode=0o660)

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
            client_name = "%s-%s" % (client.name, counter)
            lines.append("client %s {" % address)
            lines.append("\tipv4addr\t\t= %s" % address)
            lines.append("\tsecret\t\t= %s" % client.secret)
            lines.append("\tshortname\t= %s" % client_name)
            lines.append("}")

    lines = "\n".join(lines)

    filetools.create_file(freeradius_clients,
                        content=lines,
                        mode=0o660)

def get_pid():
    fd = open(freeradius_pidfile, "r")
    pid = fd.read().replace("\n", "")
    fd.close()
    return pid

def start():
    try:
        status()
        freeradius_running = True
    except:
        freeradius_running = False
    if freeradius_running:
        msg = "Freeradius already running."
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
        start_cmd = [config.freeradius_bin, "-d", freeradius_dir]
        system_command.run(command=start_cmd,
                            user=config.user,
                            group=config.group,
                            close_fds=True,
                            return_proc=True,
                            shell=False,
                            call=True)
    finally:
        lock.release_lock(lock_caller=lock_caller)

def stop():
    try:
        status()
        freeradius_running = True
    except:
        freeradius_running = False
    if not freeradius_running:
        return
    pid = get_pid()
    stuff.kill_pid(pid)
    while stuff.check_pid(pid):
        time.sleep(0.1)

def status():
    if not os.path.exists(freeradius_pidfile):
        msg = "Freeradius not running."
        raise Exception(msg)
    pid = get_pid()
    if not stuff.check_pid(pid):
        msg = "Freeradius not running."
        raise Exception(msg)
    return True

def reload():
    if not os.path.exists(freeradius_pidfile):
        msg = "Freeradius not running."
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
        pid = get_pid()
        stuff.kill_pid(pid, signal=1)
    finally:
        lock.release_lock(lock_caller=lock_caller)
