# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="tool", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-tool {command}"),

    'reload'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool reload'),
                    '_help' :   {
                                    'cmd'                   : _('Tell OTPme to reload its config. (e.g. if running as freeradius module)'),
                                },
                },


    'dump'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool dump [object_cache|instance_cache|...] {object_id}'),
                    'cmd'   :   '<cache_type> [object_id]',
                    '_help' :   {
                                    'cmd'                   : _('Tell OTPme daemon to dump the given cache.'),
                                },
                },


    'dump_object'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool dump_object {object_id}'),
                    '_help' :   {
                                    'cmd'                   : _('Dump object.'),
                                },
                },


    'delete_object'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool delete_object [object_id]'),
                    'cmd'   :   '<object_id>',
                    '_help' :   {
                                    'cmd'                   : _('Delete object.'),
                                },
                },

    'check_duplicate_ids'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool check_duplicate_ids {object_type}'),
                    'cmd'   :   '<object_type>',
                    '_help' :   {
                                    'cmd'                   : _('Check for duplicate uidNumber/gidNumber.'),
                                },
                },

    'add_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool add_signer [--private] [--no-pin] [--tag <tag1> --tag <tag2> ...] --signer-type {signer_type} {object_id}'),
                    'cmd'   :   '--private :private=True: --no-pin :pin=false: --tag :+tags+: --signer-type ::signer_type:: <object_oid>',
                    '_help' :   {
                                    'cmd'                   : _('Add signer.'),
                                    '--signer-type <type>'  : _('Add signer of type <type>.'),
                                    '--no-pin'              : _('Do not pin signature keys.'),
                                    '--private'             : _('Add signer for the logged in user.'),
                                },
                },


    'del_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool del_signer [--private] {signer_uuid}'),
                    'cmd'   :   '--private :private=True: <signer_uuid>',
                    '_help' :   {
                                    'cmd'                   : _('Delete signer.'),
                                    '--private'             : _('Delete signer of the logged in user.'),
                                },
                },


    'enable_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool enable_signer [--private --type <signer_type>] {signer_uuid}'),
                    'cmd'   :   '--private :private=True: --type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Enable signer.'),
                                    '--private'             : _('Enable signer of the logged in user.'),
                                },
                },


    'disable_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool disable_signer [--private --type <signer_type>] {signer_uuid}'),
                    'cmd'   :   '--private :private=True: --type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Disable signer.'),
                                    '--private'             : _('Disable signer of the logged in user.'),
                                },
                },

    'update_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool update_signer [--private] [--no-pin] [--tags tag1,tag2...] [signer_uuid]'),
                    'cmd'   :   '--private :private=True: --no-pin :pin=false: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Update signer.'),
                                    '--no-pin'              : _('Do not pin signature keys.'),
                                    '--private'             : _('Update signer of the logged in user.'),
                                },
                },

    'show_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool show_signer [--private] {signer_uuid}'),
                    'cmd'   :   '--private :private=True: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Show signer(s).'),
                                    '--private'             : _('Show signer(s) of the logged in user.'),
                                },
                },

    'show_offline_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool show_offline_token [token_id]'),
                    'cmd'   :   '[|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Show cached offline token(s).'),
                                },
                },

    'pin_offline_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool pin_offline_token'),
                    'cmd'   :   '',
                    '_help' :   {
                                    'cmd'                   : _('Pin cached offline token(s).'),
                                },
                },

    'unpin_offline_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool unpin_offline_token'),
                    'cmd'   :   '',
                    '_help' :   {
                                    'cmd'                   : _('Unpin cached offline token(s).'),
                                },
                },

    'dump_index'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool dump_index {object_id}'),
                    'cmd'   :   '[|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Dump object index.'),
                                },
                },

    'mass_object_add'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool mass_object_add [--verify-only] [--procs <16>] {csv_file}'),
                    'cmd'   :   '--verify-only :verify_csv=True: --procs :procs: <csv_file>',
                    '_help' :   {
                                    'cmd'                   : _('Add objects from csv file.'),
                                    '--verify-only'         : _('Only verify csv file.'),
                                    '--procs <int>'         : _('Start n jobs in parallel.'),
                                },
                },

    'login_benchmark'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool login_benchmark [--procs <16>] [--node <node>] {csv_file}'),
                    'cmd'   :   '--procs :procs: --node :node: <csv_file>',
                    '_help' :   {
                                    'cmd'                   : _('Run login benchmark.'),
                                    '--node <node>'         : _('Send login request to this node.'),
                                    '--procs <int>'         : _('Start n jobs in parallel.'),
                                },
                },

    'sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool sync [sites|objects|token_data|ssh_authorized_keys|nsscache]'),
                    'cmd'   :   '--realm :realm: --site :site: [sync_type]',
                    '_help' :   {
                                    'cmd'                   : _('tell OTPme daemon to start sync with master node.'),
                                    '--realm'               : _('Realm to start object sync with.'),
                                    '--site'                : _('Site to start object sync with.'),
                                },
                },


    'resync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool resync [objects|token_data|ssh_authorized_keys|nsscache]'),
                    'cmd'   :   '--realm :realm: --site :site: <sync_type>',
                    '_help' :   {
                                    'cmd'                   : _('Tell OTPme daemon to start resync the given data type.'),
                                    '--realm'               : _('Realm to start object resync with.'),
                                    '--site'                : _('Site to start object resync with.'),
                                },
                },


    'sync_status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool sync_status [sync_type]'),
                    '_help' :   {
                                    'cmd'                   : _('Get time of last successful sync.'),
                                },
                },


    'sign'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool sign {file} {sign_file}'),
                    'cmd'   :   '--stdin-pass :stdin_pass=True: <file1> <file2>',
                    '_help' :   {
                                    'cmd'                   : _('Create signature for given file using users RSA key.'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                },
                },


    'verify'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool verify {sign_file} {file}'),
                    'cmd'   :   '<file1> <file2>',
                    '_help' :   {
                                    'cmd'                   : _('Verify signature for given file using users RSA key.'),
                                },
                },


    'encrypt'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool encrypt [--rsa] [--no-rsa] [-u <username>] [--pass <password>] [--stdin-pass] {file} {outfile}'),
                    'cmd'   :   '--rsa :use_rsa=True: --no-rsa :no_rsa=True: -u :username: --pass :password: --stdin-pass :stdin_pass=True: --force-pass :force_pass=True: <file1> <file2>',
                    '_help' :   {
                                    'cmd'                   : _('Encrypt file using users RSA key (AES encryption).'),
                                    '--rsa'                 : _('Encrypt file using users RSA key (RSA encryption).'),
                                    '--no-rsa'              : _('Disable use of RSA public keys for encryption of AES keys.'),
                                    '-u <username>'         : _('Encrypt file with public key of user <username>'),
                                    '--pass <password>'     : _('Use <password> to encrypt the file (AES only).'),
                                    '--stdin-pass'          : _('Read password from stdin (AES only).'),
                                    '--force-pass'          : _('Force encryption with password and not via e.g. GPG (AES only).'),
                                },
                },


    'decrypt'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool decrypt --pass <password> --stdin-pass {file} {outfile}'),
                    'cmd'   :   '--pass :password: --stdin-pass :stdin_pass=True: <file1> <file2>',
                    '_help' :   {
                                    'cmd'                   : _('Decrypt file using users RSA key (AES encryption).'),
                                    '--pass <password>'     : _('Use <password> to decrypt the file (AES only).'),
                                    '--stdin-pass'          : _('Read passphrase for RSA private key from stdin'),
                                },
                },


    'gen_motp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_motp {epoch_time} {secret} {pin} [otp_count]'),
                    '_help' :   {
                                    'cmd'                   : _('generate {otp_count} motp OTPs from {epoch_time} {secret} and {pin}'),
                                },
                },

    'gen_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_mschap {username} {password}'),
                    '_help' :   {
                                    'cmd'                   : _('generate mschap challange/response from given username and password'),
                                },
                },

    'gen_refresh'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_refresh {username} {password}'),
                    '_help' :   {
                                    'cmd'                   : _('generate SRP (Session-Refresh-Password) from given password'),
                                },
                },

    'gen_refresh_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_refresh_mschap {username} {password}'),
                    '_help' :   {
                                    'cmd'                   : _('generate SRP challange/response (MSCHAP) from given username and password"'),
                                },
                },

    'gen_logout'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_logout {username} {password}'),
                    '_help' :   {
                                    'cmd'                   : _('generate SLP (Session-Logout-Password) from given password"'),
                                },
                },

    'gen_logout_mschap'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool gen_logout_mschap {username} {password}'),
                    '_help' :   {
                                    'cmd'                   : _('generate mschap SLP challange/response (MSCHAP) from given username and password'),
                                },
                },

    'get_realm'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_realm'),
                    '_help' :   {
                                    'cmd'                   : _('Show realm of this host'),
                                },
                },

    'get_site'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_site'),
                    '_help' :   {
                                    'cmd'                   : _('Show site of this host'),
                                },
                },

    'import'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool import {file}'),
                    'cmd'   :   '--password :password: <|object|>',
                    '_help' :   {
                                    'cmd'                   : _('Import object config'),
                                    '--password <password>' : _('Decrypt object config with password.'),
                                },
                },

    'add_user'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool add_user {file}'),
                    '_help' :   {
                                    'cmd'                   : _('Create users listed in file'),
                                },
                },

    'index'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool index {start|status|stop|cli|init|drop|rebuild|create_db_indices|drop_db_indices}'),
                    '_help' :   {
                                    'cmd'                   : _('Execute index command (e.g. rebuild)'),
                                },
                },

    'cache'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool cache {command}'),
                    '_help' :   {
                                    'cmd'                   : _('Execute cache command (e.g start)'),
                                },
                },

    'radius'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool radius {start|status|stop|reload|restart|test}'),
                    '_help' :   {
                                    'cmd'                   : _('Execute radius command'),
                                },
                },

    'regen_master_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool regen_master_key'),
                    '_help' :   {
                                    'cmd'                   : _('Regen AES master key'),
                                },
                },

    'renew_auth_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool renew_auth_key'),
                    '_help' :   {
                                    'cmd'                   : _('Renew host auth key.'),
                                },
                },

    'renew_cert'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool renew_cert'),
                    '_help' :   {
                                    'cmd'                   : _('Renew host certificate.'),
                                },
                },


    'do_sync'      : {
                    '_cmd_usage_help' : _('Usage: otpme-tool do_sync [ --realm <realm> --site <site> --resync --no-memory-cache --ignore-changed-objects --offline] {objects|token_counters|used_otps|nsscache|ssh_authorized_keys}'),
                    'cmd'   :   '--realm :realm: --site :site: --resync :resync=True: --no-memory-cache :mem_cache=False: --ignore-changed-objects :ignore_changed_objects=True: --sync-older-objects :sync_older_objects=True: --offline :offline=True: <|object|>',
                    '_help' :   {
                                    'cmd'                       : _('Do a manual hostd sync.'),
                                    '--realm <realm>'           : _('Realm to sync.'),
                                    '--host-type <host_type>'   : _('Site to sync.'),
                                    '--resync'                  : _('Do a complete resync.'),
                                    '--offline'                 : _('Do a sync of offline token data.'),
                                    '--no-memory-cache'         : _('Do not cache objects in memory.'),
                                    '--sync-older-objects'      : _('Sync objects even if they are older than the local ones.'),
                                    '--ignore-changed-objects'  : _('Sync objects even if they changed while syncing.'),
                                },
                },



    'join'      : {
                    '_cmd_usage_help' : _('Usage: otpme-tool join [ --jotp <jotp> --host-type <node|host> --unit <unit> --trust-site-cert --check-site-cert <site_cert_fp> --no-daemon-start] [domain]'),
                    'cmd'   :   '--jotp :jotp: --host-type :host_type: --unit :unit: --trust-site-cert :trust_site_cert=True: --check-site-cert :site_cert_fingerprint: --host-key-len :host_key_len: --site-key-len :site_key_len: --no-daemon-start :no_daemon_start=True: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('Join OTPme realm'),
                                    '--jotp <jotp>'             : _('Join using the given JOTP.'),
                                    '--host-type <host_type>'   : _('Join host as type <host_type>.'),
                                    '--unit <unit>'             : _('Join host to the given unit.'),
                                    '--host-key-len <key_len>'  : _('Host/Node key length.'),
                                    '--site-key-len <key_len>'  : _('Site key length.'),
                                    '--trust-site-cert'         : _('Trust any site certificate.'),
                                    '--check-site-cert <fp>'    : _('Check the site certificate fingerprint.'),
                                    '--no-daemon-start'         : _('Dont start OTPme daemons after joining realm.'),
                                },
                },


    'leave'     : {
                    '_cmd_usage_help' : _('Usage: otpme-tool leave [ --lotp <lotp> --offline --keep-host --no-keep-host --keep-data --keep-cache --keep-cert ] [domain]'),
                    'cmd'   :   '--lotp :lotp: --offline :offline=True: --keep-host :keep_host=True: --no-keep-host :keep_host=False, --keep-data :keep_data=True: --keep-cache :keep_cache=True: --keep-cert :keep_cert=True: --keep-auth-key :keep_auth_key=True: [|object|]',
                    '_help' :   {
                                    'cmd'                   : _('Leave OTPme realm'),
                                    '--lotp <lotp>'         : _('Leave using the given LOTP.'),
                                    '--offline'             : _('Leave realm without talking to OTPme servers.'),
                                    '--keep-host'           : _('Do not delete node/host object on server side.'),
                                    '--no-keep-host'        : _('Delete node/host object on server side.'),
                                    '--keep-data'           : _('Keep all data (e.g realm data, certs, offline tokens...)'),
                                    '--keep-cache'          : _('Keep cached data (offline tokens, nsscache etc.)'),
                                    '--keep-cert'           : _('Do not revoke host certficiate when leaving.'),
                                    '--keep-auth-key'       : _('Do not revoke host auth key when leaving.'),
                                },
                },


    'login'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool login --node {node} [username]'),
                    'cmd'   :   '--node :node: [username]',
                    '_help' :   {
                                    'cmd'                   : _('login to OTPme realm'),
                                    '--node <node>'         : _('Send login request to given node.'),
                                },
                },

    'logout'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool logout'),
                    '_help' :   {
                                    'cmd'                   : _('logout from OTPme realm'),
                                },
                },

    'whoami'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool whoami'),
                    '_help' :   {
                                    'cmd'                   : _('show currently logged in user'),
                                },
                },

    'show_sessions'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool show_sessions'),
                    '_help' :   {
                                    'cmd'                   : _('Get otpme-agent login sessions.'),
                                },
                },

    'get_login_session_id'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_login_session_id'),
                    '_help' :   {
                                    'cmd'                   : _('Get otpme-agent login session ID.'),
                                },
                },

    'get_login_token'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_login_token'),
                    '_help' :   {
                                    'cmd'                   : _('Show token of currently logged in user'),
                                },
                },

    'get_login_pass_type'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_login_pass_type'),
                    '_help' :   {
                                    'cmd'                   : _('Show token password type used at login.'),
                                },
                },

    'get_tty'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_tty'),
                    '_help' :   {
                                    'cmd'                   : _('Get TTY for logged in user'),
                                },
                },

    'get_sotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_sotp --site {site}'),
                    'cmd'   :   '--site :site:',
                    '_help' :   {
                                    'cmd'                   : _('Get a SOTP for logged in user'),
                                },
                },

    'get_srp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_srp'),
                    '_help' :   {
                                    'cmd'                   : _('Get a SRP for logged in user'),
                                },
                },


    'get_jwt'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_jwt <challenge>'),
                    '_help' :   {
                                    'cmd'                   : _('Request JWT from mgmtd'),
                                },
                },


    'reneg'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool reneg'),
                    '_help' :   {
                                    'cmd'                   : _('Try to renegotiate login session.'),
                                },
                },

    'search'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool search attribute=<attribute> value=<value> object_type=<object_type> return_type=<uuid|full_oid|read_oid|name>'),
                    '_help' :   {
                                    'cmd'                   : _('Search otpme objects'),
                                },
                },

    'start_ssh_agent'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool start_ssh_agent'),
                    '_help' :   {
                                    'cmd'                   : _('Start users SSH agent script'),
                                },
                },

    'stop_ssh_agent'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool stop_ssh_agent'),
                    '_help' :   {
                                    'cmd'                   : _('Stop users SSH agent script'),
                                },
                },

    'restart_ssh_agent'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool restart_ssh_agent'),
                    '_help' :   {
                                    'cmd'                   : _('Restart users SSH agent script'),
                                },
                },

    'ssh_agent_status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool ssh_agent_status'),
                    '_help' :   {
                                    'cmd'                   : _('Get users SSH agent script status'),
                                },
                },

    'reset_reauth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool reset_reauth'),
                    'cmd'   :   'reset_reauth',
                    '_help' :   {
                                    'cmd'                   : _('Reset auth_on_action reauth.'),
                                },
                },

    'backup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool backup -d <backup_dir>'),
                    'cmd'   :   '-d :backup_dir:',
                    '_help' :   {
                                    'cmd'                   : _('Write backup to backup directory.'),
                                },
                },
    'restore'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool restore {-d <restore_dir>|-f <restore_file>}'),
                    'cmd'   :   '-d :restore_dir: -f :restore_file:',
                    '_help' :   {
                                    'cmd'                   : _('Write backup to backup directory.'),
                                },
                },
    'detect_smartcard'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool detect_smartcard -t [fido2,yubikey_hmac,...]'),
                    'cmd'   :   '-t :[smartcard_types]:',
                    '_help' :   {
                                    'cmd'                   : _('Detect connected smartcards.'),
                                },
                },
    }
