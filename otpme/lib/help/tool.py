# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
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
                    '_cmd_usage_help' : _('Usage: otpme-tool dump [acl_cache|sync_map] {object_id}'),
                    'cmd'   :   '<cache_type> [object_id]',
                    '_help' :   {
                                    'cmd'                   : _('Tell OTPme daemon to dump the given cache.'),
                                },
                },

    'dump_object'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool dump_object {object_id}'),
                    'cmd'   :   '<object_id>',
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
                    '_cmd_usage_help' : _('Usage: otpme-tool add_signer [--private] [--no-pin] [--no-verify-token-opts] [--allow-throwaway-key] [--tag <tag1> --tag <tag2> ...] --signer-type {signer_type} {object_id}'),
                    'cmd'   :   '--private :private=True: --no-pin :pin=false: --no-verify-token-opts :verify_token_opts=false: --allow-throwaway-key :allow_throwaway_key=True: --tag :+tags+: --signer-type ::signer_type:: <object_oid>',
                    '_help' :   {
                                    'cmd'                   : _('Add signer.'),
                                    '--signer-type <type>'  : _('Add signer of type <type>.'),
                                    '--no-pin'              : _('Do not pin signature keys.'),
                                    '--no-verify-token-opts': _('Do not require the signature to include the token options (e.g. command=) the SSH key is used with.'),
                                    '--allow-throwaway-key' : _('Only for remote_access: let this signer ask for a shell on a key the job brings along.'),
                                    '--private'             : _('Add signer for the logged in user.'),
                                },
                },


    'update_host_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool update_host_keys [--list] [host]'),
                    'cmd'   :   '--list :list_only=True: [host_name]',
                    '_help' :   {
                                    'cmd'                   : _('Take over the public keys of hosts that changed.'),
                                    '--list'                : _('Only show what changed, change nothing.'),
                                },
                },

    'update_user_keys'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool update_user_keys [--list] [user]'),
                    'cmd'   :   '--list :list_only=True: [user_name]',
                    '_help' :   {
                                    'cmd'                   : _('Take over the encrypt keys of users that changed.'),
                                    '--list'                : _('Only show what changed, change nothing.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-tool enable_signer [--private] [--signer-type <signer_type>] [signer_uuid]'),
                    'cmd'   :   '--private :private=True: --signer-type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Enable signer.'),
                                    '--private'             : _('Enable signer of the logged in user.'),
                                    '--signer-type <type>'  : _('Enable every signer of this type instead of one.'),
                                },
                },


    'disable_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool disable_signer [--private] [--signer-type <signer_type>] [signer_uuid]'),
                    'cmd'   :   '--private :private=True: --signer-type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Disable signer.'),
                                    '--private'             : _('Disable signer of the logged in user.'),
                                    '--signer-type <type>'  : _('Disable every signer of this type instead of one.'),
                                },
                },

    'update_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool update_signer [--private] [--no-pin] [--remove-gone] [--verify-token-opts|--no-verify-token-opts] [--allow-throwaway-key|--no-throwaway-key] [--signer-type <signer_type>] [signer_uuid]'),
                    'cmd'   :   '--private :private=True: --no-pin :pin=false: --remove-gone :remove_gone=True: --verify-token-opts :verify_token_opts=True: --no-verify-token-opts :verify_token_opts=false: --allow-throwaway-key :allow_throwaway_key=True: --no-throwaway-key :allow_throwaway_key=false: --signer-type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Update signer.'),
                                    '--no-pin'              : _('Do not pin signature keys.'),
                                    '--private'             : _('Update signer of the logged in user.'),
                                    '--signer-type <type>'  : _('Update every signer of this type instead of one.'),
                                    '--remove-gone'         : _('Drop signers that are not there anymore: the user was deleted, or is no longer in the role. Without this they are kept, so what they signed still validates.'),
                                    '--verify-token-opts'   : _('Require the signature to include the token options the SSH key is used with. Left as it is when neither this nor --no-verify-token-opts is given.'),
                                    '--no-verify-token-opts': _('Do not require it.'),
                                    '--allow-throwaway-key' : _('Only for remote_access: let this signer ask for a shell on a key the job brings along.'),
                                    '--no-throwaway-key'    : _('Take that permission away again.'),
                                },
                },

    'show_signer'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool show_signer [--private] [--signer-type <signer_type>] [signer_uuid]'),
                    'cmd'   :   '--private :private=True: --signer-type :signer_type: [signer_uuid]',
                    '_help' :   {
                                    'cmd'                   : _('Show signer(s).'),
                                    '--signer-type <type>'  : _('Only signers of this type.'),
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
                    'cmd'   :   '--procs :procs: --node :+node+: <csv_file>',
                    '_help' :   {
                                    'cmd'                   : _('Run login benchmark.'),
                                    '--node <node>'         : _('Send login request to this node.'),
                                    '--procs <int>'         : _('Start n jobs in parallel.'),
                                },
                },

    'sync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool sync [--realm <realm>] [--site <site>] [--request-site-cert] [sites|objects|token_data|ssh_authorized_keys|nsscache]'),
                    'cmd'   :   '--realm :realm: --site :site: --request-site-cert :request_site_cert=True: [sync_type]',
                    '_help' :   {
                                    'cmd'                   : _('Tell hostd to start a sync in the background.'),
                                    '--realm <realm>'       : _('Sync the objects of this realm only (objects only).'),
                                    '--site <site>'         : _('Sync the objects of this site only (objects only).'),
                                    '--request-site-cert'   : _('Take the site certs from the peers, e.g. after a renew_cert of a site (sites only).'),
                                },
                },


    'resync'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool resync [--realm <realm>] [--site <site>] {objects|nsscache}'),
                    'cmd'   :   '--realm :realm: --site :site: <sync_type>',
                    '_help' :   {
                                    'cmd'                   : _('Tell hostd to start a full sync in the background.'),
                                    '--realm <realm>'       : _('Resync the objects of this realm only (objects only).'),
                                    '--site <site>'         : _('Resync the objects of this site only (objects only).'),
                                },
                },


    'sync_status'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool sync_status [sync_type]'),
                    '_help' :   {
                                    'cmd'                   : _('Show the start of the last sync run of each sync type and its status.'),
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

    'get_user_site'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_user_site'),
                    '_help' :   {
                                    'cmd'                   : _('Get site of login user.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-tool index {start|status|reload|restart|stop|cli|init|drop|fix|rebuild|init|backup|restore|create_db_indices|drop_db_indices}'),
                    '_help' :   {
                                    'cmd'                   : _('Execute index command (e.g. rebuild)'),
                                },
                },

    'cache'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool cache {start|status|restart|stop|cli}'),
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


    'force_sync'      : {
                    '_cmd_usage_help' : _('Usage: otpme-tool force_sync {object_id}'),
                    'cmd'   :   '<|object|>',
                    '_help' :   {
                                    'cmd'   : _('Write an object whole, index, ACLs and LDIF included.'),
                                },
                },


    'do_sync'      : {
                    '_cmd_usage_help' : _('Usage: otpme-tool do_sync [--realm <realm>] [--site <site>] [--resync] [--offline] [--sync-older-objects] [--ignore-changed-objects] [--remove-orphan-objects] {objects|token_counters|used_otps|nsscache|ssh_authorized_keys}'),
                    'cmd'   :   '--realm :realm: --site :site: --resync :resync=True: --ignore-changed-objects :ignore_changed_objects=True: --sync-older-objects :sync_older_objects=True: --remove-orphan-objects :remove_orphan_objects=True: --offline :offline=True: <|object|>',
                    '_help' :   {
                                    'cmd'                       : _('Do a manual hostd sync.'),
                                    '--realm <realm>'           : _('Realm to sync.'),
                                    '--site <site>'             : _('Site to sync.'),
                                    '--resync'                  : _('Do a complete resync.'),
                                    '--offline'                 : _('Do a sync of offline token data.'),
                                    '--sync-older-objects'      : _('Sync objects even if they are older than the local ones.'),
                                    '--ignore-changed-objects'  : _('Sync objects even if they changed while syncing.'),
                                    '--remove-orphan-objects'   : _('Remove local objects of types this host no longer syncs.'),
                                },
                },



    'join'      : {
                    '_cmd_usage_help' : _('Usage: otpme-tool join [--jotp <jotp>] [--host-type <node|host>] [--unit <unit>] [--host-key-len <bits>] [--ca-key-len <bits>] [--ca-valid <days>] [--site-key-len <bits>] [--site-valid <days>] [--trust-site-cert|--check-site-cert <fp>] [--joind-uri <joind_uri>] [--no-daemon-start] [domain]'),
                    'cmd'   :   '--jotp :jotp: --host-type :host_type: --unit :unit: --trust-site-cert :trust_site_cert=True: --check-site-cert :site_cert_fingerprint: --host-key-len :host_key_len: --node-key-len :host_key_len: --ca-key-len :ca_key_len: --ca-valid :ca_valid: --site-key-len :site_key_len: --site-valid :site_valid: --joind-uri :joind_uri: --no-daemon-start :no_daemon_start=True: [|object|]',
                    '_help' :   {
                                    'cmd'                       : _('Join OTPme realm'),
                                    '--jotp <jotp>'             : _('Join using the given JOTP.'),
                                    '--host-type <host_type>'   : _('Join host as type <host_type>.'),
                                    '--unit <unit>'             : _('Join host to the given unit.'),
                                    '--host-key-len <key_len>'  : _('Key length of the certificate of this host or node (also --node-key-len).'),
                                    '--ca-key-len <key_len>'    : _('First node of a site: key length of the site CA.'),
                                    '--ca-valid <days>'         : _('First node of a site: validity of the site CA in days.'),
                                    '--site-key-len <key_len>'  : _('First node of a site: key length of the site certificate.'),
                                    '--site-valid <days>'       : _('First node of a site: validity of the site certificate in days.'),
                                    '--trust-site-cert'         : _('Trust any site certificate.'),
                                    '--check-site-cert <fp>'    : _('Check the site certificate fingerprint.'),
                                    '--joind-uri <joind_uri>'   : _('Joind URI e.g. tcp://login.otpme.org:2024'),
                                    '--no-daemon-start'         : _('Dont start OTPme daemons after joining realm.'),
                                },
                },


    'leave'     : {
                    '_cmd_usage_help' : _('Usage: otpme-tool leave [--lotp <lotp>] [--offline] [--keep-host|--no-keep-host] [--keep-data] [--keep-cache] [--keep-cert]'),
                    'cmd'   :   '--lotp :lotp: --offline :offline=True: --keep-host :keep_host=True: --no-keep-host :keep_host=False: --keep-data :keep_data=True: --keep-cache :keep_cache=True: --keep-cert :keep_cert=True:',
                    '_help' :   {
                                    'cmd'                   : _('Leave OTPme realm'),
                                    '--lotp <lotp>'         : _('Leave using the given LOTP.'),
                                    '--offline'             : _('Leave realm without talking to OTPme servers.'),
                                    '--keep-host'           : _('Do not delete node/host object on server side.'),
                                    '--no-keep-host'        : _('Delete node/host object on server side.'),
                                    '--keep-data'           : _('Keep all data (e.g realm data, certs, offline tokens...)'),
                                    '--keep-cache'          : _('Keep cached data (offline tokens, nsscache etc.)'),
                                    '--keep-cert'           : _('Do not revoke host certificate when leaving.'),
                                },
                },


    'login'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool login [--node {node}] [--no-authorize-host] [username]'),
                    'cmd'   :   '--node :node: --no-authorize-host :authorize_host=False: [username]',
                    '_help' :   {
                                    'cmd'                   : _('login to OTPme realm'),
                                    '--node <node>'         : _('Send login request to given node.'),
                                    '--no-authorize-host'   : _('Tell node not to authorize host on login.'),
                                },
                },

    'logout'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool logout'),
                    '_help' :   {
                                    'cmd'                   : _('logout from OTPme realm'),
                                },
                },

    'who'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool who'),
                    '_help' :   {
                                    'cmd'                   : _('Show logged in users'),
                                },
                },

    'host_who'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool host_who'),
                    '_help' :   {
                                    'cmd'                   : _('Show hosts waiting for jobs'),
                                },
                },

    'message'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool message [--user <username>] [--host <hostname>] [--all] [--title <title>] {text}'),
                    'cmd'   :   '--user :username: --host :host: --all :all_users=True: --title :title: <text>',
                    '_help' :   {
                                    'cmd'                   : _('Show a message box to logged in users'),
                                    '--user <username>'     : _('Send the message to this user.'),
                                    '--host <hostname>'     : _('Send the message to the users logged in on this host.'),
                                    '--all'                 : _('Send the message to all logged in users of this site.'),
                                    '--title <title>'       : _('Title of the message box.'),
                                },
                },

    'whoami'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool whoami'),
                    '_help' :   {
                                    'cmd'                   : _('show currently logged in user'),
                                },
                },

    'show_sessions'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool show_sessions [login_pid]'),
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

    'get_login_token_type'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_login_token_type'),
                    '_help' :   {
                                    'cmd'                   : _('Show token type of currently logged in user'),
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

    'get_display'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_display'),
                    '_help' :   {
                                    'cmd'                   : _('Get DISPLAY for logged in user'),
                                },
                },

    'get_sotp'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_sotp [--site {site}]'),
                    'cmd'   :   '--site :site:',
                    '_help' :   {
                                    'cmd'                   : _('Get a SOTP for logged in user'),
                                    '--site <site>'         : _('SOTP for a session at this site of the realm.'),
                                },
                },

    'get_private_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool get_private_key --role {sign|encrypt} [--decrypted]'),
                    'cmd'   :   '--role :key_role: --decrypted :decrypted=True:',
                    '_help' :   {
                                    'cmd'                   : _('Get a private key of the logged in user from otpme-agent.'),
                                    '--role <role>'         : _('Which key: sign or encrypt.'),
                                    '--decrypted'           : _('Ask for the unwrapped key instead of the one wrapped with the key password.'),
                                },
                },

    'add_private_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool add_private_key --role {sign|encrypt} [--decrypted]'),
                    'cmd'   :   '--role :key_role: --decrypted :decrypted=True:',
                    '_help' :   {
                                    'cmd'                   : _('Add a private key of the logged in user to otpme-agent. The key is read from stdin.'),
                                    '--role <role>'         : _('Which key: sign or encrypt.'),
                                    '--decrypted'           : _('The key is unwrapped. It is kept for the users key cache time.'),
                                },
                },

    'del_private_key'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool del_private_key --role {sign|encrypt}'),
                    'cmd'   :   '--role :key_role:',
                    '_help' :   {
                                    'cmd'                   : _('Remove a private key of the logged in user from otpme-agent. Both the wrapped and the unwrapped one.'),
                                    '--role <role>'         : _('Which key: sign or encrypt.'),
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
                                    'cmd'                   : _('Request JWT from authd'),
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

    'do_reauth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool do_reauth'),
                    '_help' :   {
                                    'cmd'                   : _('Do manual auth_on_action reauth.'),
                                },
                },

    'reset_reauth'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool reset_reauth'),
                    '_help' :   {
                                    'cmd'                   : _('Reset auth_on_action reauth.'),
                                },
                },

    'backup'    : {
                    '_cmd_usage_help' : _('Usage: otpme-tool backup -d <backup_dir>'),
                    'cmd'   :   '-d :backup_dir: --remove-older-than :remove_older_than: --dry-run :dry_run=True:',
                    '_help' :   {
                                    'cmd'                           : _('Write backup to backup directory.'),
                                    '-d <backup_dir>'               : _('Write backup to directory <backup_dir>.'),
                                    '--remove-older-than <time>'    : _('Remove backups older than <time> from <backup_dir>.'),
                                    '--dry-run'                     : _('Dont remove backups, just show what would be removed.'),
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
