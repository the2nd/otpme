#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

# http://stackoverflow.com/questions/6031584/importing-from-builtin-library-when-module-with-same-name-exists
import socket

import os
import sys
import struct
import psutil

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

# Needed when running as fake pinentry.
if __name__ == '__main__':
    my_path = os.path.realpath(sys.argv[0])
    my_path = os.path.dirname(my_path)
    my_path = os.path.dirname(my_path)
    my_path = os.path.dirname(my_path)
    my_path = os.path.dirname(my_path)
    sys.path.insert(0, my_path)

try:
    from otpme.lib import config
except:
    # Add PYTHONPATH.
    PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
    if os.path.exists(PYTHONPATH_FILE):
        fd = open(PYTHONPATH_FILE, "r")
        try:
            for x in fd.readlines():
                x = x.replace("\n", "")
                if x in sys.path:
                    continue
                sys.path.insert(0, x)
        finally:
            fd.close()
    from otpme.lib.otpme_config import OTPmeConfig
    config = OTPmeConfig("pinentry", auto_load=False)
    config.load(quiet=True)

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.encoding.base import encode

from otpme.lib.exceptions import *

GPG_BIN = "gpg"
SOCKET_FILE = "/tmp/gpg-pinentry.sock"

user_home = os.getenv("HOME")
gpg_dir = "%s/.gnupg" % user_home
gpg_sshcontrol_file = "%s/sshcontrol" % gpg_dir
tmp_dir = "/dev/shm"

try:
    import pexpect
except:
    raise Exception("Please install python pexpect module. (e.g. apt-get "
                    "install python-pexpect)")

# Make sure we get english messages (for use with expect)
os.environ['LANG'] = ''

def get_gpg_version():
    """ Get GPG version. """
    gpg_version_command = [ GPG_BIN, '--version' ]
    returncode, \
    stdout, \
    stderr, \
    pid = system_command.run(command=gpg_version_command)
    if returncode != 0:
        return None
    stdout = stdout.decode()
    line1 = stdout.split("\n")[0]
    version = line1.split()[2]
    return version

def init_gpg(user_email, user_real_name, passphrase):
    """ Init GPG. """
    import gnupg
    sys.stdout.write("Generating GPG keys...\n")
    sys.stdout.flush()

    if not os.path.exists(gpg_dir):
        filetools.create_dir(gpg_dir, user="root", group="root", mode=0o700)

    gpg = gnupg.GPG(gnupghome=gpg_dir, verbose=False)
    gpg.encoding = 'utf-8'
    input_data = gpg.gen_key_input(key_type="RSA",
                                key_length=1024,
                                name_real=user_real_name,
                                name_email=user_email,
                                passphrase=passphrase)
    master_key = gpg.gen_key(input_data)

    auth_key = gpg.add_subkey(master_key=master_key.fingerprint,
                            master_passphrase=passphrase,
                            algorithm='rsa4096',
                            usage='auth',
                            expire='-')

    enc_key = gpg.add_subkey(master_key=master_key.fingerprint,
                            master_passphrase=passphrase,
                            algorithm='rsa4096',
                            usage='encrypt',
                            expire='-')
    stop_agent()

    return str(master_key), str(auth_key), str(enc_key)


def create_backup(backup_file, passphrase):
    """ Backup GPG keys to file. """
    print("Creating GPG backup...")
    from otpme.lib import multiprocessing
    # start thread to handover backup password to gpg-agent.
    #passphrases = [ passphrase, passphrase ]
    passphrases = [ passphrase ]
    pass_thread = multiprocessing.start_thread(name="create_backup", target=send_passphrases, target_args=("backup_gpg", passphrases))

    if os.path.exists(backup_file):
        print("File already exists: %s" % backup_file)
        return False
    #gpg_backup_command = [GPG_BIN, '--export-secret-keys', '-a', key_id]
    gpg_backup_command = [GPG_BIN, '--export-secret-keys']
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_backup_command)
    if command_returncode == 0:
        filetools.create_file(path=backup_file, content=command_stdout, mode=0o600, write_mode="wb")
        print("GPG backup successful.")
        pass_thread.join()
        return True
    print("GPG backup failed: %s" % command_stderr)
    pass_thread.join()
    return False


def restore_backup(backup_file, passphrase):
    """ Restore GPG keys from file. """
    from otpme.lib import multiprocessing
    print("Restoring GPG backup...")
    if not os.path.exists(backup_file):
        print("File does not exist: %s" % backup_file)
        return False

    # Start thread to handover backup password to gpg-agent.
    passphrases = [ passphrase ]
    pass_thread = multiprocessing.start_thread(name="restore_backup", target=send_passphrases, target_args=("restore_gpg", passphrases))


    gpg_restore_command = [GPG_BIN,
                        '--import',
                        '--allow-secret-key-import',
                        backup_file]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_restore_command)
    if command_returncode == 0:
        pass_thread.join()
        return True
    print("GPG restore failed: %s" % command_stderr)
    pass_thread.join()
    return False


#def start_agent(pinentry_bin=None):
#    """ Start GPG agent. """
#    if pinentry_bin is None:
#        pinentry_bin = my_path
#    if not os.path.exists(gpg_dir + "/private-keys-v1.d"):
#        # create private keys dir to prevent agent startup problems
#        filetools.create_dir(gpg_dir + "/private-keys-v1.d", mode=0o700)
#    #gpg_agent_command = ('gpg-agent --daemon --enable-ssh-support '
#    #                    '--allow-preset-passphrase --pinentry-program %s'
#    #                    % pinentry_bin)
#    gpg_agent_command = ['gpg-agent',
#                        '--daemon',
#                        '--enable-ssh-support',
#                        '--allow-preset-passphrase',
#                        '--pinentry-program',
#                        pinentry_bin]
#    agent_returncode, \
#    agent_stdout, \
#    agent_stderr, \
#    agent_pid = system_command.run(command=gpg_agent_command)
#    if agent_returncode != 0:
#        msg = ("Unable to start gpg-agent: " + agent_stderr)
#        raise Exception(msg)
#    ssh_agent_pid, ssh_auth_sock, gpg_agent_info = stuff.get_agent_vars(agent_stdout)
#    if ssh_auth_sock:
#        return ssh_agent_pid, ssh_auth_sock, gpg_agent_info


def remove_main_key(key_id, debug=False):
    """ Remove main GPG key from .gnupg dir. """
    pubring_file = "%s/pubring.gpg" % gpg_dir
    if not os.path.exists(pubring_file):
        print("Cannot remove main key. Missing pubring file: %s" % pubring_file)
        return
    gpg_pubring_fd = open(pubring_file, "r")
    gpg_pubring = encode(gpg_pubring_fd.read(), "base64")
    gpg_pubring_fd.close()

    gpg_export_stubs_command = [
                                GPG_BIN,
                                '--yes',
                                '--export-secret-subkeys',
                                key_id,
                            ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_export_stubs_command)
    if command_returncode != 0:
        raise Exception("Export of key stubs failed: %s" % command_stderr)

    key_stubs = encode(command_stdout, "base64")

    gpg_remove_main_key_command = '%s --delete-secret-keys %s' % (GPG_BIN, key_id)

    child = pexpect.spawn(gpg_remove_main_key_command)
    if debug:
        child.logfile = sys.stdout

    child.expect(r'Delete this key from the keyring.*', timeout=300)
    child.sendline('y')
    child.expect(r'This is a secret key! - really delete.*', timeout=300)
    child.sendline('y')
    child.wait()

    gpg_import_stubs_command = [
                                'echo',
                                '-n',
                                '"%s"',
                                '|',
                                'base64',
                                '-d',
                                '|',
                                GPG_BIN,
                                '--yes',
                                '--import',
                                key_stubs,
                            ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_import_stubs_command)
    if command_returncode != 0:
        raise Exception("Import of key stubs failed: %s" % command_stderr)

    gpg_import_pubring_command = [
                                'echo',
                                '-n',
                                '"%s"',
                                '|',
                                'base64',
                                '-d',
                                '|',
                                GPG_BIN,
                                '--yes',
                                '--import',
                                gpg_pubring,
                            ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_import_pubring_command)
    if command_returncode != 0:
        raise Exception("Import of public keys failed: %s" % command_stderr)

    return True

def get_sub_keygrip():
    """ get keygrip of sub key 1. """
    key_id = None
    key_id_split = False
    keygrip = None
    gpg_fingerprint_command = [ GPG_BIN, '--fingerprint', '--fingerprint' ]
    returncode, \
    stdout, \
    stderr, \
    pid = system_command.run(command=gpg_fingerprint_command)
    if returncode == 0:
        sub_found = False
        stdout = stdout.decode()
        for line in stdout.split("\n"):
            if sub_found:
                keygrip = line.replace(" ", "")
                break
            if line.startswith('sub '):
                if "/" in line:
                    key_id = line.split("/")[1]
                    key_id_split = key_id[0:4] + " " + key_id[4:8]
                else:
                    sub_found = True
            if key_id_split:
                if line.endswith(key_id_split):
                    keygrip = line.split("=")[1].replace(" ", "")
                    break
    return keygrip

def get_ssh_keygrip():
    """ Get keygrip of sub key 1 (public) needed for sshcontrol file. """
    keygrip = None
    gpg_connect_command = 'gpg-connect-agent "keyinfo --list" /bye'
    returncode, \
    stdout, \
    stderr, \
    pid = system_command.run(command=gpg_connect_command, shell=True)
    if returncode != 0:
        raise Exception(str(stderr))
    stdout = stdout.decode()
    for line in stdout.split("\n"):
        if line.startswith('S KEYINFO '):
            keygrip = line.split()[2]
            break
    if not keygrip:
        raise Exception("Unable to get public sub keygrip.")
    return keygrip

def get_ssh_public_key():
    """ Get public key from smartcard (e.g. yubikey) via gpg-agent. """
    gpg_command = [
                    'ssh-add',
                    '-L',
                ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_command)
    if command_returncode != 0:
        print(command_stderr, command_stdout)
        return False
    # Cut off key type and comment
    command_stdout = command_stdout.decode()
    ssh_public_key = command_stdout.split(" ")[1]
    return ssh_public_key

def get_main_key_id():
    """ Get GPG main key ID. """
    key_id = False
    gpg_list_command = [ GPG_BIN, '--list-secret-keys' ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_list_command)
    for line in command_stdout.split("\n"):
        if line.startswith("sec"):
            key_id = line.split("/")[1][0:8]
    return key_id

def key_to_card(key_id, key_type, sc_admin_pin, gpg_passphrase, debug=False):
    """ Move GPG sub key to card. """
    from otpme.lib import multiprocessing
    if key_type != "auth":
        if key_type != "encrypt":
            msg = "Unknown key type: %s" % key_type
            raise OTPmeException(msg)
    # Start thread to handover token admin PIN to gpg-agent via socket
    passphrases = [ gpg_passphrase, sc_admin_pin, sc_admin_pin ]
    pass_thread = multiprocessing.start_thread(name="keytocard", target=send_passphrases, target_args=("keytocard", passphrases))

    gpg_keytocard_command = '%s --expert --edit-key -a %s' % (GPG_BIN, key_id)
    gpg_prompt = 'gpg> '
    gpg_card_error = 'gpg: error writing key to card: Card error'
    gpg_operation_canelled = 'gpg: error writing key to card: Operation cancelled'

    child = pexpect.spawn(gpg_keytocard_command)
    if debug:
        fd = open("/tmp/expect", "wb")
        child.logfile = fd

    child.expect(gpg_prompt, timeout=3)
    child.sendline('toggle')
    child.expect(gpg_prompt, timeout=3)
    if key_type == "auth":
        child.sendline('key 1')
    if key_type == "encrypt":
        child.sendline('key 2')
    child.expect(gpg_prompt, timeout=3)
    child.sendline('keytocard')
    child.expect('Your selection?', timeout=3)
    if key_type == "auth":
        child.sendline('3')
    if key_type == "encrypt":
        child.sendline('2')

    i = child.expect([gpg_prompt,
                    gpg_card_error,
                    gpg_operation_canelled],
                    timeout=30)

    if i == 1:
        child.sendline('quit')
        child.wait()
        raise Exception("GPG error: %s" % gpg_card_error)

    if i == 2:
        child.sendline('quit')
        child.wait()
        raise Exception("Operation cancelled.")

    child.sendline('save')
    child.wait()
    pass_thread.join()

    return True

def verify_passphrase(key_id, passphrase):
    """ Verify if GPG passphrase is correct. """
    ssh_agent_pid, \
    ssh_auth_sock, \
    gpg_agent_info = start_agent()

    #if gpg_agent_info:
    #    os.environ['GPG_AGENT_INFO'] = gpg_agent_info
    os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock

    test_file = '%s/gpg_test.txt' % config.tmp_dir
    filetools.create_file(path=test_file, content="test", mode=0o600)
    gpg_verify_command = [
                            'echo',
                            '-n',
                            passphrase,
                            '|',
                            GPG_BIN,
                            '-q',
                            '--sign',
                            '--local-user',
                            key_id,
                            '--batch',
                            '--passphrase-fd',
                            '0',
                            '--output',
                            '/dev/null',
                            '--yes',
                            test_file,
                        ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_verify_command)
    os.remove(test_file)
    stop_agent()
    if command_returncode == 0:
        return True
    else:
        return False

def change_passphrase(key_id, old_passphrase, new_passphrase, debug=False):
    """ Change GnuPG passphrase. """
    from otpme.lib import multiprocessing
    #print("Changing GPG passphrase...")
    gpg_change_passphrase_command = '%s --expert --edit-key -a %s' % (GPG_BIN, key_id)
    gpg_prompt = 'gpg> '

    child = pexpect.spawn(gpg_change_passphrase_command)
    if debug:
        child.logfile = sys.stdout

    # start thread to handover token PIN to gpg-agent via socket
    passphrases = [ old_passphrase, new_passphrase, new_passphrase ]
    pass_thread = multiprocessing.start_thread(name="change_pass", target=send_passphrases, target_args=("change_pass", passphrases))

    child.expect(gpg_prompt, timeout=300)
    child.sendline('passwd')
    child.expect(gpg_prompt, timeout=300)
    child.sendline('quit')
    child.expect(r'Save changes.*', timeout=300)
    child.sendline('y')
    child.wait()
    pass_thread.join()

    return True

def change_sc_pin(old_pin, new_pin, admin_pin=False, debug=False):
    """ Change smartcard PIN. """
    from otpme.lib import multiprocessing

    gpg_change_pin_command = '%s --change-pin' % GPG_BIN

    child = pexpect.spawn(gpg_change_pin_command)
    if debug:
        child.logfile = sys.stdout

    # Start thread to handover smartcard PIN to gpg-agent via socket.
    passphrases = [ old_pin, new_pin, new_pin ]
    pass_thread = multiprocessing.start_thread(name="change_pin", target=send_passphrases, target_args=("change_pin", passphrases))

    child.expect(r'Your selection.*', timeout=300)
    if admin_pin:
        child.sendline('3')
    else:
        child.sendline('1')
    #child.expect('PIN changed.', timeout=300)
    child.expect(r'Your selection.*', timeout=300)
    child.sendline('q')
    child.wait()
    pass_thread.join()

    #print("Unable to change smartcard PIN.")
    return True

def send_passphrases(name, passphrases=[], debug_file=None):
    """ Send card PIN to gpp-agent/pinentry via unix socket. """
    #debug_file = "/tmp/otpme.log"
    log = None
    if debug_file:
        log = open(debug_file, "a")
    if os.path.exists(SOCKET_FILE):
        if debug_file:
            msg = "Socket exists: %s\n" % SOCKET_FILE
            log.write(msg)
            log.flush()
        os.remove(SOCKET_FILE)
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.bind(SOCKET_FILE)
    filetools.set_fs_permissions(path=SOCKET_FILE, mode=0o700)
    _socket.listen(1)
    count = 0
    while True:
        # Wait for client connection.
        try:
            new_connection, new_client_socket = _socket.accept()
        except Exception as e:
            new_connection = None

        if not new_connection:
            continue

        # Get process infos from connecting PID.
        try:
            SO_PEERCRED = 17
            creds = new_connection.getsockopt(socket.SOL_SOCKET,
                                            SO_PEERCRED,
                                            struct.calcsize('3i'))
            client_pid, \
            client_uid, \
            client_gid = struct.unpack('3i',creds)
        except Exception as e:
            if debug_file:
                msg = "Unable to get client infos from socket: %s\n" % e
                log.write(msg)
                log.flush()
            raise

        if debug_file:
            msg = "new connection: %s: %s\n" % (name, client_pid)
            log.write(msg)
            log.flush()

        send_passphrase = "%s" % passphrases[count]
        send_passphrase = send_passphrase.encode()

        try:
            new_connection.send(send_passphrase)
            count += 1
        except Exception as e:
            if debug_file:
                msg = "Unable to send passphrase: %s\n" % e
                log.write(msg)
                log.flush()
            pass

        if len(passphrases) == count:
            if debug_file:
                msg = "close client: %s: (%s/%s)\n" % (name, count, len(passphrases))
                log.write(msg)
                log.flush()
            break

    _socket.close()
    os.remove(SOCKET_FILE)

def receive_passphrase():
    """
    Helper function to receive card PIN via unix socket
    when called from gpg-agent as pinentry wrapper.
    """
    if not os.path.exists(SOCKET_FILE):
        raise Exception("Socket file does not exist: %s" % SOCKET_FILE)
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.settimeout(3)
    _socket.connect(SOCKET_FILE)
    try:
        passphrase = _socket.recv(1024)
        if passphrase == "":
            raise Exception("Empty string received.")
    except Exception as e:
        _socket.close()
        raise Exception("Socket error: %s" % e)
    _socket.close()
    return passphrase

def is_authorized(auth_pid, pid):
    """
    Helper fucntion to check if PID is authorized
    to get passphrase via socket.
    """
    try:
        proc = psutil.Process(int(auth_pid))
        # WORKAROUND: proc.get_children() changed to
        #             proc.children() between versions.
        try:
            proc_children = proc.children(recursive=True)
        except:
            proc_children = proc.get_children(recursive=True)
        # Walk through all child processes of client_pid and
        # check if one is the requesting process.
        for proc in proc_children:
            try:
                if proc.pid == pid:
                    return True
            except Exception as e:
                pass
    except Exception as e:
        print("Exception in is_authorized(): %s" % e)
        pass
    return False

def start_agent(pinentry=None):
    """ Start gpg-agent. """
    if pinentry is None:
        pinentry = os.path.realpath(__file__)
        if pinentry.endswith('.pyc'):
            pinentry = my_path[:-1]

    while True:
        agent_pid = stuff.get_pid_by_name('gpg-agent')
        if not agent_pid:
            break
        stuff.kill_pid(agent_pid)

    if not os.path.exists("%s/private-keys-v1.d" % gpg_dir):
        # Create private keys dir to prevent agent startup problems
        filetools.create_dir("%s/private-keys-v1.d" % gpg_dir, mode=0o700)
    gpg_agent_command = [
                        'gpg-agent',
                        '--daemon',
                        '--enable-ssh-support',
                        '--allow-preset-passphrase',
                        #'--log-file',
                        #'/tmp/gpg-agent-log',
                        '--pinentry-program',
                        pinentry,
                    ]
    agent_returncode, \
    agent_stdout, \
    agent_stderr, \
    agent_pid = system_command.run(command=gpg_agent_command)
    if agent_returncode != 0:
        raise Exception("Error starting gpg-agent: %s" % agent_stderr)
    agent_stdout = agent_stdout.decode()
    ssh_agent_name, \
    ssh_agent_pid, \
    ssh_auth_sock, \
    gpg_agent_info = stuff.get_agent_vars(agent_stdout)
    if not ssh_agent_pid:
        system_user = config.system_user()
        ssh_agent_pid = stuff.get_pid(name='gpg-agent', user=system_user)[0]

    if ssh_auth_sock:
        os.environ['SSH_AUTH_SOCK'] = ssh_auth_sock

    if gpg_agent_info:
        os.environ['GPG_AGENT_INFO'] = gpg_agent_info

    return ssh_agent_pid, ssh_auth_sock, gpg_agent_info

def stop_agent():
    """ Stop gpg-agent. """
    system_user = config.system_user()
    stuff.kill_proc(name='gpg-agent', user=system_user, timeout=5)
    stuff.kill_proc(name='scdaemon', user=system_user, timeout=5)


# Run as fake pinentry if called from gpg-agent
if __name__ == '__main__':
    try:
        #from otpme.lib.pinentry import pinentry
        from otpme.lib.pinentry.wrapper import pinentry_wrapper
        ppid_name = stuff.get_pid_name(os.getppid())
        agent_name = "gpg-agent"
        #agent_name = "bash"
        if ppid_name == agent_name:
            #debug_file = "/tmp/pinentry.log"
            debug_file = None
            pinentry_wrapper(pinentry_bin="pinentry",
                            pinentry_opts=None,
                            #wrapper=True,
                            debug_file=debug_file,
                            pin_function=receive_passphrase)
        sys.exit(0)
    except Exception as e:
        print("Error running pinentry function: %s" % e)
        raise
