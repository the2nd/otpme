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
    sys.path.append(my_path)

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.encoding.base import encode

GPG_BIN = "gpg"
socket_path = "/tmp/gpg-pinentry.sock"

user_home = os.getenv("HOME")
gpg_dir = "%s/.gnupg" % user_home
gpg_sshcontrol_file = "%s/sshcontrol" % gpg_dir
tmp_dir = "/dev/shm"

def find_preset_passhprase_bin():
    """ Try to find a valid gpg-preset-passphrase binary. """
    possible_paths = [
                    "/usr/libexec/gpg-preset-passphrase",
                    "/usr/lib/gnupg2/gpg-preset-passphrase",
                    ]
    for p in possible_paths:
        if os.path.exists(p):
            return p
    raise Exception("Unable to find gpg-preset-passphrase.")

gpg_preset_passphrase = find_preset_passhprase_bin()

try:
    import pexpect
except:
    raise Exception("Please install python pexpect module. (e.g. apt-get "
                    "install python-pexpect)")

# Make sure we get english messages (for use with expect)
os.environ['LANG'] = ''

# Unset display to prevent gpg-agent/pinentry issues.
try:
    del os.environ['DISPLAY']
except:
    pass

def get_gpg_version():
    """ Get GPG version. """
    from otpme.lib import system_command
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
    from otpme.lib import system_command
    sys.stdout.write("We need to generate a lot of random bytes. It is a good idea to perform\n")
    sys.stdout.write("some other action (type on the keyboard, move the mouse, utilize the\n")
    sys.stdout.write("disks) during the prime generation; this gives the random number\n")
    sys.stdout.write("generator a better chance to gain enough entropy.\n")
    sys.stdout.write("Generating GPG keys...")

    key_id = None
    gpg_batch_config = [
                'Key-Type: 1',
                'Key-Length: 2048',
                'Key-Usage: sign',
                'Subkey-Type: 1',
                'Subkey-Length: 2048',
                'Name-Real: ' + user_real_name,
                'Name-Email: ' + user_email,
                'Passphrase: ' + passphrase,
                'Expire-Date: 0',
                #'%pubring pubring.gpg',
                #'%secring secring.gpg',
                '%commit\n',
            ]

    gpg_batch_config = "\n".join(gpg_batch_config)
    gpg_batch_file = os.path.join(tmp_dir, "%s.gpg.batch" % user_email)
    fd = open(gpg_batch_file, "w")
    fd.write(gpg_batch_config)
    fd.close()
    #if sys.version_info[0] == 3:
    #    gpg_batch_config = gpg_batch_config.encode()

    #gpg_init_command = ['gpg2', '--batch', '--gen-key', '--debug-all', gpg_batch_file]
    gpg_init_command = [GPG_BIN, '--batch', '--gen-key', gpg_batch_file]
    #gpg_init_command = ['gpg2', '--batch', '--gen-key']
    proc = system_command.run(command=gpg_init_command, return_proc=True)
    #proc.stdin.write(gpg_batch_config)
    proc.stdin.flush()

    line = ""
    while stuff.check_pid(proc.pid):
        #x = proc.stderr.read(1)
        #line += x
        #sys.stdout.write('.')
        #if x == "\n":
        #   print("LINE:", line9
        #   if line.endswith('marked as ultimately trusted\n'):
        #       key_id = re.sub('.* (.*) marked as ultimately trusted\n$', r'\1', line)
        #       break
        #   line = ""
        stderr = proc.stderr.readline()
        if sys.version_info[0] == 3:
            stderr = stderr.decode()
        line = stderr.replace("\n", "")
        sys.stdout.write('.')
        if line.endswith('marked as ultimately trusted'):
            key_id = re.sub('.* (.*) marked as ultimately trusted$', r'\1', line)
            break
    print("")
    os.remove(gpg_batch_file)
    if not key_id:
        print("GPG init failed.")
        return False
    return key_id


def create_backup(key_id, backup_file, passphrase):
    """ Backup GPG keys to file. """
    print("Creating GPG backup...")
    from otpme.lib import system_command
    from threading import start_new_thread
    gpg_version = get_gpg_version()
    if gpg_version[0] == 2 and gpg_version[1] >=1:
        # start thread to handover backup password to gpg-agent.
        agent_pid = stuff.get_pid_by_name('gpg-agent')
        stuff.kill_pid(agent_pid)
        start_gpg_agent()
        agent_pid = stuff.get_pid_by_name('gpg-agent')
        passphrases = [ passphrase, passphrase ]
        start_new_thread(send_passphrases ,("backup_gpg", agent_pid, passphrases))

    if os.path.exists(backup_file):
        print("File already exists: %s" % backup_file)
        return False
    gpg_backup_command = [GPG_BIN, '--export-secret-keys', '-a', key_id]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_backup_command)
    if command_returncode == 0:
        filetools.create_file(path=backup_file, content=command_stdout, mode=0o600)
        return True
    print("GPG backup failed: %s" % command_stderr)
    return False


def restore_backup(backup_file, passphrase):
    """ Restore GPG keys from file. """
    from otpme.lib import system_command
    from threading import start_new_thread
    print("Restoring GPG backup...")
    gpg_version = get_gpg_version()
    if gpg_version[0] == 2 and gpg_version[1] >=1:
        # Start thread to handover backup password to gpg-agent.
        agent_pid = stuff.get_pid_by_name('gpg-agent')
        stuff.kill_pid(agent_pid)
        start_gpg_agent()
        agent_pid = stuff.get_pid_by_name('gpg-agent')
        passphrases = [ passphrase ]
        start_new_thread(send_passphrases ,("restore_gpg", agent_pid, passphrases))

    if not os.path.exists(backup_file):
        print("File does not exist: %s" % backup_file)
        return False
    gpg_restore_command = [GPG_BIN,
                        '--import',
                        '--allow-secret-key-import',
                        backup_file]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_restore_command)
    if command_returncode == 0:
        return True
    print("GPG restore failed: %s" % command_stderr)
    return False


def start_gpg_agent(pinentry_bin=None):
    """ Start GPG agent. """
    if pinentry_bin is None:
        pinentry_bin = my_path
    if not os.path.exists(gpg_dir + "/private-keys-v1.d"):
        # create private keys dir to prevent agent startup problems
        filetools.create_dir(gpg_dir + "/private-keys-v1.d", mode=0o700)
    #gpg_agent_command = ('gpg-agent --daemon --enable-ssh-support '
    #                    '--allow-preset-passphrase --pinentry-program %s'
    #                    % pinentry_bin)
    gpg_agent_command = ['gpg-agent',
                        '--daemon',
                        '--enable-ssh-support',
                        '--allow-preset-passphrase',
                        '--pinentry-program',
                        pinentry_bin]
    agent_returncode, \
    agent_stdout, \
    agent_stderr, \
    agent_pid = system_command.run(command=gpg_agent_command)
    if agent_returncode != 0:
        msg = ("Unable to start gpg-agent: " + agent_stderr)
        raise Exception(msg)
    ssh_agent_pid, ssh_auth_sock, gpg_agent_info = stuff.get_agent_vars(agent_stdout)
    if ssh_auth_sock:
        return ssh_agent_pid, ssh_auth_sock, gpg_agent_info


def remove_main_key(key_id, debug=False):
    """ Remove main GPG key from .gnupg dir. """
    from otpme.lib import system_command
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
    from otpme.lib import system_command
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
    from otpme.lib import system_command
    keygrip = None
    gpg_connect_command = 'ssh-add  -l;gpg-connect-agent "keyinfo --list" /bye'
    returncode, \
    stdout, \
    stderr, \
    pid = system_command.run(command=gpg_connect_command, shell=True)
    if returncode != 0:
        raise Exception(str(stderr))
    for line in stdout.split("\n"):
        if line.startswith('S KEYINFO '):
            keygrip = re.sub('^S KEYINFO ([^ ]*) T .*$', r'\1', line)
            break
    if not keygrip:
        raise Exception("Unable to get public sub keygrip.")
    return keygrip

def get_ssh_public_key():
    """ Get public key from smartcard (e.g. yubikey) via gpg-agent. """
    from otpme.lib import system_command
    gpg_command = [
                    'gpg-agent',
                    '--enable-ssh-support',
                    '--daemon',
                    'ssh-add',
                    '-L',
                ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command=gpg_command)
    stop_agent()
    if command_returncode != 0:
        return False
    # Cut off key type and comment
    ssh_public_key = command_stdout.split(" ")[1]
    return ssh_public_key

def get_main_key_id():
    """ Get GPG main key ID. """
    from otpme.lib import system_command
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

def key_to_card(key_id, sc_admin_pin, gpg_passphrase,
    agent_pid=None, debug=False):
    """ Move GPG sub key to card. """
    from otpme.lib import multiprocessing
    _stop_agent = False
    if not agent_pid:
        agent_pid = start_agent()[0]
        _stop_agent = True
        if not agent_pid:
            raise Exception("Unable to start gpg-agent.")

    gpg_version = get_gpg_version()
    if gpg_version.startswith("2.1."):
        # Start thread to handover token admin PIN to gpg-agent via socket
        passphrases = [ gpg_passphrase, sc_admin_pin ]
        multiprocessing.start_thread(send_passphrases, (agent_pid, passphrases))
    else:
        # Start thread to handover token admin PIN to gpg-agent via socket
        passphrases = [ sc_admin_pin ]
        multiprocessing.start_thread(send_passphrases, (agent_pid, passphrases))

        # Preset passphrase for local key when running "keytocard" command
        sub_keygrip = get_sub_keygrip()
        preset_command = [
                            'echo',
                            gpg_passphrase,
                            '|',
                            gpg_preset_passphrase,
                            '--preset',
                            sub_keygrip,
                        ]
        command_returncode, \
        command_stdout, \
        command_stderr, \
        command_pid = system_command.run(preset_command)
        if command_returncode != 0:
            raise Exception("Admin PIN preset failed: %s" % command_stderr)

    gpg_keytocard_command = '%s --expert --edit-key -a %s' % (GPG_BIN, key_id)
    gpg_prompt = 'gpg> '
    gpg_card_error = 'gpg: error writing key to card: Card error'
    gpg_operation_canelled = 'gpg: error writing key to card: Operation cancelled'

    child = pexpect.spawn(gpg_keytocard_command)
    if debug:
        child.logfile = sys.stdout

    child.expect(gpg_prompt, timeout=300)
    child.sendline('toggle')
    child.expect(gpg_prompt, timeout=300)
    child.sendline('key 1')
    child.expect(gpg_prompt, timeout=300)
    child.sendline('keytocard')
    child.expect('Your selection?', timeout=300)
    child.sendline('3')

    i = child.expect([gpg_prompt,
                    gpg_card_error,
                    gpg_operation_canelled],
                    timeout=300)
    if i == 1:
        child.sendline('quit')
        child.wait()
        raise Exception("GPG error: %s" % gpg_card_error)

    if i == 2:
        child.sendline('quit')
        child.wait()
        raise Exception("Operation cancelled.")

    #child.sendline('quit')
    #child.expect(r'Save changes.*', timeout=300)
    #child.sendline('y')
    child.sendline('save')
    child.wait()

    if _stop_agent:
        stop_agent()

    return True

def verify_passphrase(key_id, passphrase):
    """ Verify if GPG passphrase is correct. """
    from otpme.lib import system_command
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

def change_passphrase(key_id, old_passphrase,
    new_passphrase, agent_pid=None, debug=False):
    """ Change GnuPG passphrase. """
    from otpme.lib import multiprocessing
    _stop_agent = False
    if not agent_pid:
        agent_pid = start_agent()[0]
        _stop_agent = True
        if not agent_pid:
            raise Exception("Unable to start gpg-agent.")

    #print("Changing GPG passphrase...")
    gpg_change_passphrase_command = '%s --expert --edit-key -a %s' % (GPG_BIN, key_id)
    gpg_prompt = 'gpg> '

    child = pexpect.spawn(gpg_change_passphrase_command)
    if debug:
        child.logfile = sys.stdout

    # start thread to handover token PIN to gpg-agent via socket
    passphrases = [ old_passphrase, new_passphrase, new_passphrase ]
    multiprocessing.start_thread(send_passphrases, (agent_pid, passphrases))

    child.expect(gpg_prompt, timeout=300)
    child.sendline('passwd')
    child.expect(gpg_prompt, timeout=300)
    child.sendline('quit')
    child.expect(r'Save changes.*', timeout=300)
    child.sendline('y')
    child.wait()

    if _stop_agent:
        stop_agent()

    return True

def change_sc_pin(old_pin, new_pin, admin_pin=False,
    agent_pid=None, debug=False):
    """ Change smartcard PIN. """
    from otpme.lib import multiprocessing
    _stop_agent = False
    if not agent_pid:
        agent_pid = start_agent()[0]
        _stop_agent = True
        if not agent_pid:
            raise Exception("Unable to start gpg-agent.")

    gpg_change_pin_command = '%s --change-pin' % GPG_BIN

    child = pexpect.spawn(gpg_change_pin_command)
    if debug:
        child.logfile = sys.stdout

    # Start thread to handover smartcard PIN to gpg-agent via socket.
    passphrases = [ old_pin, new_pin, new_pin ]
    multiprocessing.start_thread(send_passphrases, (agent_pid, passphrases))

    child.expect(r'Your selection.*', timeout=300)
    if admin_pin:
        child.sendline('3')
    else:
        child.sendline('1')
    child.expect('PIN changed.', timeout=300)
    child.expect(r'Your selection.*', timeout=300)
    child.sendline('q')
    child.wait()

    if _stop_agent:
        stop_agent()

    #print("Unable to change smartcard PIN.")
    return True

def send_passphrases(name, agent_pid, passphrases=[], debug_file=None):
    """ Send card PIN to gpp-agent/pinentry via unix socket. """
    #debug_file = "/tmp/log"
    log = None
    if debug_file:
        log = open(debug_file, "a")
    if os.path.exists(socket_file):
        if debug_file:
            msg = "Socket exists: %s\n" % socket_file
            log.write(msg)
            log.flush()
        os.remove(socket_file)
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.bind(socket_file)
    filetools.set_fs_permissions(path=socket_file, mode=0o700)
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

        try:
            if not is_authorized(agent_pid, client_pid, log=log):
                if debug_file:
                    msg = "denied client: %s: %s\n" % (name, client_pid)
                    log.write(msg)
                    log.flush()
                new_connection.close()
                continue
        except Exception as e:
            if debug_file:
                msg = "exception: %s: %s\n" % (name, e)
                log.write(msg)
                log.flush()
            raise

        if debug_file:
            msg = "allowed client: %s: %s\n" % (name, client_pid)
            log.write(msg)
            log.flush()

        try:
            greeting = new_connection.recv(1024)
        except Exception as e:
            if debug_file:
                msg = "Error receiving client greeting: %s: %s\n" % (name, e)
                log.write(msg)
                log.flush()

        if debug_file:
            msg = "client greeting: %s\n" % greeting
            log.write(msg)
            log.flush()

        send_passphrase = "%s" % passphrases[count]
        if sys.version_info[0] == 3:
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

        try:
            reply = new_connection.recv(1024)
            new_connection.close()
        except Exception as e:
            if debug_file:
                msg = "Unable to receive reply: %s\n" % e
                log.write(msg)
                log.flush()
            pass

        if reply != send_passphrase:
            if debug_file:
                msg = "Got wrong verify passphrase from client: %s\n" % reply
                log.write(msg)
                log.flush()

        if len(passphrases) == count:
            if debug_file:
                msg = "close client: %s: (%s/%s)\n" % (name, count, len(passphrases))
                log.write(msg)
                log.flush()
            break

    _socket.close()
    os.remove(socket_file)

def receive_passphrase():
    """
    Helper function to receive card PIN via unix socket
    when called from gpg-agent as pinentry wrapper.
    """
    if not os.path.exists(socket_path):
        raise Exception("Socket file does not exist: %s" % socket_path)
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _socket.settimeout(3)
    _socket.connect(socket_path)
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

def start_agent():
    """ Start gpg-agent. """
    from otpme.lib import system_command
    my_path = os.path.realpath(__file__)
    if my_path.endswith('.pyc'):
        my_path = my_path[:-1]

    if not os.path.exists("%s/private-keys-v1.d" % gpg_dir):
        # Create private keys dir to prevent agent startup problems
        filetools.create_dir("%s/private-keys-v1.d" % gpg_dir, mode=0o700)
    gpg_agent_command = [
                        'gpg-agent',
                        '--daemon',
                        '--enable-ssh-support',
                        '--allow-preset-passphrase',
                        '--pinentry-program',
                        my_path,
                    ]
    agent_returncode, \
    agent_stdout, \
    agent_stderr, \
    agent_pid = system_command.run(command=gpg_agent_command)
    if agent_returncode != 0:
        print("LLLLLLL", agent_returncode, agent_stdout, agent_stderr)
        raise Exception("Error starting gpg-agent: %s" % agent_stderr)
    agent_stdout = agent_stdout.decode()
    ssh_agent_name, \
    ssh_agent_pid, \
    ssh_auth_sock, \
    gpg_agent_info = stuff.get_agent_vars(agent_stdout)
    if not ssh_agent_pid:
        system_user = config.system_user()
        ssh_agent_pid = stuff.get_pid(name='gpg-agent', user=system_user)[0]

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
    socket_file = "/tmp/yubikey_deploy.sock"
    try:
        #from otpme.lib.pinentry import pinentry
        from otpme.lib.pinentry.wrapper import pinentry_wrapper
        ppid_name = stuff.get_pid_name(os.getppid())
        agent_name = "gpg-agent"
        agent_name = "bash"
        if ppid_name == agent_name:
            debug_file = None
            debug_file = "/tmp/hallo"
            # Start pinentry/wrapper.
            #pinentry.run(pinentry_bin=None,
            pinentry_wrapper(pinentry_bin="pinentry",
                            pinentry_opts=None,
                            #wrapper=True,
                            debug_file=debug_file)
                            #pin_function=receive_passphrase)
        sys.exit(0)
    except Exception as e:
        print("Error running pinentry function: %s" % e)
        raise
