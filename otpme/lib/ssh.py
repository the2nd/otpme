# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from Crypto.PublicKey import RSA

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib.encoding.base import encode
from otpme.lib.classes.signing import get_signers
from otpme.lib.classes.signing import verify_signatures

from otpme.lib.exceptions import *

logger = config.logger

def gen_ssh_key_pair():
    """ Generate SSH private/public key pair. """
    new_key = RSA.generate(2048, e=65537)
    #public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")

    command = [
                "echo",
                "-n",
                private_key,
                "|",
                "ssh-keygen",
                "-y",
                "-f",
                "/dev/stdin",
            ]
    command_returncode, \
    command_stdout, \
    command_stderr, \
    command_pid = system_command.run(command)
    public_key = command_stdout.replace("\n", "")

    return private_key, public_key

def copy_ssh_key(public_key, public_key_comment, host, private_key=None):
    """ Copy SSH public key to given host. """
    authorized_keys_file = "/root/.ssh/authorized_keys"
    # Command to run.
    ssh_command = f"if ! grep '{public_key}' {authorized_keys_file} > /dev/null 2>&1 ; then echo '# {public_key_comment}\n{public_key}' >> {authorized_keys_file}; fi"
    # Run command
    command_return = run_ssh_command(host=host,
                                    ssh_command=ssh_command,
                                    private_key=private_key)
    return command_return

def run_ssh_command(host, ssh_command,
    stdin_command=None, stdout_command=None, private_key=None):
    """
    Run SSH command with optional stdin_command and stdout_command in a PIPE.
    """
    ssh_key_opt = ""
    ssh_key_file = None
    if private_key:
        # Create tempfile with site's private key
        ssh_key_file = filetools.create_temp_file(content=private_key, mode=0o600)
        ssh_key_opt = f"-i {ssh_key_file}"
    # Build command string
    command = [ "ssh", ssh_key_opt, host, '"', ssh_command, '"' ]
    if stdin_command is not None:
        x_type = type(stdin_command)
        if x_type != list:
            raise Exception(f"Excpected stdin_command as <list>. Got {x_type}")
        stdin_command.append("|")
        stdin_command += command
    if stdout_command is not None:
        x_type = type(stdout_command)
        if x_type != list:
            raise Exception(f"Excpected stdout_command as <list>. Got {x_type}")
        command.append("|")
        command += stdout_command
    # Run command
    command_return = system_command.run(command)
    # Remove tempfile
    if ssh_key_file:
        os.remove(ssh_key_file)
    return command_return

def add_agent_key(ssh_key, passphrase=None):
    """ Add SSH private key to SSH agent. """
    import pexpect
    import tempfile
    from otpme.lib import filetools
    os.environ['LANG'] = ''
    result = None
    connection_error = "Could not open a connection to your authentication agent."
    passphrase_prompt = 'Enter passphrase for .*'
    bad_passphrase = 'Bad passphrase, .*'
    key_added = 'Identity added: .*'
    try:
        # Create FIFO to pass on SSH key to ssh-add(1).
        fifo = tempfile.mktemp()
        os.mkfifo(fifo)
        filetools.set_fs_permissions(path=fifo, mode=0o600)
        # The ssh-add command.
        ssh_add_command = f'ssh-add {fifo}'
        # Start command
        child = pexpect.spawn(ssh_add_command)
        # Handle connection error.
        try:
            child.expect(connection_error, timeout=0.1)
            connection_failed = True
        except:
            connection_failed = False
        if connection_failed:
            result = 3
        else:
            # Write SSH key to file
            fd = open(fifo, "w")
            fd.write(ssh_key)
            fd.close()
            # Excpect passphrase prompt and send passphrase.
            if passphrase:
                child.expect(passphrase_prompt, timeout=0.1)
                child.sendline (passphrase)
            result = child.expect([key_added,
                                    bad_passphrase,
                                    passphrase_prompt],
                                    timeout=0.1)
    except Exception as e:
        result = str(e)
    finally:
        os.remove(fifo)
        if result == 1:
            raise Exception("Bad passphrase.")
        elif result == 2:
            raise Exception("Key is protected with a passphrase.")
        elif result == 3:
            raise Exception("Unable to connect to ssh-agent.")
        elif result != 0:
            raise Exception("Unknown error while running ssh-add(1) command.")

def gen_challenge(ssh_public_key, otp_len=0):
    """ Generate OTPme SSH challenge. """
    epoch_time = str(int(time.time()))
    nonce = stuff.gen_secret(len=32)
    challenge = f"{epoch_time}:{otp_len}:{nonce}:{ssh_public_key}"
    return challenge

def sign_challenge(challenge):
    """ Sign OTPme SSH challenge. """
    from paramiko.agent import Agent

    rsa_message = None
    public_key = challenge.split(":")[3]

    sign_data_kwargs = {'data' : challenge}
    agent = Agent()
    agent_keys = agent.get_keys()

    if len(agent_keys) == 0:
        agent.close()
        raise Exception("Unable to get keys from ssh-agent.")

    for key in agent_keys:
        if public_key == key.get_base64():
            try:
                x = key.sign_ssh_data(**sign_data_kwargs)
            except Exception as e:
                config.raise_exception()
                msg = _("Error signing SSH challenge: {error}")
                msg = msg.format(error=e)
                raise Exception(msg)
            finally:
                agent.close()
            # Encode response.
            rsa_message = encode(x, "base64")
            break
    return rsa_message

def verify_sign(public_key, data, plaintext):
    """ Verify signed data with given public key. """
    from paramiko import Message
    from paramiko.rsakey import RSAKey
    rsa_key = RSAKey(data=public_key)
    rsa_message = Message(data)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    try:
        return_value = rsa_key.verify_ssh_sig(plaintext, rsa_message)
    except Exception as e:
        config.raise_exception()
        msg = _("Unable to verify SSH signature: {error}")
        msg = msg.format(error=e)
        raise Exception(msg)
    return return_value

def read_cached_ssh_keys():
    """ Read cached SSH keys from file. """
    ssh_keys = {}
    # File with cached SSH keys assigned to this host.
    keys_cache_file = f"{config.ssh_deploy_dir}/keys.json"
    if not os.path.exists(keys_cache_file):
        return ssh_keys
    # Read all cached SSH keys from file.
    try:
        fd = open(keys_cache_file, "r")
        ssh_keys_json_string = fd.read()
        fd.close()
    except Exception as e:
        msg = _("Unable to read SSH keys cache file: {error}")
        msg = msg.format(error=e)
        raise Exception(msg)
    # Decode cached SSH keys.
    try:
        ssh_keys = json.decode(ssh_keys_json_string)
    except Exception as e:
        msg = _("Unable to decode SSH keys: {error}")
        msg = msg.format(error=e)
        raise Exception(msg)
    return ssh_keys

def write_cached_ssh_keys(ssh_keys):
    """ Write SSH keys to cache file. """
    # File with cached SSH keys assigned to this host.
    keys_cache_file = f"{config.ssh_deploy_dir}/keys.json"
    # Write cache file.
    ssh_keys_json_string = json.encode(ssh_keys)
    try:
        filetools.create_file(path=keys_cache_file,
                            content=ssh_keys_json_string,
                            user=config.user,
                            group=config.group,
                            mode=0o660)
    except Exception as e:
        msg = _("Unable to create SSH keys cache file: {error}")
        msg = msg.format(error=e)
        raise Exception(msg)

def update_authorized_keys():
    """ Update SSH authorized_keys files from cache. """
    from otpme.lib import backend
    authorized_keys = {}

    # Get SSH keys assigned to this host.
    all_ssh_keys = read_cached_ssh_keys()

    # Get currently cached authorized_keys users.
    orphan_authorized_keys = os.listdir(config.authorized_keys_dir)

    # Try to get own host.
    try:
        host_name = config.host_data['name']
        host_type = config.host_data['type']
    except:
        msg = _("Failed to load host data.")
        raise OTPmeException(msg)
    result = backend.search(object_type=host_type,
                            attribute="name",
                            value=host_name,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
    if not result:
        msg = _("Uuuhhh, unable to find own host: {host_name}")
        msg = msg.format(host_name=host_name)
        raise OTPmeException(msg)

    myhost = result[0]
    # Check host status.
    if myhost.enabled:
        # Verify host policies.
        try:
            myhost.run_policies("authenticate")
        except PolicyException as e:
            if orphan_authorized_keys:
                log_msg = _("Not adding SSH keys: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.debug(log_msg)
            # We need to emtpy all SSH keys if policy check fails.
            all_ssh_keys = {}
        except Exception as e:
            config.raise_exception()
    else:
        log_msg = _("Not adding SSH keys: {host_type} disabled", log=True)[1]
        log_msg = log_msg.format(host_type=myhost.type)
        logger.debug(log_msg)
        # We need to emtpy all SSH keys if host is disabled.
        all_ssh_keys = {}

    # Users we have checked policies for.
    processed_users = {}
    processed_tokens = {}
    # Check for valid signatures, policy restrictions etc.
    for token_uuid in all_ssh_keys:
        token_entry = all_ssh_keys[token_uuid]
        user_uuid = token_entry['user_uuid']
        token_path = token_entry['token_path']
        token_options = token_entry['token_options']
        #ssh_key = token_entry['ssh_key']
        #key_opts = token_entry['key_opts']
        #signatures = token_entry['signatures']
        unknown_token_msg = _("Ignoring SSH key from unknown token", log=True)[1]
        unknown_dst_token_msg = _("Ignoring unknown linked token", log=True)[1]
        disabled_token_msg = _("Ignoring SSH key from disabled token", log=True)[1]
        no_key_token_msg = _("Ignoring token without SSH key", log=True)[1]
        no_ssh_token_msg = _("Ignoring non-SSH token", log=True)[1]

        # Check if token exists.
        token = backend.get_object(object_type="token", uuid=token_uuid)
        if not token:
            log_msg = f"{unknown_token_msg}: {token_path}"
            logger.warning(log_msg)
            continue
        if not token.enabled:
            log_msg = f"{disabled_token_msg}: {token_path}"
            logger.debug(log_msg)
            continue

        # Users to run policies for etc.
        check_users = [user_uuid]
        # Tokens to run policies for etc.
        check_tokens = [token]

        # The token with the SSH public key.
        verify_token = token

        # Handle linked tokens.
        if token.token_type == "link":
            log_msg = _("Found linked token: {token_path}", log=True)[1]
            log_msg = log_msg.format(token_path=token_path)
            logger.debug(log_msg)
            # Make sure we check the user of the linked token.
            check_users.append(token.owner_uuid)
            # Get destination token.
            try:
                dst_token = token.get_destination_token()
            except:
                dst_token = None
            if not dst_token:
                log_msg = f"{unknown_dst_token_msg}: {token_path}"
                logger.warning(log_msg)
                continue
            if not dst_token.enabled:
                log_msg = f"{disabled_token_msg}: {dst_token.rel_path}"
                logger.debug(log_msg)
                continue
            verify_token = dst_token
            check_tokens.append(dst_token)

        if verify_token.token_type != "ssh":
            log_msg = f"{no_ssh_token_msg}: {verify_token}"
            logger.debug(log_msg)
            continue

        if not verify_token.ssh_public_key:
            log_msg = f"{no_key_token_msg}: {verify_token}"
            logger.debug(log_msg)
            continue

        # Make sure user/token owner exists, is enabled and run policies.
        for uuid in check_users:
            if uuid in processed_users:
                continue
            # Get user.
            x_user = backend.get_object(object_type="user", uuid=uuid)
            if not x_user:
                # Make sure we do not process a unknown user more than once.
                processed_users[uuid] = None
                log_msg = _("Ignoring SSH key from unknown user: {uuid}", log=True)[1]
                log_msg = log_msg.format(uuid=uuid)
                logger.warning(log_msg)
                continue

            # Add user to list of processed users.
            processed_users[uuid] = x_user

            if not x_user.enabled:
                log_msg = _("Ignoring SSH key from disabled user: {user_oid}", log=True)[1]
                log_msg = log_msg.format(user_oid=x_user.oid)
                logger.debug(log_msg)
                continue

            # Check user policies.
            try:
                x_user.run_policies("authenticate")
            except PolicyException as e:
                log_msg = str(e)
                logger.debug(log_msg)
                continue
            except Exception as e:
                config.raise_exception()

        # Run token policies.
        for x_token in check_tokens:
            if x_token.uuid in processed_tokens:
                continue
            processed_tokens[x_token.uuid] = x_token
            # Check token policies.
            try:
                x_token.run_policies("authenticate")
            except PolicyException as e:
                log_msg = str(e)
                logger.debug(log_msg)
                continue
            except Exception as e:
                config.raise_exception()
                log_msg = str(e)
                logger.debug(log_msg)
                continue

        # Filter SSH authorized_keys options.
        key_opts = []
        if token_options:
            for opt in token_options.split(","):
                if "=" in opt:
                    o = opt.split("=")[0]
                    v = "=".join(opt.split("=")[1:])
                    option = f'{o}={v}'
                else:
                    o = opt
                    option = opt
                if o not in verify_token.valid_token_options:
                    log_msg = _("Ignoring unknown token option: {token_path}: {o}", log=True)[1]
                    log_msg = log_msg.format(token_path=verify_token.rel_path, o=o)
                    logger.warning(log_msg)
                    continue
                key_opts.append(option)

        # Try to authorize token for this host (e.g. run role/group policies).
        try:
            myhost.authorize_token(token, login_interface="ssh")
        except LoginsLimited as e:
            log_msg = str(e)
            logger.debug(log_msg)
            continue
        except PolicyException as e:
            log_msg = str(e)
            logger.debug(log_msg)
            continue
        except Exception as e:
            config.raise_exception()

        # The system user that logs in via SSH.
        system_user = processed_users[user_uuid]
        # OTPME_USER variable to be added to key options.
        otpme_user_env = f'environment="OTPME_USER={system_user.name}"'

        # Get signers.
        signers = get_signers(signer_type="token", username=system_user.name)
        if signers:
            signatures = verify_token.signatures
            # Without signatures the key will not be allowed to login.
            if not signatures:
                log_msg = _("Ignoring SSH key without signatures: {token_path}", log=True)[1]
                log_msg = log_msg.format(token_path=token_path)
                logger.info(log_msg)
                continue

            # Add user tag to make sure the token is assigned to the right user.
            user_tag = f"user:{user_uuid}"
            # Remove OTPME_USER from token opts because we never add a sign
            # tag for this option.
            token_opts = dict(key_opts)
            try:
                token_opts.remove(otpme_user_env)
            except:
                pass
            # Add token options to e.g. prevent an SSH key from being used for
            # interactive login even if the "command=" option is used.
            check_tags = [user_tag]
            if token_opts:
                opts_tag = f"options:{','.join(token_opts)}"
                check_tags.append(opts_tag)

            # Verify signatures.
            sign_data  = verify_token.get_sign_data(verify_acls=False)
            try:
                verify_signatures(signer_type="token",
                                signers=signers,
                                signatures=signatures,
                                sign_data=sign_data,
                                stop_on_fist_match=True)
            except:
                continue

        # Add OTPME_USER to environment.
        if otpme_user_env not in key_opts:
            key_opts.append(otpme_user_env)

        # Build authorized_keys line.
        line = f"{','.join(key_opts)} ssh-{verify_token.key_type} {verify_token.ssh_public_key} {token.rel_path}"

        system_user_name = system_user.name
        if not system_user_name in authorized_keys:
            authorized_keys[system_user_name] = {}
        if not 'user_uuid' in authorized_keys[system_user_name]:
            authorized_keys[system_user_name]['user_uuid'] = system_user.uuid
        if not 'authorized_keys' in authorized_keys[system_user_name]:
            authorized_keys[system_user_name]['authorized_keys'] = []
        authorized_keys[system_user_name]['authorized_keys'].append(line)

    # Build authorized_keys file for all valid SSH tokens.
    authorized_keys_changed = False
    denied_users = []
    for username in authorized_keys:
        user_uuid = authorized_keys[username]['user_uuid']
        user_keys = sorted(authorized_keys[username]['authorized_keys'])
        authorized_keys_dir = f"{config.authorized_keys_dir}/{username}"
        authorized_keys_file = f"{authorized_keys_dir}/authorized_keys"
        authorized_keys_content = "\n".join(user_keys)

        # Check if user is allowed to login.
        try:
            stuff.check_login_user(user_name=username, user_uuid=user_uuid)
        except Exception as e:
            log_msg = _("Not adding SSH key: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            denied_users.append(log_msg)
            continue

        # Remove processed user from orphans list.
        try:
            orphan_authorized_keys.remove(username)
        except:
            pass

        current_keys = []
        new_keys = list(authorized_keys[username]['authorized_keys'])
        if os.path.exists(authorized_keys_file):
            try:
                fd = open(authorized_keys_file, "r")
                current_file_content = fd.read()
                current_keys = current_file_content.split("\n")
                fd.close()
            except Exception as e:
                log_msg = _("Unable to read current authorized_keys file: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.critical(log_msg)
                continue

            # If nothing changed skip this user.
            if current_file_content == authorized_keys_content:
                continue

            # Count new and removed keys.
            for line in list(current_keys):
                if len(line) == 0:
                    current_keys.remove(line)
                    continue
                if line not in new_keys:
                    continue
                new_keys.remove(line)
                current_keys.remove(line)

        if not os.path.exists(authorized_keys_dir):
            try:
                filetools.create_dir(path=authorized_keys_dir,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o770)
            except Exception as e:
                log_msg = _("Unable to create authorized_keys cache dir: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                logger.critical(log_msg)
                continue

        # Write cache file.
        try:
            filetools.create_file(path=authorized_keys_file,
                                content=authorized_keys_content,
                                user=config.user,
                                group=config.group,
                                mode=0o660)
        except Exception as e:
            log_msg = _("Unable to create authorized_keys cache file: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.critical(log_msg)
            continue

        added_keys = len(new_keys)
        if added_keys > 0:
            log_msg = _("Added {added_keys} SSH key(s) for user {username}.", log=True)[1]
            log_msg = log_msg.format(added_keys=added_keys, username=username)
            logger.info(log_msg)
        removed_keys = len(current_keys)
        if removed_keys > 0:
            log_msg = _("Removed {removed_keys} SSH key(s) of user {username}.", log=True)[1]
            log_msg = log_msg.format(removed_keys=removed_keys, username=username)
            logger.info(log_msg)
        authorized_keys_changed = True

    # Remove orphan authorized_keys.
    for username in orphan_authorized_keys:
        orphan_dir = f"{config.authorized_keys_dir}/{username}"
        orphan_keys_file = f"{orphan_dir}/authorized_keys"
        orphan_tokens_file = f"{orphan_dir}/keys.json"
        if os.path.exists(orphan_keys_file):
            # Remove authorized_keys file.
            try:
                os.remove(orphan_keys_file)
            except Exception as e:
                log_msg = _("Error removing authorized_keys file: {orphan_keys_file}", log=True)[1]
                log_msg = log_msg.format(orphan_keys_file=orphan_keys_file)
                logger.warning(log_msg)
            # Remove token cache file.
            if os.path.exists(orphan_tokens_file):
                try:
                    os.remove(orphan_tokens_file)
                except Exception as e:
                    log_msg = _("Error removing SSH tokens file: {orphan_tokens_file}", log=True)[1]
                    log_msg = log_msg.format(orphan_tokens_file=orphan_tokens_file)
                    logger.warning(log_msg)
            # Remove cache dir.
            try:
                os.rmdir(orphan_dir)
            except Exception as e:
                log_msg = _("Error removing authorized_keys directory: {orphan_dir}", log=True)[1]
                log_msg = log_msg.format(orphan_dir=orphan_dir)
                logger.warning(log_msg)
            log_msg = _("Removed all SSH keys of user: {username}", log=True)[1]
            log_msg = log_msg.format(username=username)
            logger.info(log_msg)
            authorized_keys_changed = True

    if authorized_keys_changed:
        for log_msg in denied_users:
            logger.warning(log_msg)
    else:
        log_msg = _("SSH authorized_keys up-to-date.", log=True)[1]
        logger.info(log_msg)

    # Update directory timestamp to notify probably running
    # otpme-get-authorized-keys that we have finished.
    now = time.time()
    os.utime(config.authorized_keys_dir,(now, now))
