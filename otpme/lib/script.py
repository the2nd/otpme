# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
# python3.
try:
    from thread import *
except:
    from _thread import *

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import system_command
from otpme.lib import multiprocessing
from otpme.lib.classes import signing
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

logger = config.logger

def get(script_path):
    """ Get OTPme script with UUID and signatures. """
    if config.host_data['type'] == "node" and config.use_backend:
        result = backend.search(object_type="script",
                                attribute="rel_path",
                                value=script_path,
                                return_type="instance",
                                realm=config.realm)
        if not result:
            msg = (_("Unable to find script: %s") % script_path)
            raise OTPmeException(msg)
        s = result[0]
        script = decode(s.script, "base64")
        signatures = s.signatures
        script_uuid = s.uuid
    else:

        from otpme.lib.classes.command_handler import CommandHandler
        command_handler = CommandHandler(interactive=False)

        # Try to get script.
        try:
            script = command_handler.get_script(script_path=script_path)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting script: %s: %s") % (script_path, e))
            raise OTPmeException(msg)

        # Try to get script UUID.
        try:
            script_uuid = command_handler.get_script_uuid(script_path=script_path)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting script UUID: %s: %s") % (script_path, e))
            raise OTPmeException(msg)

        # Try to get script signatures.
        try:
            signatures = command_handler.get_script_sign(script_path=script_path)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error getting script signatures: %s: %s")
                    % (script_path, e))
            raise OTPmeException(msg)

    return script, script_uuid, signatures

def run(script_type, script_path, realm=None, site=None, options=None,
    script_uuid=None, script=None, variables=None, verify_signatures=True,
    signers=None, signatures=None, script_env=None, call=True, return_proc=False,
    user=None, group=None, groups=None, **kwargs):
    """ Run OTPme script. """
    if call and return_proc:
        msg = (_("Cannot use 'call' and 'return_proc' together."))
        raise OTPmeException(msg)

    if not script_path:
        msg = "Missing script path."
        raise OTPmeException(msg)

    # Set default user.
    if user is None:
        user = config.system_user()

    # Get users groups.
    if group is None or groups is None:
        user_groups = system_command.get_user_groups(user)
        if group is None:
            group = user_groups['group']
        if groups is None:
            groups = user_groups['groups']

    # Some logging.
    log_user = user
    log_group = group
    log_groups = ",".join(groups)
    msg = ("Running script: %s: user=%s, group=%s, groups=%s"
        % (script_path, log_user, log_group, log_groups))
    logger.debug(msg)

    script_name = script_path.split("/")[-1]

    # Get script if none was given.
    if not script or not script_uuid:
        script, script_uuid, signatures = get(script_path)

    # Get default signers if none are given.
    if verify_signatures and not signers:
        signers = signing.get_signers(signer_type=script_type,
                                    username=config.system_user())

    # Verify script signatures if needed.
    if verify_signatures and signers:
        # Verify signatures.
        try:
            signing.verify_signatures(signer_type=script_type,
                                    signatures=signatures,
                                    sign_data=script,
                                    signers=signers,
                                    stop_on_fist_match=True)
        except OTPmeException as e:
            config.raise_exception()
            msg = (_("Failed to verify script signatures: %s") % e)
            raise OTPmeException(msg)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error verifying signatures: %s") % e)
            raise OTPmeException(msg)

    # Will hold the command line parameters we get from 'variables'.
    command_line = []

    if not script_env:
        # Get a copy of our shell environment.
        script_env = os.environ.copy()

    # Add OTPme's binary path to scripts environment.
    script_env['OTPME_BIN_DIR'] = config.bin_dir

    # If the user we have to run the script as differs from the current system
    # user set $HOME and $USER variables.
    if user and user != config.system_user():
        user_home = os.path.expanduser("~%s" % user)
        script_env['USER'] = user
        script_env['HOME'] = user_home

    if options is not None:
        options_type = type(options)
        if options_type != list:
            msg = (_("options must be <list> not <%s>.") % options_type)
            raise OTPmeException(msg)

    if variables and options:
        # Walk through script argv's
        for i in list(options):
            # Check if we found a variable name that should be added to the
            # script's environment.
            if i.startswith("[") and i.endswith("]"):
                # Remove surrounding '[]' from variable name.
                var_name = re.sub('^\[', '', i)
                var_name = re.sub('\]$', '', var_name)
                # Try to set bash variable (uppercase) from the dictionary.
                try:
                    # Get var type.
                    var_val = variables[var_name.lower()]
                    # Only put env variables that are not bool/None.
                    if not isinstance(var_val, bool) and var_val is not None:
                        script_env[var_name] = str(variables[var_name.lower()])
                except:
                    msg = (_("Unknown variable in script command: %s: %s")
                            % (script_path, var_name))
                    raise OTPmeException(msg)
                # Remove special option from options.
                options.remove(i)

            # Check if we found a variable name that should be added to script's
            # command line (argv).
            elif i.startswith("%"):
                # Remove leading '%'
                var_name = i.replace("%", "")
                # Try to get variable value from dictionary.
                try:
                    var_value = variables[var_name.lower()]
                except:
                    msg = (_("Unknown variable in script command: %s: %s")
                            % (script_path, var_name))
                    raise OTPmeException(msg)
                # Check if we got a bool or None value and convert it to an
                # emtpy script parameter.
                if isinstance(var_value, bool) or var_value is None:
                    command_line.append("")
                else:
                    command_line.append(var_value)
                # Remove special option from options.
                options.remove(i)

            # Handle script options and parameters without special meaning
            # (e.g. no otpme variable).
            else:
                command_line.append(i)

    # Warn if script runs as root.
    if user == "root":
        msg = "Running script as user root: %s" % script_path
        logger.warning(msg)
    if group == "root":
        msg = "Running script as group root: %s" % script_path
        logger.warning(msg)

    # Create temp script file.
    script_file = "%s/%s.%s" % (config.tmp_dir,
                                script_name,
                                stuff.gen_secret())
    filetools.create_file(path=script_file,
                            content=script,
                            user=user,
                            mode=0o700)
    # Build script command.
    script_command = [script_file]
    script_command += command_line

    if options:
        script_command += options

    # Start script.
    if call:
        return_val = system_command.run(command=script_command,
                                        env=script_env,
                                        user=user,
                                        group=group,
                                        groups=groups,
                                        **kwargs)
    else:
        return_val = system_command.run(command=script_command,
                                        return_proc=return_proc,
                                        env=script_env,
                                        user=user,
                                        group=group,
                                        groups=groups,
                                        **kwargs)
    if return_proc:
        def _remove_file():
            # Wait for process to finish.
            return_val.wait()
            # Remove temporary script file.
            os.remove(script_file)
        multiprocessing.start_thread(name="remove_script",
                                    target=_remove_file,
                                    daemon=True)
        return return_val

    # Remove temporary script file.
    os.remove(script_file)

    # Make sure script output is string.
    return_code, script_stdout, script_stderr, pid = return_val
    script_stdout = script_stdout.decode()
    script_stderr = script_stderr.decode()

    # Return script status etc.
    return return_code, script_stdout, script_stderr, pid
