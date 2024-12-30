# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pwd
import grp
import signal
from subprocess import PIPE
from subprocess import Popen
#from subprocess import DEVNULL
from subprocess import call as _call

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

logger = config.logger

def get_user_groups(user):
    """ Get (system) users groups. """
    if user is None:
        msg = "Need <user> as string."
        raise OTPmeException(msg)

    user_group = pwd.getpwnam(user).pw_gid
    user_group = grp.getgrgid(user_group).gr_name
    user_groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]

    result = {
                'group'     : user_group,
                'groups'    : user_groups,
            }
    return result

def run(command, user=None, group=True, groups=True, return_proc=False,
    call=False, shell=False, return_proc_data=True,
    disable_ctrl_c=False, **kwargs):
    """ Run system command. """
    if shell is True:
        msg = ("Running system command with shell=True is dangerous!!!")
        logger.warning(msg)

    if user is None:
        user = config.system_user()

    if group is True or groups is True:
        user_groups = get_user_groups(user)
        if group is True:
            group = user_groups['group']
        if groups is True:
            groups = user_groups['groups']

    if user and not group:
        msg = ("Running system command with different user but keeping group "
                "membership.")
        logger.warning(msg)

    if call:
        stdout = None
        stderr = None
        if "stdout" in kwargs:
            stdout = kwargs.pop('stdout')
            if stdout is None:
                stdout = open(os.devnull, 'w')
        if "stderr" in kwargs:
            stderr = kwargs.pop('stderr')
            if stderr is None:
                stderr = open(os.devnull, 'w')
        try:
            return_val = _call(command,
                                shell=shell,
                                stdout=stdout,
                                stderr=stderr,
                                preexec_fn=demote(user=user,
                                                group=group,
                                                groups=groups,
                                                disable_ctrl_c=disable_ctrl_c),
                                **kwargs)
        except OSError as e:
            msg = "Failed to start command: %s: %s" % (command, e)
            raise OSError(msg)
        return return_val

    stdin = PIPE
    if "stdin" in kwargs:
        stdin = kwargs.pop('stdin')
        if stdin is None:
            stdin = open(os.devnull, 'w')
    stdout = PIPE
    if "stdout" in kwargs:
        stdout = kwargs.pop('stdout')
        if stdout is None:
            stdout = open(os.devnull, 'w')
    stderr = PIPE
    if "stderr" in kwargs:
        stderr = kwargs.pop('stderr')
        if stderr is None:
            stderr = open(os.devnull, 'w')

    # Start command.
    proc = Popen(command,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                shell=shell,
                preexec_fn=demote(user=user,
                                group=group,
                                groups=groups,
                                disable_ctrl_c=disable_ctrl_c),
                **kwargs)
    # Return proc if requested.
    if return_proc:
        return proc
    # Wait for process to finish.
    proc.wait()
    if not return_proc_data:
        return
    # Get command stdout and stderr.
    command_stdout, command_stderr = proc.communicate()
    # Get command exit code.
    command_returncode = proc.returncode
    # Get PID of command.
    command_pid = proc.pid
    return command_returncode, command_stdout, command_stderr, command_pid

def demote(user, group, groups=[], disable_ctrl_c=False):
    """ Drop privileges. """
    # Disable CTRL+C while script is running.
    if disable_ctrl_c:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    uid = None
    gid = None
    group_ids = []
    # Get group IDs.
    if groups:
        for g in groups:
            try:
                x = grp.getgrnam(g).gr_gid
            except Exception as e:
                msg = "Failed to resolve group: %s" % g
                raise OTPmeException(msg)
            group_ids.append(x)
    # Cannot drop privileges when not running as root.
    if config.system_user() != "root":
        return
    if user:
        uid = pwd.getpwnam(user).pw_uid
        if group:
            try:
                gid = grp.getgrnam(group).gr_gid
            except Exception as e:
                msg = "Failed to resolve group: %s" % group
                raise OTPmeException(msg)
    def set_ids():
        if gid:
            os.setgid(gid)
        # Set groups. By default this list is empty.
        os.setgroups(group_ids)
        if uid:
            os.setuid(uid)
    return set_ids
