# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" What every operating system family has in common when running a
configuration management job.

The handler of a job type gets the arguments of the job as they came
over the wire. The signature of the job says that it comes from
somebody who may command this host; it does not say that its arguments
are sane, so every value that reaches a command is checked here first.
Nothing is ever run through a shell: a command is a list of arguments.

An operating system family brings its own class (see debian.py) and
fills in what differs -- packages, repositories, upgrading the host.
"""
import os
import re

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import filetools
from otpme.lib import system_command

from otpme.lib.exceptions import *

logger = config.logger

# What the arguments of a job may look like.
PACKAGE_NAME_RE = r'^[a-zA-Z0-9][a-zA-Z0-9+._-]{0,127}$'
REPO_NAME_RE = r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$'
SERVICE_NAME_RE = r'^[a-zA-Z0-9@][a-zA-Z0-9@._-]{0,127}$'
USER_NAME_RE = r'^[a-z_][a-z0-9_-]{0,31}$'
FILE_MODE_RE = r'^0[0-7]{3}$'
SIGNER_TYPE_RE = r'^[a-z][a-z_]{0,63}$'
# Only users and roles have keys that sign (OTPmeSigner.supported_signers).
SIGNER_OID_RE = r'^(user|role)[|][^\s\0]{1,1024}$'
# What del_signer and update_signer may name: the object, or the signer
# entry this host holds, by the uuid show_signer prints. The second is
# the only way left once the object is deleted, see run_signer_mgmt().
SIGNER_REF_RE = r'^((user|role)[|][^\s\0]{1,1024}|[0-9a-fA-F-]{36})$'
SIGNER_TAG_RE = r'^[^\s\0]{1,256}$'
# What a yes or no argument of a job may say.
TRUE_VALUES = ['true', 'yes', '1']
FALSE_VALUES = ['false', 'no', '0']

def parse_bool_arg(args, name, default=False):
    """ A yes or no argument of a job. Written as a word, because that
    is what fits on a command line.

    Outside the handler as well: whether a job runs at all is decided
    before there is a handler (confd/job.py), and that decision reads
    arguments too. """
    value = args.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        msg = _("Job argument is not a yes or no: {name}")
        msg = msg.format(name=name)
        raise OTPmeException(msg)
    value = value.strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    msg = _("Job argument must be one of {values}: {name}")
    msg = msg.format(values=", ".join(TRUE_VALUES + FALSE_VALUES),
                    name=name)
    raise OTPmeException(msg)

class ConfJobHandler(object):
    """ Runs the jobs of one operating system family. """
    # What /etc/os-release has to say for this handler to be the one.
    os_ids = []

    def __init__(self, logger=None):
        self.logger = logger or config.logger

    def get_installed_packages(self):
        """ The installed packages: {name: version}. """
        msg = _("Listing packages is not supported on this system.")
        raise OTPmeException(msg)

    def run(self, job_type, action, args, log_file):
        """ Run one job. Returns exit code and output. """
        handler = getattr(self, f"run_{job_type}", None)
        if handler is None:
            msg = _("Job type not supported on this system: {job_type}")
            msg = msg.format(job_type=job_type)
            raise OTPmeException(msg)
        return handler(action, args, log_file)

    # ---- The arguments of a job -------------------------------------

    def get_str_arg(self, args, name, regex, required=True):
        """ One argument of a job, checked against what it may look
        like. """
        value = args.get(name)
        if value is None:
            if not required:
                return None
            msg = _("Job misses argument: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        if not isinstance(value, str):
            msg = _("Job argument is not a string: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        if not re.match(regex, value):
            msg = _("Invalid value for job argument '{name}': {value}")
            msg = msg.format(name=name, value=value)
            raise OTPmeException(msg)
        return value

    def get_list_arg(self, args, name, regex, max_len=128):
        """ A list argument of a job, every entry checked.

        One value is a list of one: --arg packages=tcpdump means the
        same as --arg packages=tcpdump,gimp with one package. """
        values = args.get(name)
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            msg = _("Job misses argument: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        if len(values) > max_len:
            msg = _("Too many values for job argument: {name}")
            msg = msg.format(name=name)
            raise OTPmeException(msg)
        for x_value in values:
            if not isinstance(x_value, str) or not re.match(regex, x_value):
                msg = _("Invalid value for job argument '{name}': {value}")
                msg = msg.format(name=name, value=x_value)
                raise OTPmeException(msg)
        return list(values)

    def get_bool_arg(self, args, name, default=False):
        """ A yes or no argument of a job. Written as a word, because
        that is what fits on a command line. """
        return parse_bool_arg(args, name, default=default)

    def get_path_arg(self, args, name):
        """ A file path a job names. Absolute, and without a way out of
        itself. """
        path = self.get_str_arg(args, name, r'^/[^\0\n]{1,4095}$')
        if "/../" in path or path.endswith("/.."):
            msg = _("Invalid path: {path}")
            msg = msg.format(path=path)
            raise OTPmeException(msg)
        return path

    # ---- Running things ---------------------------------------------

    def log_output(self, log_file, output):
        """ Add to the log of this job. """
        try:
            with open(log_file, "a") as fd:
                fd.write(output)
        except OSError as e:
            log_msg = _("Failed to write job log: {file}: {e}", log=True)[1]
            log_msg = log_msg.format(file=log_file, e=e)
            self.logger.warning(log_msg)

    def run_command(self, command, log_file, env=None):
        """ Run one system command as root and write what it said to the
        job log. Returns the exit code and the output. """
        self.log_output(log_file, f"### {' '.join(command)}\n")
        run_kwargs = {}
        if env is not None:
            run_kwargs['env'] = env
        try:
            return_code, \
            command_stdout, \
            command_stderr, \
            command_pid = system_command.run(command=command,
                                            user="root",
                                            group="root",
                                            shell=False,
                                            **run_kwargs)
        except Exception as e:
            output = _("Failed to run command: {e}")
            output = output.format(e=e)
            self.log_output(log_file, f"{output}\n")
            return 1, output
        output = ""
        for x_out in (command_stdout, command_stderr):
            if not x_out:
                continue
            if isinstance(x_out, bytes):
                x_out = x_out.decode(errors="replace")
            output = f"{output}{x_out}"
        self.log_output(log_file, output)
        return return_code, output

    # ---- The same on every system -----------------------------------

    def run_service_mgmt(self, action, args, log_file):
        """ Start, stop, restart, enable or disable a systemd unit. """
        unit = self.get_str_arg(args, "unit", SERVICE_NAME_RE)
        command = ["systemctl", action, "--", unit]
        return self.run_command(command, log_file)

    def run_file_mgmt(self, action, args, log_file):
        """ Write or remove a file.

        Whatever the job says, written as root: this job type is as
        powerful as the host itself, and who may sign one is what keeps
        that in bounds. """
        path = self.get_path_arg(args, "path")
        if action == "del_file":
            if not os.path.exists(path):
                output = f"{path} does not exist\n"
                self.log_output(log_file, output)
                return 0, output
            try:
                os.remove(path)
            except OSError as e:
                msg = _("Failed to remove file: {file}: {e}")
                msg = msg.format(file=path, e=e)
                raise OTPmeException(msg) from e
            output = f"removed {path}\n"
            self.log_output(log_file, output)
            return 0, output
        if action != "put_file":
            msg = _("Unknown action: {action}")
            msg = msg.format(action=action)
            raise OTPmeException(msg)
        content = args.get("content")
        if not isinstance(content, str):
            msg = _("Job misses the content of the file.")
            raise OTPmeException(msg)
        mode = self.get_str_arg(args, "mode", FILE_MODE_RE, required=False)
        if mode is None:
            mode = "0644"
        owner = self.get_str_arg(args, "owner", USER_NAME_RE, required=False)
        if owner is None:
            owner = "root"
        group = self.get_str_arg(args, "group", USER_NAME_RE, required=False)
        if group is None:
            group = "root"
        file_dir = os.path.dirname(path)
        if not os.path.exists(file_dir):
            msg = _("Directory does not exist: {directory}")
            msg = msg.format(directory=file_dir)
            raise OTPmeException(msg)
        filetools.create_file(path=path,
                            content=content,
                            user=owner,
                            group=group,
                            mode=int(mode, 8))
        output = f"wrote {path} ({len(content)} bytes, {mode} {owner}:{group})\n"
        self.log_output(log_file, output)
        return 0, output

    def run_signer_mgmt(self, action, args, log_file):
        """ Show, add, remove or update a system-wide signer of this
        host.

        The same as root running otpme-tool show_signer, add_signer,
        del_signer or update_signer on the host. The job names the
        signer by its type and by the user or role whose key signs. A
        new signer is pinned to the key the object has now;
        update_signer pins the current key again.

        show_signer names no signer: it asks what the host holds, which
        is the whole point of asking from somewhere else. Its answer is
        the output of the job, so otpme-deploy results shows it.

        update_signer keeps a signer whose user or role was deleted, and
        the pinned key of a member a role does not have anymore -- what
        they signed has to go on validating. remove_gone=yes drops them.

        Adding a signer that is there already, or removing one that is
        not, is not an error: the host is then as the job wants it. """
        from otpme.lib import oid
        from otpme.lib import stuff
        from otpme.lib.classes.signing import OTPmeSigner
        from otpme.lib.classes.command_handler import CommandHandler
        # Only show_signer may leave the type out, and it names no
        # signer at all, so it is answered before both are asked for.
        signer_type = self.get_str_arg(args, "type", SIGNER_TYPE_RE,
                                    required=(action != "show_signer"))
        if signer_type is not None:
            if signer_type not in OTPmeSigner.supported_signer_types:
                msg = _("Invalid signer type: {signer_type}")
                msg = msg.format(signer_type=signer_type)
                raise OTPmeException(msg)
        if action == "show_signer":
            command_handler = CommandHandler(interactive=False)
            output = command_handler.show_signer(signer_type=signer_type)
            output = f"{output}\n"
            self.log_output(log_file, output)
            return 0, output
        # A signer has two UUIDs: its own (signer.uuid, also the name of
        # its file) and the one of the user or role whose key signs
        # (signer.object_uuid).
        #
        # add_signer names the object, and the object has to be here: a
        # key is what gets pinned. del_signer and update_signer name an
        # entry this host holds, and that entry outlives the object --
        # a role that is deleted leaves one behind, and there is no
        # looking that up by the name of something that is gone. So
        # they take the uuid show_signer prints as well.
        signer_ref = self.get_str_arg(args, "signer", SIGNER_REF_RE)
        command_handler = CommandHandler(interactive=False)
        host_signers = command_handler.get_signers(signer_type=signer_type)
        if stuff.is_uuid(signer_ref):
            if action == "add_signer":
                msg = _("add_signer needs a user or a role: {signer}")
                msg = msg.format(signer=signer_ref)
                raise OTPmeException(msg)
            signers = [x for x in host_signers if x.uuid == signer_ref]
        else:
            try:
                object_oid = oid.get(signer_ref)
            except Exception as e:
                msg = _("Invalid signer OID: {signer_oid}")
                msg = msg.format(signer_oid=signer_ref)
                raise OTPmeException(msg) from e
            object_uuid = stuff.resolve_oid(object_oid)
            signers = [x for x in host_signers
                    if x.object_uuid == object_uuid]
        signer_oid = signer_ref
        if action == "add_signer":
            if signers:
                output = f"signer exists already: {signer_type} {signer_oid} ({signers[0].uuid})\n"
                self.log_output(log_file, output)
                return 0, output
            tags = None
            if args.get("tags"):
                tags = self.get_list_arg(args, "tags", SIGNER_TAG_RE)
            command_handler.add_signer(signer_type=signer_type,
                                    object_oid=signer_oid,
                                    tags=tags)
            output = f"added signer: {signer_type} {signer_oid}\n"
            self.log_output(log_file, output)
            return 0, output
        if action == "del_signer":
            if not signers:
                output = f"no such signer: {signer_type} {signer_oid}\n"
                self.log_output(log_file, output)
                return 0, output
            output = ""
            for x_signer in signers:
                command_handler.del_signer(x_signer.uuid)
                output = f"{output}removed signer: {signer_type} {signer_oid} ({x_signer.uuid})\n"
            self.log_output(log_file, output)
            return 0, output
        if action == "update_signer":
            if not signers:
                msg = _("No such signer: {signer_type} {signer_oid}")
                msg = msg.format(signer_type=signer_type,
                                signer_oid=signer_oid)
                raise OTPmeException(msg)
            remove_gone = self.get_bool_arg(args, "remove_gone")
            output = ""
            for x_signer in signers:
                command_handler.update_signer(x_signer.uuid,
                                        remove_gone=remove_gone)
                output = f"{output}updated signer: {signer_type} {signer_oid} ({x_signer.uuid})\n"
            self.log_output(log_file, output)
            return 0, output
        msg = _("Unknown action: {action}")
        msg = msg.format(action=action)
        raise OTPmeException(msg)
