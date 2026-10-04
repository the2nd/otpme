# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Configuration management jobs on Debian and its relatives.

What differs from other systems: packages and repositories (apt), and
switching the host off. The rest -- services, files -- is the same
everywhere and lives in base.py.
"""
import os
import re
import subprocess

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import filetools
from otpme.lib.confd.base import ConfJobHandler
from otpme.lib.confd.base import REPO_NAME_RE
from otpme.lib.confd.base import PACKAGE_NAME_RE
from otpme.lib.confd.inventory import PACKAGE_VERSION_RE
from otpme.lib.confd.inventory import PACKAGE_NAME_RE as INVENTORY_PACKAGE_NAME_RE

from otpme.lib.exceptions import *

APT_SOURCES_DIR = "/etc/apt/sources.list.d"
APT_KEYRING_DIR = "/etc/apt/keyrings"
# A repository line as it goes into sources.list.d, without the key: we
# put that in ourselves, see add_repo.
REPO_LINE_RE = r'^deb(-src)? [a-zA-Z0-9:/._~+-]+( [a-zA-Z0-9._-]+)+$'

class DebianHandler(ConfJobHandler):
    """ Configuration management jobs on a Debian system. """
    os_ids = [
            'debian',
            'ubuntu',
            ]

    def apt_command(self, command):
        """ An apt command that asks nobody anything: a package manager
        waiting for an answer nobody will give would sit there until the
        job is killed. Configuration files are kept as they are, for the
        same reason. """
        apt_env = dict(os.environ)
        apt_env['DEBIAN_FRONTEND'] = "noninteractive"
        base_command = [
                    "apt-get",
                    "-y",
                    "-o", "DPkg::Lock::Timeout=300",
                    "-o", "Dpkg::Options::=--force-confdef",
                    "-o", "Dpkg::Options::=--force-confold",
                    ]
        return base_command + command, apt_env

    def get_installed_packages(self):
        """ The installed packages: {name: version}.

        What dpkg says is installed ("ii"), nothing that is only half
        there or removed with its configuration left. The name is the
        one dpkg uses, with the architecture for a multi-arch package
        (libc6:amd64). """
        command = [
                "dpkg-query",
                "-W",
                "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${Version}\\n",
                ]
        try:
            proc = subprocess.run(command,
                                check=False,
                                capture_output=True,
                                text=True)
        except OSError as e:
            msg = _("Failed to run dpkg-query: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg) from e
        if proc.returncode != 0:
            msg = _("dpkg-query failed: {error}")
            msg = msg.format(error=proc.stderr.strip())
            raise OTPmeException(msg)
        packages = {}
        for line in proc.stdout.splitlines():
            try:
                status, name, version = line.split("\t")
            except ValueError:
                continue
            if not status.startswith("ii"):
                continue
            if not re.match(INVENTORY_PACKAGE_NAME_RE, name):
                continue
            if not re.match(PACKAGE_VERSION_RE, version):
                continue
            packages[name] = version
        return packages

    def run_sw_mgmt(self, action, args, log_file):
        """ Install, remove or upgrade packages, or clean up after them.

        Nothing is removed on the side: apt only takes packages away
        when it is told to, either by the action itself or by
        autoremove=yes on a remove. """
        if action == "autoremove":
            command, apt_env = self.apt_command(["autoremove"])
            return self.run_command(command, log_file, env=apt_env)
        if action == "dist_upgrade":
            # The package lists first: without them the upgrade works
            # from whatever the host last heard of, which on a host that
            # has been quiet for a while is nothing.
            command, apt_env = self.apt_command(["update"])
            update_code, update_output = self.run_command(command, log_file,
                                                        env=apt_env)
            if update_code != 0:
                return update_code, update_output
            command, apt_env = self.apt_command(["dist-upgrade"])
            upgrade_code, upgrade_output = self.run_command(command, log_file,
                                                        env=apt_env)
            return upgrade_code, f"{update_output}{upgrade_output}"
        packages = self.get_list_arg(args, "packages", PACKAGE_NAME_RE)
        if action == "install":
            command = ["install", "--"] + packages
        elif action == "remove":
            command = ["remove"]
            if self.get_bool_arg(args, "autoremove"):
                command.append("--auto-remove")
            command += ["--"] + packages
        elif action == "upgrade":
            command = ["install", "--only-upgrade", "--"] + packages
        else:
            msg = _("Unknown action: {action}")
            msg = msg.format(action=action)
            raise OTPmeException(msg)
        command, apt_env = self.apt_command(command)
        return self.run_command(command, log_file, env=apt_env)

    def run_repo_mgmt(self, action, args, log_file):
        """ Add or remove a repository, or update the package lists. """
        if action == "update":
            command, apt_env = self.apt_command(["update"])
            return self.run_command(command, log_file, env=apt_env)
        if action == "add_repo":
            return self.add_repo(args, log_file)
        if action == "del_repo":
            return self.del_repo(args, log_file)
        msg = _("Unknown action: {action}")
        msg = msg.format(action=action)
        raise OTPmeException(msg)

    def get_repo_files(self, args):
        """ The two files one repository of ours consists of. """
        name = self.get_str_arg(args, "name", REPO_NAME_RE)
        list_file = os.path.join(APT_SOURCES_DIR, f"otpme-{name}.list")
        key_file = os.path.join(APT_KEYRING_DIR, f"otpme-{name}.asc")
        return list_file, key_file

    def add_repo(self, args, log_file):
        """ Write the repository and its signing key, then update. """
        list_file, key_file = self.get_repo_files(args)
        line = self.get_str_arg(args, "line", REPO_LINE_RE)
        # The key comes with the job. A repository whose signature we
        # cannot check is not one to install from, and fetching the key
        # ourselves would mean trusting whatever answers at that URL.
        key = args.get("key")
        if not isinstance(key, str) or "BEGIN PGP PUBLIC KEY BLOCK" not in key:
            msg = _("Job misses the signing key of the repository.")
            raise OTPmeException(msg)
        for x_dir in (APT_SOURCES_DIR, APT_KEYRING_DIR):
            if os.path.exists(x_dir):
                continue
            filetools.create_dir(x_dir, mode=0o755, user="root", group="root")
        filetools.create_file(path=key_file,
                            content=key,
                            user="root",
                            group="root",
                            mode=0o644)
        deb_type, repo_rest = line.split(" ", 1)
        repo_line = f"{deb_type} [signed-by={key_file}] {repo_rest}\n"
        filetools.create_file(path=list_file,
                            content=repo_line,
                            user="root",
                            group="root",
                            mode=0o644)
        output = f"wrote {key_file}\nwrote {list_file}\n"
        self.log_output(log_file, output)
        command, apt_env = self.apt_command(["update"])
        update_code, update_output = self.run_command(command, log_file,
                                                    env=apt_env)
        return update_code, f"{output}{update_output}"

    def del_repo(self, args, log_file):
        """ Remove the repository and its key, then update. """
        list_file, key_file = self.get_repo_files(args)
        output = ""
        for x_file in (list_file, key_file):
            if not os.path.exists(x_file):
                continue
            try:
                os.remove(x_file)
            except OSError as e:
                msg = _("Failed to remove file: {file}: {e}")
                msg = msg.format(file=x_file, e=e)
                raise OTPmeException(msg) from e
            output = f"{output}removed {x_file}\n"
        if not output:
            output = "nothing to remove\n"
        self.log_output(log_file, output)
        command, apt_env = self.apt_command(["update"])
        update_code, update_output = self.run_command(command, log_file,
                                                    env=apt_env)
        return update_code, f"{output}{update_output}"

    def run_host_mgmt(self, action, args, log_file):
        """ Switch the host off, or off and on again.

        Nothing else: upgrading it is the package manager's work and
        lives with the other package actions (run_sw_mgmt).

        In a minute, not now, for both: the result of this job still has
        to reach the nodes, and once the host is down nobody would send
        it. So the job ends with an answer and the host goes afterwards.
        """
        if action == "reboot":
            how = "-r"
            said = "Reboot by OTPme configuration job"
        elif action == "shutdown":
            how = "-h"
            said = "Shutdown by OTPme configuration job"
        else:
            msg = _("Unknown action: {action}")
            msg = msg.format(action=action)
            raise OTPmeException(msg)
        command = ["shutdown", how, "+1", said]
        return self.run_command(command, log_file)
