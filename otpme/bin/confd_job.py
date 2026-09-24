#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" Runs one configuration management job and leaves its result.

Started by confd for each job, detached from it (a transient systemd
service where there is systemd), so that a job outlives the daemon that
started it -- a job that restarts OTPme itself would otherwise take its
own runner with it and never be finished.

    otpme-confd-job <spool file>

It checks the job again before doing anything: this is the process that
installs the package, and it takes the word of nobody, not even of the
file it was handed.
"""
import os
import sys

# Run from the checkout when we were started through a symlink to it
# (switch_install.sh): the project root is two levels above this file.
_script_dir = os.path.dirname(os.path.realpath(__file__))
_project_root = os.path.dirname(os.path.dirname(_script_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

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

# Below the PYTHONPATH file, not above it: started as a transient
# service we get the PATH of systemd, so "python3" is the one of the
# system and not the one OTPme was installed into -- everything that
# does not come with Python itself is only there once the path from
# the file is in place.
import setproctitle

import otpme.lib
from otpme.lib import init_otpme
from otpme.lib.otpme_config import OTPmeConfig

def main():
    """ Run the job of the spool file we were given. """
    usage = "Usage: otpme-confd-job <spool file>\n"
    try:
        job_file = sys.argv[1]
    except IndexError:
        sys.stderr.write(usage)
        return 1
    # Started by confd, not by hand, so there is nothing to tell but
    # what it is called with.
    if job_file in ("-h", "--help"):
        sys.stdout.write(usage)
        return 0

    config = OTPmeConfig(tool_name="otpme-confd-job")
    otpme.lib.config = config
    init_otpme()

    from otpme.lib.confd import job as confd_job

    try:
        setproctitle.setproctitle(f"otpme-confd-job {os.path.basename(job_file)}")
    except Exception:
        pass

    # No log file of our own: what a run has to say goes into the log
    # file of its job, which is the one the result points at. What is
    # left is the unexpected, and that goes where the transient service
    # puts our output anyway -- the journal of its unit.
    try:
        result = confd_job.run_spooled_job(job_file)
    except Exception as e:
        msg = _("Failed to run job: {job_file}: {e}")
        msg = msg.format(job_file=job_file, e=e)
        sys.stderr.write(f"{msg}\n")
        return 1

    if result['status'] != "ok":
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
