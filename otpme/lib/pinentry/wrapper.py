#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
from subprocess import PIPE
from subprocess import Popen

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.pinentry.pinentry import get_autoconfirm

# Add OTPme dir to path.
module_path = os.path.realpath(__file__)
otpme_dir = os.path.dirname(os.path.dirname(os.path.dirname(module_path)))
sys.path.append(otpme_dir)

def pinentry_wrapper(pin=None, pin_function=None, autoconfirm_file=None,
    fallback=False, debug_file=None, pinentry_bin=None, pinentry_opts=None):
    """
    Start pinentry wrapper to send given PIN or get PIN via helper function.
    """
    command_history = []

    if debug_file:
        log = open(debug_file, "w")

    display = None
    home_exp = "~%s" % config.system_user()
    home_dir = os.path.expanduser(home_exp)
    display_file = "%s/.display" % home_dir
    if os.path.exists(display_file):
        fd = open(display_file, "r")
        try:
            display = fd.read()
        except Exception as e:
            if debug_file:
                log.write("Failed to read display file: %s: %s" % (display_file, e))
                log.flush()
        finally:
            fd.close()
        if display:
            os.environ['DISPLAY'] = display
    if debug_file:
        log.write("Using DISPLAY: %s\n" % display)
        log.flush()

    autoconfirm = False
    if autoconfirm_file:
        autoconfirm, \
        fallback, \
        message_file = get_autoconfirm(autoconfirm_file)

    if debug_file:
        log.write("Autoconfirmation enabled: %s\n" % autoconfirm)
        log.flush()

    if pinentry_bin is None:
        pinentry_bin = "/usr/bin/pinentry"

    command = [ pinentry_bin ]

    if pinentry_opts is not None:
        x_type = type(pinentry_opts)
        if x_type != list:
            raise Exception("Expected pinentry_opts as <list>. Got %s" % x_type)
        command += pinentry_opts

    # Print greeting.
    sys.stdout.write("OK Pleased to meet you\n")
    sys.stdout.flush()

    while True:
        if pin_function:
            pin = None
        session_end = False
        pinentry_required = False

        try:
            line = sys.stdin.readline()
            command_history.append(line)
        except KeyboardInterrupt:
            break

        if not line or line == "\n":
            break

        if debug_file:
            log.write("Received command: %s" % line)
            log.flush()

        if line.lower() == "confirm\n":
            if autoconfirm:
                if debug_file:
                    log.write("Auto confirming question (autoconfirm=True): %s"
                            % line)
                    log.flush()
                sys.stdout.write("OK\n")
                sys.stdout.flush()
                continue
            else:
                pinentry_required = True

        if line.lower() == "getpin\n":
            if not pin:
                if pin_function:
                    if debug_file:
                        log.write("Starting PIN function...\n")
                        log.flush()
                    try:
                        pin = pin_function()
                    except Exception as e:
                        if debug_file:
                            log.write("Exception in PIN function: %s\n" % e)
                            log.flush()
                        break
                    if not pin:
                        if debug_file:
                            log.write("No PIN received from PIN function.\n")
                            log.flush()
            if pin:
                if isinstance(pin, bytes):
                    pin = pin.decode()
                sys.stdout.write("D %s\n" % pin)
                sys.stdout.flush()
                sys.stdout.write("OK\n")
                sys.stdout.flush()
                continue
            elif not fallback:
                if debug_file:
                    log.write("Cancelling GETPIN action (fallback=False)\n")
                    log.flush()
                sys.stdout.write("ERR 83886179 canceled\n")
                continue
            else:
                pinentry_required = True

        if pinentry_required:
            if debug_file:
                log.write("Trying fallback to original pinentry program: %s\n"
                            % " ".join(command))
                log.flush()

            #os.environ["GPG_TTY"] = os.popen("tty").read().strip()
            env = os.environ.copy()
            # Start original pinentry.
            proc = Popen(command,
                        stdin=PIPE,
                        stdout=PIPE,
                        stderr=PIPE,
                        text=True,
                        shell=False,
                        env=env)

            # Read first line.
            line = proc.stdout.readline()

            while True:
                if len(command_history) > 0:
                    #line = "%s\n" % command_history.pop(0)
                    line = command_history.pop(0)
                else:
                    try:
                        line = sys.stdin.readline()
                    except KeyboardInterrupt:
                        break

                if not line or line == "\n":
                    continue

                if debug_file:
                    log.write("Sending command to original pinentry: %s" % line)
                    log.flush()

                # Send line to pinentry.
                if isinstance(line, bytes):
                    line = line.decode()
                try:
                    proc.stdin.write(line)
                    proc.stdin.flush()
                except Exception as e:
                    if debug_file:
                        log.write("Error sending command to original "
                                "pinentry: %s\n" % e)
                        log.flush()
                    raise

                # Handle reply.
                if debug_file:
                    log.write("Reading reply from original pinentry...\n")
                    log.flush()

                try:
                    r = proc.stdout.readline()
                except Exception as e:
                    if debug_file:
                        log.write("Error reading reply from original "
                                "pinentry: %s\n" % e)
                        log.flush()
                    raise

                reply = r
                while not r.lower().startswith("ok") \
                and not r.lower().startswith("err"):
                    if debug_file:
                        log.write("Reading reply from original pinentry...\n")
                        log.flush()
                    try:
                        r = proc.stdout.readline()
                    except Exception as e:
                        if debug_file:
                            log.write("Error reading reply from original "
                                    "pinentry: %s\n" % e)
                            log.flush()
                        raise
                    if r == "":
                        if debug_file:
                            log.write("Error running original pinentry: %s"
                                    % proc.stderr.read())
                            log.flush()
                        sys.exit(1)
                        break
                    reply += r

                if len(command_history) == 0:
                    try:
                        sys.stdout.write(reply)
                        sys.stdout.flush()
                    except Exception as e:
                        if line.lower() != "bye\n":
                            if debug_file:
                                log.write("Error writing reply to stdout: %s\n" % line)
                                log.flush()
                            raise

                if line.lower().startswith("bye ") or line.lower() == "bye\n":
                    if reply.lower().startswith("ok "):
                        session_end = True
                        break
            # Iteration sleep to prevent running wild if something goes wrong.
            time.sleep(0.001)

        else:
            if line.lower().startswith("bye ") or line.lower() == "bye\n":
                session_end = True

            if not session_end:
                try:
                    sys.stdout.write("OK\n")
                    sys.stdout.flush()
                except Exception as e:
                    if debug_file:
                        log.write("Error writing 'OK' command to stdout: %s\n" % e)
                        log.flush()
                    raise

        if session_end:
            break

        # Iteration sleep to prevent running wild if something goes wrong.
        time.sleep(0.001)

    if debug_file:
        log.close()

if __name__ == '__main__':
    pinentry_wrapper(pin=None,
                pin_function=None,
                fallback=True,
                debug_file="/tmp/pinentry.log",
                pinentry_bin=None)
