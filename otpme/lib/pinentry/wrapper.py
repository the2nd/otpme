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
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
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
    home_exp = f"~{config.system_user()}"
    home_dir = os.path.expanduser(home_exp)
    display_file = f"{home_dir}/.display"
    if os.path.exists(display_file):
        fd = open(display_file, "r")
        try:
            display = fd.read()
        except Exception as e:
            if debug_file:
                log.write(f"Failed to read display file: {display_file}: {e}")
                log.flush()
        finally:
            fd.close()
        if display:
            os.environ['DISPLAY'] = display
    if debug_file:
        log.write(f"Using DISPLAY: {display}\n")
        log.flush()

    autoconfirm = False
    if autoconfirm_file:
        autoconfirm, \
        fallback, \
        message_file = get_autoconfirm(autoconfirm_file)

    if debug_file:
        log.write(f"Autoconfirmation enabled: {autoconfirm}\n")
        log.flush()

    if pinentry_bin is None:
        pinentry_bin = "/usr/bin/pinentry"

    command = [ pinentry_bin ]

    if pinentry_opts is not None:
        x_type = type(pinentry_opts)
        if x_type != list:
            msg = _("Expected pinentry_opts as <list>. Got {x_type}")
            msg = msg.format(x_type=x_type)
            raise Exception(msg)
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
            log.write(f"Received command: {line}")
            log.flush()

        if line.lower() == "confirm\n":
            if autoconfirm:
                if debug_file:
                    log.write(f"Auto confirming question (autoconfirm=True): {line}")
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
                            log.write(f"Exception in PIN function: {e}\n")
                            log.flush()
                        break
                    if not pin:
                        if debug_file:
                            log.write("No PIN received from PIN function.\n")
                            log.flush()
            if pin:
                if isinstance(pin, bytes):
                    pin = pin.decode()
                sys.stdout.write(f"D {pin}\n")
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
                log.write(f"Trying fallback to original pinentry program: {' '.join(command)}\n")
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
                    #line = f"{command_history.pop(0)}\n"
                    line = command_history.pop(0)
                else:
                    try:
                        line = sys.stdin.readline()
                    except KeyboardInterrupt:
                        break

                if not line or line == "\n":
                    continue

                if debug_file:
                    log.write(f"Sending command to original pinentry: {line}")
                    log.flush()

                # Send line to pinentry.
                if isinstance(line, bytes):
                    line = line.decode()
                try:
                    proc.stdin.write(line)
                    proc.stdin.flush()
                except Exception as e:
                    if debug_file:
                        log.write(f"Error sending command to original pinentry: {e}\n")
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
                        log.write(f"Error reading reply from original pinentry: {e}\n")
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
                            log.write(f"Error reading reply from original pinentry: {e}\n")
                            log.flush()
                        raise
                    if r == "":
                        if debug_file:
                            log.write(f"Error running original pinentry: {proc.stderr.read()}")
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
                                log.write(f"Error writing reply to stdout: {line}\n")
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
                        log.write(f"Error writing 'OK' command to stdout: {e}\n")
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
