# -*- coding: utf-8 -*-
import os
import sys
import time
import signal
from daemonize import Daemonize

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib.register import register_module

class UnixDaemon(object):
    """ Class to run as unix daemon using python-daemon. """
    def __init__(self, name, pidfile):
        # Set name.
        self.proc_name = name
        # Set pidfile.
        self.pidfile = pidfile
        register_module("otpme.lib.filetools")

    def files_preserve_by_path(self, paths):
        """ Workaround to preserve needed FDs. """
        preserve_fds = []
        proc_path = '/proc/self/fd'
        fds = set(os.listdir(proc_path))
        for x in fds:
            fd_path = os.path.join(proc_path, x)
            fd_path = os.path.realpath(fd_path)
            if fd_path not in paths:
                continue
            preserve_fds.append(int(x))
        return preserve_fds

    def delpid(self):
        """ Delete pidfile. """
        if not os.path.exists(self.pidfile):
            return
        os.remove(self.pidfile)

    def start(self):
        """ Start the daemon. """
        status, pid = self.status(quiet=True)

        if status:
            message = "Already running.\n"
            sys.stderr.write(message)
            return False

        if config.daemonize:
            # Run stuff before daemonizing.
            self.pre_fork()
            # WORKAROUND: https://stackoverflow.com/questions/20636678/paramiko-inside-python-daemon-causes-ioerror
            #files_preserve = self.files_preserve_by_path(['/dev/urandom', '/dev/null'])
            class TestDaemon(Daemonize):
                def exit(self, *args, **kwargs):
                    return
                def sigterm(self, *args, **kwargs):
                    return
            daemon = Daemonize(app=self.proc_name,
                            pid=self.pidfile,
                            action=self.__atfork,
                            auto_close_fds=False)
                            #keep_fds=files_preserve,
                            #auto_close_fds=True)
                            #foreground=True)
            daemon.start()
        else:
            # Create pidfile.
            filetools.create_file(self.pidfile,
                                content=str(os.getpid()),
                                lock=False)
            # Run daemon in foreground.
            self.run()

    def __atfork(self):
        """ Run stuff on fork. """
        # Seed RNGD after starting child process
        stuff.seed_rng(quiet=True)
        # Run daemon.
        self.run()

    def stop(self, timeout=60, kill=False, quiet=False):
        """ Stop the daemon. """
        status, pid = self.status(quiet=True)
        if not status:
            if not quiet:
                message = "Not running.\n"
                sys.stderr.write(message)
            return False

        # Try killing the daemon process
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                        self.delpid()
            else:
                sys.stderr.write(str(err))
                return False

        wait_timeout = timeout
        if kill:
            wait_timeout = timeout / 2
            kill_timeout =  wait_timeout

        pid_status = stuff.wait_pid(pid=pid,
                        recursive=True,
                        timeout=wait_timeout)

        if not kill:
            if pid_status:
                return False
            self.remove_pidfile()
            return True

        stuff.kill_pid(pid=pid,
                    recursive=True,
                    kill_timeout=kill_timeout)

        self.remove_pidfile()
        return True

    def reload(self, quiet=False):
        """
        Send SIGHUP to daemon
        """
        status, pid = self.status(quiet=True)
        if not status:
            if not quiet:
                message =  "%s: Not running.\n" % self.proc_name
                sys.stderr.write(message)
            return False

        # Try sending SIGHUP to the daemon
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                        self.delpid()
            else:
                sys.stderr.write(str(err))
                return False
        except Exception as e:
            message = "Failed to send SIGHUP to daemon: %s" % e
            sys.stderr.write(message)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop(quiet=True)
        while True:
            time.sleep(0.001)
            daemon_status = self.status(quiet=True)[0]
            if not daemon_status:
                break
        self.start()

    def remove_pidfile(self):
        """ Remove PID file. """
        if not os.path.exists(self.pidfile):
            return
        try:
            os.remove(self.pidfile)
        except Exception as e:
            msg = ("Error removing PID file: %s: %s\n"
                    % (self.pidfile, e))
            sys.stdout.write(msg)
            return False
        return True

    def remove_stale_pidfile(self):
        """ Remove stale PID file. """
        if not os.path.exists(self.pidfile):
            return
        if not self.remove_pidfile():
            return
        msg = ("Removed stale PID file: %s\n"
                % self.pidfile)
        sys.stdout.write(msg)

    def status(self, quiet=False):
        """
        Check for daemon status
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = open(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        running = False
        if pid:
            if stuff.check_pid(pid):
                running = True

        if running:
            if not quiet:
                message = "Running.\n"
                sys.stdout.write(message)
            return True, pid
        else:
            # Make sure we remove a stale PID file.
            self.remove_stale_pidfile()
            if not quiet:
                message = "Stopped.\n"
                sys.stdout.write(message)
            return False, ""

    def pre_fork(self):
        """
        You should override this method when you subclass Daemon. It will be called before the process has been
        daemonized by start() or restart().
        """

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
