# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import script
from otpme.lib import auth_script
from otpme.lib import push_script
from otpme.lib import multiprocessing
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

script_comm_q = multiprocessing.InterProcessQueue("scriptd")

#script_comm_q.close()
#script_comm_q.unlink()

valid_script_classes = {
                            'script'        : script,
                            'auth_script'   : auth_script,
                            'push_script'   : push_script,
                        }

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("scriptd")

def run_script(script_type, script_uuid, script_parms,
    user, group, groups=[], script_path=None):
    """ Run script via scriptd. """
    if 'user' in script_parms:
        msg = "<user> in script parameters is not allowed."
        raise OTPmeException(msg)
    if 'group' in script_parms:
        msg = "<group> in script parameters is not allowed."
        raise OTPmeException(msg)
    if 'groups' in script_parms:
        msg = "<groups> in script parameters is not allowed."
        raise OTPmeException(msg)

    # Build script execution request.
    script_request = {
                'user'          : user,
                'group'         : group,
                'groups'        : groups,
                'script_uuid'   : script_uuid,
                'script_path'   : script_path,
                'script_type'   : script_type,
                'script_parms'  : script_parms,
    }

    client_id = "script_client:%s" % stuff.gen_uuid()
    script_comm_handler = script_comm_q.get_handler(client_id)

    exec_request = {
                    'sender'            : client_id,
                    'script_request'    : script_request,
                }

    # Send request.
    script_comm_handler.send("script-handler",
                            command="run",
                            data=exec_request)

    # Run recv() with timeout to prevent blocking of clusterd shutdown.
    while True:
        try:
            sender, \
            command, \
            script_reply = script_comm_handler.recv(timeout=1)
        except TimeoutReached:
            continue
        else:
            break
    # Get script result/exception.
    script_result = script_reply['script_result']
    script_exception = script_reply['script_exception']
    # Close comm queue.
    script_comm_handler.close()
    script_comm_handler.unlink()

    if script_exception:
        raise OTPmeException(script_exception)

    return script_result

def handle_script_request(request):
    """ Run script and return status. """
    logger = config.logger
    sender = request['sender']
    script_request = request['script_request']
    # Load request data.
    user = script_request['user']
    group = script_request['group']
    groups = script_request['groups']
    script_uuid = script_request['script_uuid']
    script_path = script_request['script_path']
    script_type = script_request['script_type']
    script_parms = script_request['script_parms']

    if user == "root":
        user = config.root_script_user
    if group == "root":
        group = config.root_script_group
    try:
        groups.remove("root")
    except ValueError:
        pass

    # Get script class to run script with.
    if script_type in valid_script_classes:
        # Execute script.
        try:
            script_exception = None
            script_class = valid_script_classes[script_type]
            script_result = script_class.run(script_type=script_type,
                                            script_uuid=script_uuid,
                                            script_path=script_path,
                                            user=user,
                                            group=group,
                                            groups=groups,
                                            **script_parms)
        except Exception as e:
            script_result = None
            script_exception = str(e)
            #config.raise_exception()
            msg = "Failed to run script: %s" % e
            logger.warning(msg)
    else:
        script_result = None
        script_exception = "Invalid script type: %s" % script_type

    # Send reply.
    script_reply = {
                    'script_result'     : script_result,
                    'script_exception'  : script_exception,
                }
    scriptd_comm_handler = script_comm_q.get_handler("scriptd")
    scriptd_comm_handler.send(recipient=sender,
                            command="script_reply",
                            data=script_reply)
    scriptd_comm_handler.close()
    scriptd_comm_handler.unlink()

class ScriptDaemon(OTPmeDaemon):
    """ ScriptDaemon. """
    def set_proctitle(self):
        """ Set daemon proctitle. """
        new_proctitle = self.full_name
        setproctitle.setproctitle(new_proctitle)

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        msg = ("Received SIGTERM.")
        self.logger.info(msg)
        self.close_childs()
        return super(ScriptDaemon, self).signal_handler(_signal, frame)

    def close_childs(self):
        self.script_handler_child.terminate()
        self.script_handler_child.join()
        self.script_requests_child.terminate()
        self.script_requests_child.join()

    def handle_script_requests(self):
        """ Run scripts requested from other daemons and return status. """
        try:
            self.drop_privileges()
        except Exception as e:
            msg = "Failed to drop privileges: %s" % e
            self.logger.critical(msg)

        scriptd_comm_handler = script_comm_q.get_handler("script-handler")
        # Send ready message to open posix message queue as user otpme!
        scriptd_comm_handler.send(recipient="scriptd-runner",
                                   command="ready")

        notify_file = os.path.join(config.run_dir, "wait_for_scriptd")
        fd = open(notify_file, "w")
        fd.close()

        while True:
            try:
                sender, \
                command, \
                request = scriptd_comm_handler.recv(timeout=1)
            except ExitOnSignal:
                break
            except TimeoutReached:
                continue
            scriptd_comm_handler.send(recipient="scriptd-runner",
                                       command=command,
                                        data=request)
        # Close comm handler on exit.
        scriptd_comm_handler.unlink()

    def run_scripts_handler(self):
        """ Run scripts requested from other daemons and return status. """
        scriptd_comm_handler = script_comm_q.get_handler("scriptd-runner")
        try:
            sender, \
            command, \
            request = scriptd_comm_handler.recv(timeout=5)
        except ExitOnSignal:
            return
        except TimeoutReached:
            return

        if command != "ready":
            msg = "Got wrong 'ready' message: %s" % command
            self.logger.critical(msg)
            sys.exit(1)

        while True:
            try:
                sender, \
                command, \
                request = scriptd_comm_handler.recv(timeout=1)
            except ExitOnSignal:
                break
            except TimeoutReached:
                continue
            # Start script in new process.
            multiprocessing.start_process(name=self.name,
                            target=handle_script_request,
                            target_args=(request,),
                            daemon=True,
                            join=True)
        # Remove comm handler on exit.
        scriptd_comm_handler.close()
        scriptd_comm_handler.unlink()

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Set process title.
        self.set_proctitle()
        # Configure ourselves (e.g. certificates etc.).
        self.configure()
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        notify_file = os.path.join(config.run_dir, "wait_for_scriptd")
        try:
            os.remove(notify_file)
        except FileNotFoundError:
            pass

        # Start thread to handle script run requests..
        self.script_requests_child = multiprocessing.start_process(name=self.name,
                                                target=self.handle_script_requests)

        # Wait for posix queue to be opened from process that runs as otpme user.
        while not os.path.exists(notify_file):
            time.sleep(0.01)
        os.remove(notify_file)

        # Start thread to handle script executions.
        self.script_handler_child = multiprocessing.start_process(name=self.name,
                                                    target=self.run_scripts_handler)

        self.logger.info("%s started" % self.full_name)

        # Notify controld that we are ready.
        self.comm_handler.send("controld", command="ready")

        # Run in loop unitl we get quit command.
        while True:
            try:
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv()
                except ExitOnSignal:
                    break
                #except TimeoutReached:
                #    time.sleep(0.001)
                #    continue
                except Exception as e:
                    msg = (_("Error receiving daemon message: %s") % e)
                    self.logger.critical(msg, exc_info=True)
                    raise OTPmeException(msg)

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    self.logger.warning(str(e))
                except DaemonQuit:
                    break
                except DaemonReload:
                    # FIXME: Get reload command via network to reload on changes of own host?
                    # Check for config changes.
                    restart = self.configure()
                    if restart:
                        break
                    # Inform controld that we finished our reload.
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                config.raise_exception()
                self.logger.critical("Unhandled error in scriptd: %s" % e)

        self.close_childs()
