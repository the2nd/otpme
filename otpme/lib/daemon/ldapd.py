# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import stuff
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.ldap.server import LDAPServer
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("ldapd")

class LdapDaemon(OTPmeDaemon):
    """ LdapDaemon """
    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # FIXME: Where to configure max_conn?
        # Set max client connections.
        #self.max_conn = 100

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Create cert/key files for twisted/ldaptor.
        try:
            # FIXME: Twisted does not support password protected key files!?
            # http://twistedmatrix.com/documents/13.1.0/api/twisted.internet.ssl.DefaultOpenSSLContextFactory.html
            ## Encrypt cert private key with password if supported by python SSL.
            #passphrase = stuff.gen_secret(len=32)
            #_cert = SSLCert(key=ssl_key)
            #ssl_key = _cert.encrypt_key(key=ssl_key, algo="blowfish", passphrase=passphrase)

            ssl_cert = config.host_data['cert']
            ssl_key = config.host_data['key']

            # Temp file paths.
            self.cert_file = "%s/%s-cert.pem" % (config.tmp_dir,
                                                stuff.gen_secret(len=32))
            self.key_file = "%s/%s-key.pem" % (config.tmp_dir,
                                                stuff.gen_secret(len=32))

            # Build dict with all temp files to create.
            tmp_files = {}
            tmp_files[self.cert_file] = ssl_cert
            tmp_files[self.key_file] = ssl_key

            # Create all needed temp files.
            for tmp_file in tmp_files:
                file_content = tmp_files[tmp_file]
                # Try to create file.
                try:
                    if os.path.exists(tmp_file):
                        self.logger.warning("Cert file '%s' exists, removing."
                                        % tmp_file)
                    # Create file.
                    fd = open(tmp_file, "w")
                    # Set permissions.
                    filetools.set_fs_permissions(path=tmp_file,
                                                mode=0o600,
                                                recursive=False)
                    if self.user or self.group:
                        # Set ownership.
                        filetools.set_fs_ownership(path=tmp_file,
                                                user=self.user,
                                                group=self.group,
                                                recursive=False)
                    # Write file content.
                    fd.write(file_content)
                    fd.close()
                except:
                    raise

            for x in self.listen_sockets:
                address = x.split(":")[0]
                port = x.split(":")[1]
                self.ldap_server = LDAPServer(address=address, port=port)
                self.ldap_server.listen(use_ssl=True, cert=self.cert_file, key=self.key_file)

            # Using SSLContext.wrap_socket() with newer python versions it's
            # possible to remove cert/key files after socket initialization.
            if os.path.exists(self.cert_file):
                os.remove(self.cert_file)
            if os.path.exists(self.key_file):
                os.remove(self.key_file)
        except:
            raise

        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        self.drop_privileges()

        # We need to start the main loop in child thread because of some
        # high CPU load bug when running reactor.run() in child thread.
        multiprocessing.start_thread(name=self.name,
                                    target=self.__run,
                                    daemon=True)

        self.ldap_server.run()

    def __run(self, **kwargs):
        # Notify controld that we are ready.
        self.comm_handler.send("controld", command="ready")

        self.logger.info("%s started" % self.full_name)

        # Run in loop unitl we get a signal.
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
                    config.ldap_cache_clear = True
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                msg = ("Unhandled error in ldapd: %s" % e)
                self.logger.critical(msg)

        # Stop LDAP server (ldaptor).
        if config.daemonize:
            # Send SIGTERM.
            mypid = os.getpid()
            stuff.kill_pid(mypid)
        else:
            self.ldap_server.reactor.callFromThread(self.ldap_server.stop)
