# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import log
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
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
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
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

            #ssl_cert = config.host_data['cert']
            #ssl_key = config.host_data['key']

            own_site = backend.get_object(uuid=config.site_uuid)
            ssl_cert = own_site.mgmt_cert
            ssl_key = own_site.mgmt_key

            # Materialise cert and key in a per-daemon subdir under
            # run_dir that is owner-only (0o700). Previously these went
            # to /tmp (config.tmp_dir), which is world-traversable; any
            # local uid could read the TLS private key during the window
            # between write and unlink. The 0o700 parent closes that
            # window even if the file itself is briefly created with
            # umask-defaults. The os.open(O_CREAT|O_EXCL, 0o600) below
            # additionally pins the file mode atomically. An in-memory
            # SSLContext.wrap_socket() would let us drop the on-disk
            # path entirely, but twisted/ldaptor still wants paths.
            ldapd_tmpdir = os.path.join(config.run_dir, "ldapd")
            if not os.path.exists(ldapd_tmpdir):
                filetools.create_dir(ldapd_tmpdir,
                                    user=self.user,
                                    group=self.group,
                                    mode=0o700)
            else:
                # Defensive: a pre-fix install may have created this
                # dir with looser perms.
                filetools.set_fs_permissions(path=ldapd_tmpdir,
                                            mode=0o700)
                if self.user or self.group:
                    filetools.set_fs_ownership(path=ldapd_tmpdir,
                                            user=self.user,
                                            group=self.group,
                                            recursive=False)

            self.cert_file = os.path.join(ldapd_tmpdir, f"{stuff.gen_secret(32)}-cert.pem")
            self.key_file = os.path.join(ldapd_tmpdir, f"{stuff.gen_secret(32)}-key.pem")

            # Build dict with all temp files to create.
            tmp_files = {}
            tmp_files[self.cert_file] = ssl_cert
            tmp_files[self.key_file] = ssl_key

            # Create all needed temp files.
            for tmp_file, file_content in tmp_files.items():
                # O_CREAT|O_EXCL refuses to follow a stale symlink or
                # reuse an attacker-placed inode; mode 0o600 is set
                # atomically by os.open, removing the umask-controlled
                # window between open() and a follow-up chmod.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                fd = os.open(tmp_file, flags, 0o600)
                try:
                    if isinstance(file_content, str):
                        file_content = file_content.encode("utf-8")
                    os.write(fd, file_content)
                finally:
                    os.close(fd)
                if self.user or self.group:
                    filetools.set_fs_ownership(path=tmp_file,
                                            user=self.user,
                                            group=self.group,
                                            recursive=False)

            for x in self.listen_sockets:
                # Format: "address:port"; v6 addresses are bracketed: "[::]:389"
                if x.startswith("["):
                    end = x.find("]")
                    address = x[1:end]
                    port = x[end+2:]
                else:
                    address, port = x.rsplit(":", 1)
                self.ldap_server = LDAPServer(address=address, port=port)
                self.ldap_server.listen(use_ssl=True, cert=self.cert_file, key=self.key_file)

            # Using SSLContext.wrap_socket() with newer python versions it's
            # possible to remove cert/key files after socket initialization.
            if os.path.exists(self.cert_file):
                os.remove(self.cert_file)
            if os.path.exists(self.key_file):
                os.remove(self.key_file)
        except Exception:
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

        log_msg = _("{full_name} started", log=True)[1]
        log_msg = log_msg.format(full_name=self.full_name)
        self.logger.info(log_msg)

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
                    msg, log_msg = _("Error receiving daemon message: {error}", log=True)
                    msg = msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    raise OTPmeException(msg) from e

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    log_msg = str(e)
                    self.logger.warning(log_msg)
                except DaemonQuit:
                    break
                except DaemonReload:
                    config.ldap_cache_clear = True
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in ldapd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

        # Stop LDAP server (ldaptor).
        if config.daemonize:
            # Send SIGTERM.
            mypid = os.getpid()
            stuff.kill_pid(mypid)
        else:
            self.ldap_server.reactor.callFromThread(self.ldap_server.stop)
