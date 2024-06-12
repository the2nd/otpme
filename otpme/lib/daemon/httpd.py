# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ssl
#import time
import signal
from gevent.pywsgi import WSGIServer
from gevent import sleep as gevent_sleep
from otpme.lib.pki.utils import check_ssl_cert_key

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.pki.cert import SSLCert
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon

from otpme.web.app import app

from otpme.lib.exceptions import *

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("httpd")

class HttpDaemon(OTPmeDaemon):
    """ httpd """
    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        # Remove cert/key files.
        if os.path.exists(self.cert_file):
            os.remove(self.cert_file)
        if os.path.exists(self.key_file):
            os.remove(self.key_file)
        return super(HttpDaemon, self).signal_handler(_signal, frame)

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Configure ourselves (e.g. certificates etc.)
        self.configure()
        # FIXME: Where to configure max_conn?
        # Set max client connections.
        #self.max_conn = 100

        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Create cert/key files for flask.
        own_site = backend.get_object(uuid=config.site_uuid)
        sso_cert_ready = False
        if own_site.sso_cert and own_site.sso_key:
            try:
                check_ssl_cert_key(own_site.sso_cert, own_site.sso_key)
                sso_cert_ready = True
            except:
                sso_cert_ready = False
        if sso_cert_ready:
            ssl_cert = own_site.sso_cert
            ssl_key = own_site.sso_key
        else:
            ssl_cert = own_site.cert
            ssl_key = own_site.key

        # Encrypt cert private key with password.
        key_pass = stuff.gen_secret(len=32)
        key_pass = key_pass.encode()
        _cert = SSLCert(key=ssl_key)
        ssl_key = _cert.encrypt_key(passphrase=key_pass)

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

        # Start run method in extra thread.
        multiprocessing.start_thread(name=self.name,
                                    target=self.__run,
                                    daemon=True)

        # Configure flask app.
        own_site = backend.get_object(uuid=config.site_uuid)
        #app.config.from_object('config')
        app.config.update(
            CSRF_ENABLED = True,
            WTF_CSRF_ENABLED = True,
            CSRF_SESSION_KEY = own_site.sso_csrf_secret,
            SECRET_KEY = own_site.sso_secret,
            )

        # Load SSL context with encrypted key.
        context = ssl.SSLContext(ssl_version=ssl.PROTOCOL_SSLv23)
        context.load_cert_chain(certfile=self.cert_file,
                                keyfile=self.key_file,
                                password=key_pass)
        # Start http server.
        http_server = WSGIServer(('0.0.0.0', 443), app, ssl_context=context)

        #app.run(host="0.0.0.0", debug=True, use_reloader=False)
        #http_server = WSGIServer(("0.0.0.0", 443), app,
        #                        keyfile=self.key_file,
        #                        certfile=self.cert_file)
        #http_server.serve_forever()
        http_server.start()

        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        self.drop_privileges()

        while True:
            gevent_sleep(60)

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
                    self.comm_handler.send("controld", command="reload_shutdown")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                msg = ("Unhandled error in httpd: %s" % e)
                self.logger.critical(msg)

        # Stop flask.
        if config.daemonize:
            # Send SIGTERM.
            mypid = os.getpid()
            stuff.kill_pid(mypid)

