# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import ssl
#import time
import signal
#from gevent.pywsgi import WSGIServer
#from gevent import sleep as gevent_sleep
from gunicorn.glogging import Logger
from gunicorn.app.base import BaseApplication
from otpme.lib.pki.utils import check_ssl_cert_key

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
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
            if _signal != 2:
                return
        # Stop gunicorn.
        self.gunicorn_child.terminate()
        self.gunicorn_child.join()
        self.gunicorn_child.close()
        # Remove cert/key files.
        if os.path.exists(self.cert_file):
            os.remove(self.cert_file)
        if os.path.exists(self.key_file):
            os.remove(self.key_file)
        return super(HttpDaemon, self).signal_handler(_signal, frame)

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        self.gunicorn_child = None

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
            ssl_cert = own_site.mgmt_cert
            ssl_key = own_site.mgmt_key

        # Encrypt cert private key with password.
        key_pass = stuff.gen_secret(len=32)
        key_pass = key_pass.encode()
        _cert = SSLCert(key=ssl_key)
        ssl_key = _cert.encrypt_key(passphrase=key_pass)

        # Temp file paths.
        self.cert_file = os.path.join(config.tmp_dir, f"{stuff.gen_secret(len=32)}-cert.pem")
        self.key_file = os.path.join(config.tmp_dir, f"{stuff.gen_secret(len=32)}-key.pem")

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
                    log_msg = _("Cert file '{file}' exists, removing.", log=True)[1]
                    log_msg = log_msg.format(file=tmp_file)
                    self.logger.warning(log_msg)
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

        # Configure flask app.
        own_site = backend.get_object(uuid=config.site_uuid)
        #app.config.from_object('config')
        app.config.update(
            CSRF_ENABLED = True,
            WTF_CSRF_ENABLED = True,
            CSRF_SESSION_KEY = own_site.sso_csrf_secret,
            SECRET_KEY = own_site.sso_secret,
            )

        class GunicornApp(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()

            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)

            def load(self):
                return self.application

        def create_ssl_context(config, default_ssl_context_factory):
            context = ssl.SSLContext(ssl_version=ssl.PROTOCOL_SSLv23)
            context.load_cert_chain(certfile=self.cert_file,
                                    keyfile=self.key_file,
                                    password=key_pass)
            #context.minimum_version = ssl.TLSVersion.TLSv1_2
            return context

        gunicorn_logger = self.logger
        class CustomLogger(Logger):
            def __init__(self, cfg):
                super().__init__(cfg)
                self.error_log = gunicorn_logger
                self.access_log = gunicorn_logger

        # Gunicorn options
        options = {
          'bind': '0.0.0.0:443',
          'workers': 4,
          'worker_class': 'gevent',
          'worker_connections': 1000,
          'timeout': 30,
          'keepalive': 5,
          'certfile': self.cert_file,
          'keyfile': self.key_file,
          'ssl_context': create_ssl_context,
          'user': self.user,
          'group': self.group,
          'proc_name': 'otpme-httpd',
          'logger_class': CustomLogger,
        }

        # Wrapper to fix "ggevent.py:38: MonkeyPatchWarning: Monkey-patching ssl after ssl has already been imported may lead to errors, including..."
        # https://github.com/benoitc/gunicorn/issues/2796
        def start_gunicorn():
            #import sys
            #del sys.modules['ssl']
            try:
                import gevent.monkey
                gevent.monkey.patch_all()
            except ImportError:
                pass
            gunicorn_app.run()

        # Start Gunicorn.
        gunicorn_app = GunicornApp(app, options)
        self.gunicorn_child = multiprocessing.start_process(name="gunicorn",
                                                #target=gunicorn_app.run,
                                                target=start_gunicorn,
                                                new_process_group=True)

        # Start main loop.
        self.__run()

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
                    raise OTPmeException(msg)

                # Check if command can be handled by parent class.
                try:
                    self._handle_daemon_command(sender, daemon_command, data)
                except UnknownCommand as e:
                    log_msg = str(e)
                    self.logger.warning(log_msg)
                except DaemonQuit:
                    break
                except DaemonReload:
                    self.comm_handler.send("controld", command="reload_shutdown")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in httpd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
