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
except Exception:
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
from otpme.web.certs import app as certs_app

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
        # Stop gunicorn. terminate() sends SIGTERM (graceful). If gunicorn
        # doesn't exit within the timeout (stuck greenlet, hung worker),
        # fall back to SIGKILL so daemon shutdown can't hang forever.
        # Both the SSL/SSO gunicorn AND the optional plain-HTTP CA
        # publisher share this lifecycle -- iterate over the bundle.
        for label, child in (("https", self.gunicorn_ssl_child),
                              ("http", self.gunicorn_child)):
            if child is None:
                continue
            try:
                child.terminate()
                child.join(timeout=35)
                if child.is_alive():
                    log_msg = _("gunicorn ({label}) did not exit gracefully "
                                "within 35s; sending SIGKILL", log=True)[1]
                    log_msg = log_msg.format(label=label)
                    self.logger.warning(log_msg)
                    child.kill()
                    child.join(timeout=5)
                child.close()
            except Exception as e:
                log_msg = _("Error stopping gunicorn ({label}): {error}",
                            log=True)[1]
                log_msg = log_msg.format(label=label, error=e)
                self.logger.warning(log_msg)
        # Remove cert/key files.
        if os.path.exists(self.cert_file):
            os.remove(self.cert_file)
        if os.path.exists(self.key_file):
            os.remove(self.key_file)
        return super().signal_handler(_signal, frame)

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        self.gunicorn_ssl_child = None
        # Separate gunicorn child for the plain-HTTP CA publisher.
        # ``None`` means "not started" (either disabled via config or
        # spawn failed) -- signal_handler tolerates that.
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
        if own_site.sso_cert and own_site.sso_key:
            try:
                check_ssl_cert_key(own_site.sso_cert, own_site.sso_key)
            except Exception as e:
                msg = _("SSO cert/key mismatch.")
                raise OTPmeException(msg) from e

        ssl_cert = own_site.sso_cert
        ssl_key = own_site.sso_key

        # Encrypt cert private key with password. Stored on the
        # instance so reload can re-encrypt a freshly-fetched key
        # with the same passphrase -- gunicorn's create_ssl_context
        # closure binds this value at worker spawn time.
        self.key_pass = stuff.gen_secret(len=32).encode()
        _cert = SSLCert(key=ssl_key)
        ssl_key = _cert.encrypt_key(passphrase=self.key_pass)

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
            except Exception:
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
            # Re-read cert/key from disk on each worker spawn so a
            # SIGHUP-driven reload picks up an updated Site SSO cert
            # without restarting the whole httpd. Passphrase is the
            # stable instance attribute so a reload that rewrote the
            # encrypted key with the same passphrase still loads.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=self.cert_file,
                                    keyfile=self.key_file,
                                    password=self.key_pass)
            return context

        gunicorn_logger = self.logger
        class CustomLogger(Logger):
            def __init__(self, cfg):
                super().__init__(cfg)
                self.error_log = gunicorn_logger
                self.access_log = gunicorn_logger

        # Gunicorn options
        own_host = backend.get_object(uuid=config.uuid)
        socket_uri = own_host.get_config_parameter("httpd_ssl_socket_uri")
        if not socket_uri:
            socket_uri = "tcp://[::]:443"
        httpd_workers = own_host.get_config_parameter("httpd_ssl_workers")
        if not httpd_workers:
            httpd_workers = 4
        options = {
          # Dual-stack: '[::]' binds both IPv6 and IPv4 (V6ONLY=0 default
          # on Linux). One socket accepts traffic from both families.
          'bind': socket_uri,
          'workers': httpd_workers,
          'worker_class': 'gevent',
          'worker_connections': 1000,
          'timeout': 30,
          'keepalive': 5,
          'certfile': self.cert_file,
          'keyfile': self.key_file,
          'ssl_context': create_ssl_context,
          'user': self.user,
          'group': self.group,
          'proc_name': 'otpme-httpd-https',
          'logger_class': CustomLogger,
        }

        # Wrapper to fix "ggevent.py:38: MonkeyPatchWarning: Monkey-patching ssl after ssl has already been imported may lead to errors, including..."
        # https://github.com/benoitc/gunicorn/issues/2796
        def start_https_gunicorn():
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
        self.gunicorn_ssl_child = multiprocessing.start_process(name="gunicorn-https",
                                                #target=gunicorn_app.run,
                                                target=start_https_gunicorn,
                                                new_process_group=True)

        # Plain-HTTP CA publisher: a second gunicorn instance binds the
        # CA-publish app on the configured non-TLS socket. We can't
        # share the SSO master because gunicorn's TLS config is
        # per-master -- every bound socket on a single instance is
        # either all-TLS or all-plain. Disabling is opt-in via
        # ``httpd_workers=0`` -- typical use case is a host where
        # port 80 is owned by a reverse proxy / ACME http-01 responder.
        http_workers = own_host.get_config_parameter("httpd_workers")
        if http_workers is None:
            http_workers = 2
        http_socket_uri = own_host.get_config_parameter("httpd_socket_uri")
        if not http_socket_uri:
            http_socket_uri = "tcp://[::]:80"

        if http_workers > 0:
            http_options = {
                'bind': http_socket_uri,
                'workers': http_workers,
                'worker_class': 'gevent',
                'worker_connections': 100,
                'timeout': 30,
                'keepalive': 5,
                'user': self.user,
                'group': self.group,
                'proc_name': 'otpme-httpd-http',
                'logger_class': CustomLogger,
            }

            def start_http_gunicorn():
                # Same gevent-monkey-patch ordering rationale as the SSL
                # child: patch BEFORE gunicorn imports its stdlib bits,
                # else we get the MonkeyPatchWarning + sporadic SSL/IO
                # races.
                try:
                    import gevent.monkey
                    gevent.monkey.patch_all()
                except ImportError:
                    pass
                GunicornApp(certs_app, http_options).run()

            try:
                self.gunicorn_child = multiprocessing.start_process(
                                                name="gunicorn-http",
                                                target=start_http_gunicorn,
                                                new_process_group=True)
                log_msg = _("Started plain-HTTP httpd on {uri} ({workers} workers).", log=True)[1]
                log_msg = log_msg.format(uri=http_socket_uri,
                                          workers=http_workers)
                self.logger.info(log_msg)
            except Exception as e:
                # A failed spawn must NOT block the SSO gunicorn. The
                # CA publisher is auxiliary; log and continue.
                log_msg = _("Failed to start plain-HTTP CA publisher on "
                            "{uri}: {error}", log=True)[1]
                log_msg = log_msg.format(uri=http_socket_uri, error=e)
                self.logger.warning(log_msg, exc_info=True)
                self.gunicorn_child = None
        else:
            log_msg = _("Plain-HTTP httpd disabled (httpd_workers=0).", log=True)[1]
            self.logger.info(log_msg)

        # Start main loop.
        self.__run()

    def _reload_cert(self):
        """ Re-read the Site's SSO cert/key from the backend, re-encrypt
        the private key with the existing passphrase, and atomically
        overwrite the temp files gunicorn is configured with.

        Followed by SIGHUP to the gunicorn master, which spawns fresh
        workers; each new worker calls our ``create_ssl_context``
        callback which re-reads the files from disk. In-flight
        connections on old workers terminate gracefully, so the cert
        rotation is zero-downtime.

        Failures are logged and the existing cert is left in place --
        a broken rotation must NOT bring the OP down.
        """
        own_site = backend.get_object(uuid=config.site_uuid)
        if not own_site or not own_site.sso_cert or not own_site.sso_key:
            log_msg = _("Cert reload skipped: site has no sso_cert/sso_key.",
                        log=True)[1]
            self.logger.warning(log_msg)
            return False
        try:
            check_ssl_cert_key(own_site.sso_cert, own_site.sso_key)
        except Exception as e:
            log_msg = _("Cert reload aborted: new SSO cert/key do "
                        "not match: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return False

        try:
            _cert = SSLCert(key=own_site.sso_key)
            encrypted_key = _cert.encrypt_key(passphrase=self.key_pass)
        except Exception as e:
            log_msg = _("Cert reload aborted: failed to re-encrypt key: "
                        "{error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg, exc_info=True)
            return False

        # Atomic per-file write: stage to <path>.new, fsync, rename.
        # On Linux, rename within the same directory is atomic, so a
        # gunicorn worker spawning concurrently never sees a half-
        # written file.
        try:
            self._atomic_write(self.cert_file, own_site.sso_cert,
                                mode=0o600)
            self._atomic_write(self.key_file, encrypted_key,
                                mode=0o600)
        except Exception as e:
            log_msg = _("Cert reload failed during file write: {error}",
                        log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg, exc_info=True)
            return False

        # SIGHUP signals gunicorn master to reload: workers are
        # gracefully restarted (drain + replace), each new worker
        # invokes create_ssl_context which re-reads the updated files.
        try:
            os.kill(self.gunicorn_ssl_child.pid, signal.SIGHUP)
        except Exception as e:
            log_msg = _("Cert reload: failed to SIGHUP gunicorn "
                        "(pid={pid}): {error}", log=True)[1]
            log_msg = log_msg.format(pid=getattr(self.gunicorn_ssl_child,
                                                  'pid', '?'), error=e)
            self.logger.warning(log_msg, exc_info=True)
            return False

        log_msg = _("SSO cert reloaded; gunicorn SIGHUP'd for "
                    "graceful worker rotation.", log=True)[1]
        self.logger.info(log_msg)
        return True

    def _atomic_write(self, path, content, mode=0o600):
        """ Stage to ``<path>.new``, fsync, ``os.replace`` onto path.
        ``os.replace`` is atomic on POSIX within the same FS, so a
        concurrent gunicorn-worker open() sees either the old or the
        new file -- never a partial one. Ownership matches the
        configured daemon user/group.
        """
        tmp = f"{path}.new"
        fd = open(tmp, "w")
        try:
            fd.write(content)
            fd.flush()
            os.fsync(fd.fileno())
        finally:
            fd.close()
        filetools.set_fs_permissions(path=tmp, mode=mode, recursive=False)
        if self.user or self.group:
            filetools.set_fs_ownership(path=tmp,
                                        user=self.user,
                                        group=self.group,
                                        recursive=False)
        os.replace(tmp, path)

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
                    # Pick up an updated SSO cert/key via SIGHUP to
                    # the gunicorn master. The reload is in-process
                    # (no daemon restart) so existing connections
                    # drain on the old workers and new ones come up
                    # with the new cert. On failure we still report
                    # reload_done -- the alternative (reload_shutdown)
                    # would tear down the OP for what is at worst a
                    # cert-not-rotated condition the operator can
                    # observe in the log.
                    try:
                        self._reload_cert()
                    except Exception as e:
                        log_msg = _("Cert reload raised unexpectedly: "
                                    "{error}", log=True)[1]
                        log_msg = log_msg.format(error=e)
                        self.logger.critical(log_msg, exc_info=True)
                    self.comm_handler.send("controld", command="reload_done")
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in httpd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
