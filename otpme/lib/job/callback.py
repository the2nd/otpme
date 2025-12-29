# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import functools
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {}")
        msg = msg.format(__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import multiprocessing
from otpme.lib.protocols.utils import ask
from otpme.lib.protocols.utils import sign
from otpme.lib.protocols.utils import scauth
from otpme.lib.protocols.utils import askpass
from otpme.lib.protocols.utils import sshauth
from otpme.lib.protocols.utils import encrypt
from otpme.lib.protocols.utils import decrypt
from otpme.lib.protocols.utils import auth_jwt
from otpme.lib.protocols.utils import send_msg
from otpme.lib.protocols.utils import dump_data
from otpme.lib.protocols.utils import move_objects
from otpme.lib.protocols.utils import gen_share_key
from otpme.lib.protocols.utils import gen_user_keys
from otpme.lib.protocols.utils import send_keepalive
from otpme.lib.protocols.utils import reencrypt_share_key
from otpme.lib.protocols.utils import create_remote_job
from otpme.lib.protocols.utils import change_user_default_group

from otpme.lib.exceptions import *

CALLBACK_LOCK_TYPE = "callback"

locking.register_lock_type(CALLBACK_LOCK_TYPE, module=__file__)
def callback_lock(write=True, timeout=None):
    """ Decorator to handle entry lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            self.lock(write=write)
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                self.release()
            return result
        return wrapped
    return wrapper

class JobCallback(object):
    """ Class to handle user messages from job child processes. """
    def __init__(self, name="default", job=None, uuid=None, api_mode=None, client="API"):
        class FakeJob(object):
            def __init__(self, uuid=None, api_mode=True):
                self.uuid = uuid
                self.exit_info = {}
                self.client = client
                self._caller = "API"
                self.return_value = None
                class FakeBool(object):
                    def __init__(self):
                        self.value = False
                self.objects_written = FakeBool()
        if job:
            self.job = job
            if api_mode is None:
                self.api_mode = False
            else:
                self.api_mode = api_mode
            self.api_exception = None
        else:
            if api_mode is None:
                self.api_mode = True
            else:
                self.api_mode = api_mode
            self.api_exception = "Cannot callback in API mode!"
            self.job = FakeJob(uuid=uuid, api_mode=self.api_mode)
        # Callback name.
        self.name = name
        # Only send error messages. Used e.g. in mass_object_add.
        self.only_errors = False
        # Indicates that there was a exception in the callback chain that
        # needs to stop the job.
        self._exception = None
        # Indicates that self.error() should always raise an exception.
        self.raise_exception = False
        # Indicates if this callback will send messages to its client.
        self.enabled = True
        # Will hold all (modified objects this callback was used. in.
        self.modified_objects = []
        # Will hold all locked objects.
        self.locked_objects = []
        # Indicates that a job should stop.
        self.stop_job = False
        # Get logger.
        self.logger = config.logger
        # Time the callback was last used.
        self.last_used = time.time()
        self._lock = None

    def __str__(self):
        return self.name

    def lock(self, write=False):
        self._lock = locking.acquire_lock(lock_type=CALLBACK_LOCK_TYPE,
                                        lock_id=self.name,
                                        write=write)
        return self._lock

    def release(self):
        if not self._lock:
            return
        try:
            self._lock.release_lock()
        except Exception as e:
            log_msg = _("Failed to release callback lock: {name}: {error}", log=True)[1]
            log_msg = log_msg.format(name=self.name, error=e)
            self.logger.warning(log_msg)
        self._lock = None

    def add_locked_object(self, o):
        """ Add modified object to callback. """
        if o in self.locked_objects:
            return
        self.locked_objects.append(o)
        self.last_used = time.time()

    def add_modified_object(self, o):
        """ Add modified object to callback. """
        if o.oid in self.modified_objects:
            return
        self.modified_objects.append(o.oid)
        self.last_used = time.time()
        self.job.objects_written.value = True

    def write_modified_objects(self):
        """ Write objects modified by this callback. """
        from otpme.lib import cache
        objects_written = []
        for object_id in self.modified_objects:
            o = cache.get_modified_object(object_id)
            cache.remove_modified_object(object_id)
            if not o or not o._modified:
                continue
            log_msg = _("Writing modified object (Job): {}", log=True)[1]
            log_msg = log_msg.format(o)
            self.logger.debug(log_msg)
            o._write(callback=self)
            # Reset modified stuff before adding object to cache.
            o.reset_modified()
            # Add object to cache.
            cache.add_instance(o)
            objects_written.append(o.oid.full_oid)
        return objects_written

    def forget_modified_objects(self):
        """ Forget objects modified by this callback. """
        from otpme.lib import cache
        for object_id in list(self.modified_objects):
            cache.remove_modified_object(object_id)
            self.modified_objects.remove(object_id)

    def release_cache_locks(self):
        """ Release all 'cached' locks. """
        for o in list(self.locked_objects):
            self.locked_objects.remove(o)
            o.release_lock(lock_caller="cached")

    def handle_exception(method):
        """ Raise exception. """
        def wrapper(self, *args, **kwargs):
            # If there was a exception in our calling chain we have to raise it.
            if config.raise_exceptions:
                if self._exception:
                    raise self._exception
            return method(self, *args, **kwargs)

        # Update func/method.
        functools.update_wrapper(wrapper, method)
        if not hasattr(wrapper, '__wrapped__'):
            # Python 2.7
            wrapper.__wrapped__ = method

        return wrapper

    def exception(self, exception):
        """ Handle exceptions. """
        # We need to remember the exception and re-raise it each time the
        # callback is called. This way we should get a useful stacktrace.
        self._exception = exception
        raise exception

    def _gen_message_id(self):
        """ Generate message ID. """
        # Gen message ID.
        message_id = f"callback:{stuff.gen_secret()}"
        return message_id

    def _send(self, message, command=None, timeout=1):
        if command is None:
            command = "message"
        comm_handler = self.job.comm_queue.get_handler("callback")
        try:
            comm_handler.send(recipient="client",
                            command=command,
                            data=message,
                            timeout=timeout)
        except ExitOnSignal:
            self.job.stop()
        self.last_used = time.time()

    @callback_lock(write=True)
    def _send_message(self, message_id, message, timeout=1, convert_type=True):
        """ Send message to client and handle answer. """
        # Callback was used.
        self.last_used = time.time()
        # Send message to client.
        self._send(message, timeout=timeout)
        # Receive answer
        comm_handler = self.job.comm_queue.get_handler("callback")
        try:
            sender, \
            answer_id, \
            answer = comm_handler.recv(sender="client")
        except ExitOnSignal:
            self.job.stop()
            answer_id = None
        if answer_id != message_id:
            msg = _("Received wrong answer ID: {} <> {}")
            msg = msg.format(message_id, answer_id)
            raise OTPmeException(msg)
        # Wait for answer from peer.
        if self.job.check_timeout():
            # Do some cleanup.
            multiprocessing.cleanup()
            #os._exit(0)
            sys.exit(0)
        # FIXME: Converting from string to type() leads to some "reserved"
        #        strings (True, False and None) because they are converted
        #        to the corresponding python types. This means that e.g. a
        #        password that is just the string "False" will fail.
        # Convert string to type().
        if convert_type:
            answer = stuff.string_to_type(value=answer)

        return answer

    def keepalive(self, timeout=1):
        """ Send message to user. """
        if self.api_mode:
            return
        message = send_keepalive(job_id=self.job.uuid)
        self._send(message, timeout=timeout)
        return True

    def send(self, message='\0OTPME_NULL\0', error=False,
        command=None, timeout=1, ignore_escaping=False):
        """ Send message to user. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            return message
        if self.only_errors:
            if not error:
                return
        # In API mode we have to print the given message.
        if self.api_mode:
            print(message)
            return
        # No need to add message for API/RAPI calls.
        if self.job._caller != "CLIENT":
            return message
        if message == '\0OTPME_NULL\0':
            return True
        # Send message.
        _message = (True, message)
        if error:
            _message = (False, message)
        if ignore_escaping:
            message = dump_data(job_id=self.job.uuid, message=_message)
        else:
            message = send_msg(job_id=self.job.uuid, message=_message)
        self._send(message, command=command, timeout=timeout)
        return True

    @handle_exception
    def ok(self, message='\0OTPME_NULL\0', timeout=1):
        """ Return given message or just True. """
        if message != '\0OTPME_NULL\0':
            if self.job._caller == "CLIENT":
                return self.send(message, timeout=timeout)
            # For API/RAPI calls we have to set the return value.
            if self.job._caller == "RAPI":
                self.job.return_value = message
                return True
            return message
        return True

    @handle_exception
    def abort(self, message='\0OTPME_NULL\0', timeout=1):
        """ Return None and send 'message' if given. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            return None
        # For API/RAPI calls we do not have to send the abort message.
        if self.job._caller != "CLIENT":
            return None
        if message == '\0OTPME_NULL\0':
            return
        # Send message.
        self.send(message, timeout=timeout)
        return None

    @handle_exception
    def error(self, message='\0OTPME_NULL\0',
        raise_exception=None, exception=None, timeout=1):
        """ Send error message to user. """
        if raise_exception is None:
            if self.raise_exception:
                raise_exception = True

        if self.enabled:
            # When enabled and not in API mode we will not raise any exception.
            if not self.api_mode:
                if raise_exception is None:
                    raise_exception = False

            if message != '\0OTPME_NULL\0':
                if self.job._caller == "CLIENT":
                    # Make sure message is string.
                    exit_info = str(message)
                    # Set jobs last error.
                    if len(exit_info) > 0:
                        try:
                            self.job.exit_info['last_error'] = exit_info
                        except Exception as e:
                            log_msg = _("Error updating jobs last error: {}", log=True)[1]
                            log_msg = log_msg.format(e)
                            self.logger.critical(log_msg)

                    # Add the message to callback channel.
                    if raise_exception is False:
                        try:
                            self.send(message, error=True, timeout=timeout)
                        except:
                            pass
                else:
                    # For API/RAPI calls we have to set the return value.
                    self.job.return_value = message

        if raise_exception:
            # If we got no exception to raise use the default.
            if not exception:
                exception = Exception
            # Finally raise our exception.
            raise exception(message)

        # And return False which is useful for "return callback.error("Foo")"
        return False

    @handle_exception
    def ask(self, message, input_prefill=None, timeout=1):
        """ Send message to ask the user for some input. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Make sure message is string.
        message = str(message)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = ask(message_id=message_id,
                    input_prefill=input_prefill,
                    prompt=message)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def askpass(self, prompt, null_ok=False, timeout=1):
        """ Send message to ask the user for a password. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = askpass(message_id=message_id,
                        prompt=prompt,
                        null_ok=null_ok)
        # Send message.
        result = self._send_message(message_id,
                                message,
                                timeout=timeout,
                                convert_type=False)
        return result

    @handle_exception
    def sshauth(self, challenge, timeout=1):
        """ Send message to ask the user/client to authenticate via ssh key. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = sshauth(message_id, challenge)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def scauth(self, smartcard_type, smartcard_data, timeout=1):
        """
        Send message to ask the user/client to authenticate via
        smartcard (e.g. fido2 tokens).
        """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = scauth(message_id=message_id,
                    smartcard_type=smartcard_type,
                    smartcard_data=smartcard_data)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def auth_jwt(self, reason, challenge, timeout=1):
        """
        Send message to ask the user/client to get a JWT.
        """
        from otpme.lib import backend
        from otpme.lib import jwt as _jwt
        from otpme.lib.pki.cert import SSLCert
        from otpme.lib.encryption.rsa import RSAKey
        if not config.auth_token:
            msg = _("Cannot do JWT auth without auth token.")
            raise OTPmeException(msg)
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Get user.
        user = backend.get_object(uuid=config.auth_token.owner_uuid)
        # Build message string.
        message = auth_jwt(message_id=message_id,
                        username=user.name,
                        reason=reason,
                        challenge=challenge)
        # Send message.
        jwt = self._send_message(message_id, message, timeout=timeout)
        if jwt is None:
            msg = _("No JWT received.")
            raise OTPmeException(msg)
        user_site = backend.get_object(uuid=user.site_uuid)
        site_cert = SSLCert(cert=user_site.cert)
        try:
            jwt_key = RSAKey(key=site_cert.public_key())
        except Exception as e:
            msg = _("Unable to get public key of site certificate: {user_site}: e{}")
            msg = msg.format(user_site=user.site, e=e)
            raise OTPmeException(msg)
        try:
            jwt_data = _jwt.decode(jwt=jwt,
                                   key=jwt_key,
                                   algorithm='RS256')
        except Exception as e:
            config.raise_exception()
            msg = _("JWT decoding failed.")
            raise OTPmeException(msg)
        # We do not allow SOTP generated JWTs. A login with a real
        # token is required.
        jwt_auth_type = jwt_data['auth_type']
        if jwt_auth_type != "token":
            msg = _("Need token login, got: {}")
            msg = msg.format(jwt_auth_type)
            raise OTPmeException(msg)
        # Verify challenge.
        jwt_challenge = jwt_data['challenge']
        if jwt_challenge != challenge:
            msg = _("Wrong JWT challenge.")
            raise OTPmeException(msg)
        # Verify JWT token.
        jwt_token = jwt_data['login_token']
        if jwt_token != config.auth_token.uuid:
            msg = _("Wrong login token: {}")
            msg = msg.format(jwt_token)
            raise OTPmeException(msg)

    @handle_exception
    def dump(self, message,  timeout=1):
        """ Dump some data on client site. """
        return self.send(message, timeout=timeout, ignore_escaping=True)

    @handle_exception
    def move_objects(self, object_data, timeout=1):
        """ Send message to client to move objects cross-site. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = move_objects(message_id, object_data=object_data)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def change_user_default_group(self, object_data, timeout=1):
        """ Send message to client to change users default group cross-site. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = change_user_default_group(message_id, object_data=object_data)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def create_remote_job(self, job_data, timeout=1):
        """ Send message to client to create job on remote site. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = create_remote_job(message_id, object_data=job_data)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def reencrypt_share_key(self, share_user, share_key, key_mode=None, timeout=1):
        """ Send message to client to generate and encrypt share key. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = reencrypt_share_key(message_id,
                            share_user=share_user,
                            share_key=share_key,
                            key_mode=key_mode)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def gen_share_key(self, key_len=2048, key_mode=None, timeout=1):
        """ Send message to client to generate and encrypt share key. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = gen_share_key(message_id, key_len=key_len, key_mode=key_mode)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def gen_user_keys(self, username,
        key_len=2048, stdin_pass=False, timeout=1):
        """ Send message to client to generate users privat/public keys. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = gen_user_keys(message_id,
                            username=username,
                            key_len=key_len,
                            stdin_pass=stdin_pass)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def sign(self, data, timeout=1):
        """ Send message to client to sign given data. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = sign(message_id, data=data)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def encrypt(self, data, use_rsa_key=True, timeout=1):
        """ Send message to client to encrypt given data. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = encrypt(message_id, use_rsa_key=use_rsa_key, data=data)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def decrypt(self, data, timeout=1):
        """ Send message to client to decrypt given data. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = decrypt(message_id, data=data)
        # Send message.
        return self._send_message(message_id, message, timeout=timeout)

    @handle_exception
    def enable(self):
        """ Enable callback. """
        self.enabled = True
        self.last_used = time.time()

    @handle_exception
    def disable(self):
        """ Disable callback. """
        self.enabled = False
        self.last_used = time.time()

    @handle_exception
    def stop(self, status, message="", timeout=1,
        raise_exception=True, exception=None):
        """ Set exit code and message that should be sent to the user. """
        if message is None:
            message = ""
        # Make sure message is string.
        if self.job._caller == "CLIENT":
            message = str(message)

        # In API mode "message" is the Exception we have to raise when status=False.
        if self.api_mode or not self.enabled:
            if status is False and raise_exception:
                if not exception:
                    exception = OTPmeException
                raise exception(message)
        else:
            # Update jobs exit infos.
            try:
                self.job.exit_info['exit_status'] = status
                if len(message) > 0:
                    try:
                        self.job.exit_info['exit_message'] = message
                    except Exception as e:
                        log_msg = _("Failed to add exit message: {}", log=True)[1]
                        log_msg = log_msg.format(e)
                        self.logger.critical(log_msg)
            except:
                pass

        # Wakeup mgmtd waiting for new job messages/queries.
        self.send(None, command="job_end", timeout=timeout)

        return status, message
