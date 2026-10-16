# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import pprint
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {}")
        msg = msg.format(__name__)
        print(msg)
except Exception:
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
from otpme.lib.protocols.utils import gen_backup_rsa_key
from otpme.lib.protocols.utils import reencrypt_share_key
from otpme.lib.protocols.utils import create_remote_job
from otpme.lib.protocols.utils import change_user_default_group

from otpme.lib.exceptions import *

CALLBACK_LOCK_TYPE = "callback"

# How long one wait for an answer from the client lasts. It does not
# bound the answer -- a user may take as long as they are given to type
# a password -- it is how often we get to look around while waiting:
# whether the job was asked to stop and whether it ran out of time. An
# answer that arrives ends the wait at once, so this costs nothing.
ANSWER_POLL_TIME = 0.5

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
        # The same by read OID, to answer "do we know this one" without
        # walking the list. A recursive add_acl puts every object of a
        # tree in here, and searching a list of some thousand OIDs for
        # every next object is what made such a run slower the further
        # it got (OID.__eq__() per entry).
        self._modified_object_ids = set()
        # Will hold all locked objects.
        self.locked_objects = []
        # Indicates that a job should stop.
        self.stop_job = False
        # Post methods to run afer job succeeded.
        self.post_methods = []
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
        """ Add modified object to callback.

        Asked of the list and not of a set of OIDs beside it, unlike
        the modified objects below. Renaming an object changes its OID
        while it is cached here, and a set keyed by the old one would
        take it for a second object and let the same lock be released
        twice. See ObjectTransaction.cache_locked_object().
        """
        if o in self.locked_objects:
            return
        self.locked_objects.append(o)
        self.last_used = time.time()

    def get_modified_object_id(self, object_id):
        """ What we know a modified object by.

        Its read OID, which names it without the site, the same key the
        object cache uses (cache.add_modified_object()). A string,
        because OIDs are made to be compared and not to be hashed: a
        resolved and an unresolved OID of the same object are equal but
        hash differently, see oid.OID.__hash__().
        """
        return object_id.read_oid or str(object_id)

    def add_modified_object(self, o):
        """ Add modified object to callback. """
        object_id = self.get_modified_object_id(o.oid)
        if object_id in self._modified_object_ids:
            return
        self._modified_object_ids.add(object_id)
        self.modified_objects.append(o.oid)
        self.last_used = time.time()
        self.job.objects_written.value = True

    def write_modified_objects(self):
        """ Write objects modified by this callback.

        All of them or none, in one transaction: they were changed
        together, by one job, and one of them missing would leave the
        others pointing at something that is not there. Within a
        transaction of the caller they go into that one, and a failure
        is raised for it to abort.

        An object counts as written only when the transaction is
        committed. Its changes used to be reset whatever _write()
        returned, so a write that failed was forgotten without a word.

        Returns the OIDs of the objects written, False if none of them
        were written because one failed.
        """
        from otpme.lib import cache
        from otpme.lib import backend
        objects = []
        for object_id in self.modified_objects:
            o = cache.get_modified_object(object_id)
            if not config.no_backend_writes:
                cache.remove_modified_object(object_id)
            if not o or not o._modified:
                continue
            objects.append(o)
        if not objects:
            return []

        start_transaction = backend.get_transaction() is None
        if start_transaction:
            backend.begin_transaction(name="write_modified_objects",
                                    callback=self)
        try:
            for o in objects:
                log_msg = _("Writing modified object (Job): {}", log=True)[1]
                log_msg = log_msg.format(o)
                self.logger.debug(log_msg)
                if o._write(callback=self) is False:
                    msg = _("Failed to write object: {oid}")
                    msg = msg.format(oid=o.oid)
                    raise OTPmeException(msg)
        except Exception as e:
            if not start_transaction:
                raise
            backend.abort_transaction()
            error = e
        else:
            error = None
            if start_transaction:
                if backend.end_transaction() is False:
                    error = _("Failed to commit the transaction.")

        if error is not None:
            msg, log_msg = _("Modified objects not written: {error}", log=True)
            msg = msg.format(error=error)
            log_msg = log_msg.format(error=error)
            self.logger.critical(log_msg)
            # What is in memory was not stored. Nobody is to read it
            # or write it later as if it were.
            for o in objects:
                cache.clear(object_id=o.oid,
                            cache_type=cache.PROCESS_CACHE,
                            keep_modified=False)
            # A callback that is not enabled raises whatever it is
            # told, and the caller gets False either way.
            if self.enabled:
                self.error(msg, raise_exception=False)
            return False

        objects_written = []
        for o in objects:
            # Reset modified stuff before adding object to cache.
            o.reset_modified()
            # Add object to cache.
            cache.add_instance(o)
            objects_written.append(o.oid.full_oid)
        return objects_written

    def forget_modified_objects(self):
        """ Forget objects modified by this callback. """
        from otpme.lib import cache
        for object_id in self.modified_objects:
            cache.remove_modified_object(object_id)
        self.modified_objects = []
        self._modified_object_ids = set()

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
        """ Send message to client and handle answer.

        The answer is waited for in rounds, because a client that is
        gone sends none, and this used to be a wait without an end: the
        job kept its object locks and its transaction while it waited,
        an authentication that wanted one of those objects waited for
        the job, and the client of that one waited for both. Three
        waits, and the first of them had no end.

        A SIGTERM was no way out either. A job with an active
        transaction answers one with "not stoppable at this stage" and a
        flag on this callback (OTPmeJob.start_job), and nobody can read
        a flag from inside a blocking recv.

        So each round asks the two questions that end a wait: was the
        job asked to stop, and did it run out of time. The second is the
        job timeout the client sends with every request (--job-timeout),
        counted from the moment this message went out -- the same
        deadline the timeout thread of a job that runs as a process
        watches, which is the only reason that case ever ended.
        """
        # Callback was used.
        self.last_used = time.time()
        # Send message to client.
        self._send(message, timeout=timeout)
        # Receive answer
        comm_handler = self.job.comm_queue.get_handler("callback")
        answer = None
        answer_id = None
        while True:
            try:
                sender, \
                answer_id, \
                answer = comm_handler.recv(sender="client",
                                        timeout=ANSWER_POLL_TIME)
            except TimeoutReached:
                # Nothing yet. Have a look around and wait again.
                if self.job.check_timeout():
                    break
                if self.stop_job:
                    msg = _("Job stopped while waiting for an answer.")
                    raise OTPmeException(msg) from None
                continue
            except ExitOnSignal:
                self.job.stop()
                answer_id = None
            break
        # A job that is over its time ends here, whether its answer came
        # or the wait ran out.
        if self.job.check_timeout():
            if self.job.start_process:
                # Do some cleanup.
                multiprocessing.cleanup()
                #os._exit(0)
                sys.exit(0)
            # A job that runs as a thread has no process of its own to
            # end, and nothing of the daemon it runs in is ours to clean
            # up. The exception is the way out: the job writes nothing,
            # releases its locks and answers its client on the way
            # (OTPmeJob.start_job).
            msg = _("Timeout waiting for answer from client.")
            raise OTPmeException(msg)
        if answer_id != message_id:
            msg = _("Received wrong answer ID: {} <> {}")
            msg = msg.format(message_id, answer_id)
            raise OTPmeException(msg)
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
        # No need to add message for API calls.
        if self.job._caller == "API":
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
    def ok(self, message='\0OTPME_NULL\0', return_value=False, timeout=1):
        """ Return given message or just True. """
        if message != '\0OTPME_NULL\0':
            if return_value:
                self.job.return_value = message
            else:
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
        if self.job._caller == "API":
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
                if self.job._caller != "API":
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
                        except Exception:
                            pass
                else:
                    # For API/RAPI calls we have to set the return value.
                    self.job.return_value = message
        else:
            raise_exception = True

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
    def sshauth(self, challenge, token_test=False, timeout=1):
        """ Send message to ask the user/client to authenticate via ssh key. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = sshauth(message_id, challenge, token_test=token_test)
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
                        realm=user.realm,
                        site=user.site,
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
            raise OTPmeException(msg) from e
        try:
            jwt_data = _jwt.decode(jwt=jwt,
                                   key=jwt_key,
                                   algorithm='RS256')
        except Exception as e:
            config.raise_exception()
            msg = _("JWT decoding failed.")
            raise OTPmeException(msg) from e
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
    def gen_backup_rsa_key(self, key_name, key_len, timeout=1):
        """ Send message to client to generate privat/public backup keys. """
        # If the callback is disabled we do not send anything to the client.
        if not self.enabled:
            raise OTPmeException(self.api_exception)
        if self.api_mode:
            raise OTPmeException(self.api_exception)
        # Gen message ID.
        message_id = self._gen_message_id()
        # Build message string.
        message = gen_backup_rsa_key(message_id,
                                    key_name=key_name,
                                    key_len=key_len)
        # Send message.
        response = self._send_message(message_id, message, timeout=timeout)
        return response

    @handle_exception
    def gen_user_keys(self, username, sign_algo="rsa",
        encrypt_algo="rsa", key_len=2048, stdin_pass=False, timeout=1):
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
                            sign_algo=sign_algo,
                            encrypt_algo=encrypt_algo,
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
    def stop(self, status, message=None, timeout=1,
        raise_exception=True, exception=None):
        """ Set exit code and message that should be sent to the user. """
        if message is None:
            message = ""
        # Make sure message is string.
        if self.job._caller == "CLIENT":
            if not isinstance(message, str):
                message = pprint.pformat(message)

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
            except Exception:
                pass

        # Wakeup mgmtd waiting for new job messages/queries.
        self.send(None, command="job_end", timeout=timeout)

        return status, message
