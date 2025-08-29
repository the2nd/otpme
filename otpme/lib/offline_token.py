# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import glob
import shutil

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import filetools
from otpme.lib import encryption
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.classes.data_objects.used_otp import UsedOTP
from otpme.lib.classes.data_objects.token_counter import TokenCounter

from otpme.lib.exceptions import *

LOCK_TYPE = "offline_token"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.token",
                "otpme.lib.encryption.argon2",
                ]

def register():
    register_config()
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def register_config():
    """ Register config stuff. """
    # Session key len in bits (RSA). This key (pair) is used to encrypt/decrypt the
    # RSP when its saved to disk for re-use (e.g. in offline mode).
    config.register_config_var("session_key_len", int, 2048)

class OfflineToken(object):
    """ Class to handle OTPme offline tokens. """
    def __init__(self):
        self.username = None
        self.user_uuid = None
        self.file_acls = []
        self.dir_acls = []
        self.session_key_private = None
        self.session_key_public = None
        self.offline_dir = None
        self.lock_file = None
        self.session_dir = None
        self.env_dir = None
        self.script_dir = None
        self.used_dir = None
        self.login_token_uuid = None
        self.session_uuid = None
        self.token_cache_dir = None
        self.offline_tokens = {}
        self.login_token_uuid_file = None
        self.offline_link_name = "offline"
        self.offline_data_key = None

        self.enc_key = None
        self.enc_salt = None
        self.enc_challenge = None
        self.enc_passphrase = None
        self.enc_iterations = None
        self.enc_key_derivation_func = config.offline_token_hash_type
        self.enc_key_derivation_func_opts = None
        self.offline_enc_parameters = None
        self.check_pass_strength = False
        self.iterations_by_score = None
        # Indicates that offline token encryption is required.
        self.need_encryption = None
        # Encryption type used for offline data.
        self.enc_type = config.disk_encryption

        # Will be set to True if login token has session keeping enabled.
        self.keep_session = False
        self._lock = None
        self.rsp_cipher = "PKCS1_OAEP"
        self.logger = config.logger

    def get_session_dir(self, session_id):
        """ Get login session dir. """
        session_dir = os.path.join(self.session_dir, session_id)
        return session_dir

    def get_session_file(self, realm=None, site=None, session_id=None):
        """ Get login session file. """
        if session_id:
            if not realm or not site:
                msg = (_("Need 'site' and 'realm'."))
                raise OTPmeException(msg)
            session_dir = self.get_session_dir(session_id)
            session_file_name = "%s:%s" % (realm, site)
            session_file = os.path.join(session_dir, session_file_name)
        else:
            session_file = os.path.join(self.session_dir, self.offline_link_name)
        return session_file

    def get_script_file_path(self, script_id):
        """ Get path script file. """
        script_file = "%s/%s.script" % (self.script_dir, script_id)
        return script_file

    def get_token_files(self):
        """ Get list with offline token files. """
        token_files = []
        if not self.token_cache_dir:
            return []
        if not os.path.exists(self.token_cache_dir):
            return []
        try:
            token_files = glob.glob(os.path.join(self.token_cache_dir, '*'))
        except Exception as e:
            msg = (_("Unable to access token cache dir: %s") % e)
            raise OTPmeException(msg)
        return token_files

    def init(self):
        """ Create offline base dir. """
        if os.path.exists(self.offline_dir):
            return
        filetools.create_dir(path=self.offline_dir,
                            user=self.username,
                            mode=0o700,
                            user_acls=self.dir_acls)

    def status(self):
        """ Return True if there are any cached offline tokens. """
        if self.get_token_files():
            return True
        return None

    def get_user(self, user_name=None, user_uuid=None):
        """ Get user UUID via hostd. """
        if not user_name and not user_uuid:
            msg = (_("Need at least user_name or user_uuid."))
            raise OTPmeException(msg)
        if not user_name and user_uuid:
            user_name = stuff.get_username_by_uuid(user_uuid)
        if not user_uuid and user_name:
            user_uuid = stuff.get_user_uuid(user_name)
        return user_name, user_uuid

    def set_user(self, user=None, uuid=None):
        """ Set username/UUID of user we handle offline tokens for. """
        if not user and not uuid:
            msg = (_("Need at least 'user' or 'uuid'!"))
            raise OTPmeException(msg)
        # Get username from UUID.
        if not user:
            user = self.get_user(user_uuid=uuid)[0]
            if not user:
                raise UnknownUser(_("Unable to get username: %s") % uuid)
        # Get UUID of user.
        if not uuid:
            uuid = self.get_user(user_name=user)[1]
            if not uuid:
                raise UnknownUser(_("Unable to get user UUID: %s") % user)
        # Set user UUID.
        self.username = user
        self.user_uuid = uuid
        # Posix ACLs we need to apply to new dirs/files because hostd needs fs
        # permissions to sync used OTPs and remove expired offline tokens.
        self.file_acls = [
                        "u:%s:rw" % self.username,
                        "u:%s:rw" % config.user,
                        ]

        self.dir_acls = [
                        "u:%s:rwx" % self.username,
                        "u:%s:rwx" % config.user,
                        ]

        # Users offline cache dir.
        self.offline_dir = "%s/%s" % (config.offline_dir, self.user_uuid)
        # Offline token lock file.
        self.lock_file = "%s/.lock" % self.offline_dir
        # Users OTPme session dir.
        self.session_dir = "%s/session" % self.offline_dir
        # Users shell sessions dir.
        self.env_dir = "%s/%s" % (config.env_dir, self.username)
        # Users script dir.
        self.script_dir = "%s/scripts" % self.offline_dir
        # Users used OTP dir.
        self.used_dir = "%s/used" % self.offline_dir
        # Users offline token dir.
        self.token_cache_dir = "%s/token" % self.offline_dir
        # Login token UUID file.
        self.login_token_uuid_file = "%s/.login_token" % self.token_cache_dir
        # Indicates that offline tokens are pinned.
        self.offline_token_pinned_file = "%s/.pin" % self.token_cache_dir

    def set_login_token(self, uuid, session_uuid):
        """ Write login token UUID to cache file. """
        # Set login token and server session UUID.
        self.session_uuid = session_uuid
        self.login_token_uuid = uuid

        login_config = {
                        'session_uuid'  : session_uuid,
                        'login_time'    : time.time(),
                        'login_token'   : uuid,
                    }

        login_token_uuid_dir = os.path.dirname(self.login_token_uuid_file)
        if not os.path.exists(login_token_uuid_dir):
            filetools.create_dir(path=login_token_uuid_dir,
                                user=self.username, mode=0o700,
                                user_acls=self.dir_acls)
        # Write login token file.
        try:
            filetools.write_data_file(self.login_token_uuid_file,
                                    login_config,
                                    full_data_update=True,
                                    user=self.username,
                                    mode=0o600,
                                    user_acls=self.file_acls)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error writing login file: %s") % e)
            raise OTPmeException(msg)

    @property
    def pinned(self):
        if os.path.exists(self.offline_token_pinned_file):
            return True
        return False

    def pin(self):
        """ Pin offline tokens. """
        if os.path.exists(self.offline_token_pinned_file):
            msg = "Offline tokens already pinned."
            raise OTPmeException(msg)
        # Load offline tokens.
        self.load()
        user_tokens = self.get()
        for x in user_tokens:
            token = user_tokens[x]
            if token.offline_pinnable:
                continue
            msg = "Token not pinnable: %s" % token.oid
            raise OTPmeException(msg)
        offline_token_pinned_dir = os.path.dirname(self.offline_token_pinned_file)
        if not os.path.exists(offline_token_pinned_dir):
            filetools.create_dir(path=offline_token_pinned_dir,
                                user=self.username, mode=0o700,
                                user_acls=self.dir_acls)
        # Write offline token pinned file.
        try:
            filetools.touch(self.offline_token_pinned_file,
                                    user=self.username,
                                    mode=0o600,
                                    user_acls=self.file_acls)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error writing pinned file: %s") % e)
            raise OTPmeException(msg)

    def unpin(self):
        """ Unpin offline tokens. """
        if not self.pinned:
            msg = "Offline tokens not pinned."
            raise OTPmeException(msg)
        os.remove(self.offline_token_pinned_file)

    def set_enc_passphrase(self, passphrase, key_function, key_function_opts=None,
        iterations_by_score={}, check_pass_strength=False, challenge=None):
        """ Set encrpytion passphrase + options. """
        self.enc_challenge = challenge
        self.enc_key_derivation_func = key_function
        self.enc_key_derivation_func_opts = key_function_opts
        self.check_pass_strength = check_pass_strength
        self.iterations_by_score = iterations_by_score
        self.enc_passphrase = passphrase
        if self.check_pass_strength:
            if not self.iterations_by_score:
                msg = (_("iterations_by_score needed for check_pass_strength."))
                raise OTPmeException(msg)

    def get_password_score(self, password, policy_name=None):
        """ Get password strength score via policy. """
        from otpme.lib import connections
        try:
            hostd_conn = connections.get("hostd")
        except Exception as e:
            msg = (_("Error connecting to hostd: %s") % e)
            raise OTPmeException(msg)

        try:
            score = hostd_conn.get_pass_strength(password=password,
                                            policy_name=policy_name)
        except Exception as e:
            msg = "Failed to get password score from hostd: %s" % e
            self.logger.warning(msg)
            score = 0
        finally:
            hostd_conn.close()

        return score

    def derive_key(self):
        """ Derive encryption key from passphrase and set it. """
        # When loading offline tokens self.offline_enc_parameters is read from
        # offline token config.
        if self.offline_enc_parameters:
            config_dict = self.offline_enc_parameters
        else:
            config_dict = self.enc_key_derivation_func_opts

        try:
            iterations = int(config_dict['iterations'])
        except:
            iterations = None
        try:
            min_mem = int(config_dict['min_mem'])
        except:
            min_mem = 65536
        try:
            max_mem = int(config_dict['max_mem'])
        except:
            max_mem = 262144
        try:
            memory = int(config_dict['memory'])
        except:
            memory = "auto"
        try:
            threads = int(config_dict['threads'])
        except:
            threads = 4
        try:
            key_function = config_dict['hash_type']
        except:
            key_function = self.enc_key_derivation_func

        # Check password strength.
        if not iterations and self.check_pass_strength:
            self.logger.debug("Requesting password strength score...")
            policy_name = None
            if self.check_pass_strength != "auto":
                policy_name = self.check_pass_strength
            score = self.get_password_score(password=self.enc_passphrase,
                                            policy_name=policy_name)
            score = int(score)
            iterations = self.iterations_by_score[score]
            # Set iterations to be stored in offline token config.
            self.enc_iterations = iterations
            self.logger.debug("Got password score: %s" % score)

        # Derive encryption key from password.
        try:
            result = encryption.derive_key(self.enc_passphrase,
                                    salt=self.enc_salt,
                                    min_mem=min_mem,
                                    max_mem=max_mem,
                                    memory=memory,
                                    threads=threads,
                                    iterations=iterations,
                                    hash_type=key_function,
                                    quiet=False)
        except Exception as e:
            msg = (_("Error deriving encryption key for offline token "
                    "encryption: %s") % e)
            self.logger.critical(msg, exc_info=True)
            raise OTPmeException(msg)

        # Get key and salt.
        key = result['key']
        salt = result['salt']
        # Make we have a valid encryption key (e.g. fernet needs base64 encoded key.)
        try:
            x = config.disk_encryption_mod.derive_key(key,
                                                salt=salt,
                                                hash_type=key_function)
        except Exception as e:
            msg = "Error loading encryption key: %s" % e
            raise OTPmeException(msg)
        # Update key/salt in result.
        result['key'] = x['key']
        result['salt'] = x['salt']

        # Get hash parameters from result (will be saved in offline token config).
        self.offline_enc_parameters = {
                    'hash_type'     : result['hash_type'],
                    'iterations'    : result['iterations'],
                    'challenge'     : self.enc_challenge,
                    'threads'       : result['threads'],
                    'memory'        : result['memory'],
                    'salt'          : result['salt'],
                    }

        return result

    def lock(self):
        """ Create offline token lock. """
        if not self.lock_file:
            msg = (_("Lockfile not set."))
            raise OTPmeException(msg)
        if not os.path.exists(self.offline_dir):
            return
        self._lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                        lock_id=self.lock_file,
                                        timeout=10)
    def unlock(self):
        """ Remove offline token lock. """
        if not self._lock:
            return True
        self._lock.release_lock()
        self._lock = None

    #def get_session_key(self, realm=None, site=None, session_id=None):
    #    """ Get session public key from session file. """
    #    session_file = self.get_session_file(realm, site, session_id)
    #    if not os.path.exists(session_file):
    #        return None
    #    session_config = filetools.read_data_file(session_file)
    #    session_key = decode(session_config['KEY'], "hex")
    #    return session_key

    def gen_session_key(self):
        """ Generate session private/public key pair. """
        # Generate new RSA key pair.
        key = RSAKey(bits=config.session_key_len)
        # Get session private key as base64.
        self.session_key_private = key.private_key_base64
        # Get session public key as base64.
        self.session_key_public = key.public_key_base64

    def get_offline_session(self):
        """ Get session ID, realm and site of the offline login session. """
        session_link = self.get_session_file()
        session_file = os.path.realpath(session_link)
        if not os.path.exists(session_file):
            return None, None, None
        realm = os.path.basename(session_file).split(":")[-2]
        site = os.path.basename(session_file).split(":")[-1]
        session_id = os.path.dirname(session_file)
        session_id = os.path.basename(session_id)
        return realm, site, session_id

    def get_session_uuid(self, realm, site, session_id):
        """ Get session UUID from session file. """
        uuid = None
        session_file = self.get_session_file(realm, site, session_id)
        if os.path.exists(session_file):
            try:
                session_config = filetools.read_data_file(session_file)
            except Exception as e:
                msg = (_("Error reading login session file: %s") % e)
                raise OTPmeException(msg)
            try:
                uuid = session_config['SESSION_UUID']
            except:
                msg = (_("SESSION_UUID missing in login session file."))
                raise OTPmeException(msg)
        return uuid

    def get_old_offline_sessions(self, realm, site):
        """
        Get all outdated sessions + the SLP if the session is not in use.
        """
        sessions = {}
        if not os.path.exists(self.session_dir):
            return
        sessions = os.listdir(self.session_dir)
        try:
            sessions.remove(self.offline_link_name)
        except:
            pass
        old_sessions = {}
        for session_id in sessions:
            login_pid = session_id.split(":")[0]
            # Skip running sessions.
            if stuff.check_pid(login_pid):
                continue
            # Sessions not in use will be logged out by OTPmeClient().
            _slp = self.get_slp(realm=realm, site=site, session_id=session_id)
            if _slp:
                old_sessions[session_id] = _slp
        return old_sessions

    def set_replacement_methods(self, object_id):
        # Set replacement methods to replace token read/write methods with those
        # from this module.
        replacement_methods = {
                                'read_config'       : self.read_config,
                                'write_config'      : self.write_config,
                                'delete_object'     : self.delete_object,
                                'get_used_otps'     : self.get_used_otps,
                                'get_token_counter' : self.get_token_counter,
                                'add_used_otp'      : self.add_used_otp,
                                'add_token_counter' : self.add_token_counter,
                            }
        for i in replacement_methods:
            try:
                config.offline_methods[i]
            except:
                config.offline_methods[i] = {}
            config.offline_methods[i][object_id.read_oid] = replacement_methods[i]

    def add_token_counter(self, token_counter):
        """ Add token counter to cache dir. """
        self.set_replacement_methods(token_counter.oid)
        token_counter.offline = True
        token_counter.add()

    def add_used_otp(self, used_otp):
        """ Add token counter to cache dir. """
        self.set_replacement_methods(used_otp.oid)
        used_otp.offline = True
        used_otp.add()

    def add(self, object_id, object_config=None):
        """ Add offline token. """
        # Set replacement methods.
        self.set_replacement_methods(object_id)
        try:
            token_parameter = self.offline_tokens[object_id]
        except:
            token_parameter = {}

        if object_config is not None:
            from otpme.lib import token
            # Add object config.
            token_parameter['object_config'] = object_config
            # Get user name and token name from object path.
            object_realm = object_id.realm
            object_site = object_id.site
            #user_name = object_id.user
            token_name = object_id.name
            # Get token type from config.
            #token_type = self.read_config(object_id)['TOKEN_TYPE']
            token_type = object_config['TOKEN_TYPE']
            owner_uuid = object_config['OWNER']
            # Get token class.
            token_class = token.get_class(token_type)
            # Create token instance.
            instance = token_class(name=token_name,
                                    #user=user_name,
                                    owner_uuid=owner_uuid,
                                    realm=object_realm,
                                    site=object_site)
            # Make sure token is in offline mode to get read/write methods
            # replaced by their offline versions.
            instance.offline = True
            # Load token config.
            instance.exists()
            # Add token instance.
            token_parameter['instance'] = instance

        self.offline_tokens[object_id] = token_parameter

    def get(self, object_id=None):
        """ Get offline token instance(s). """
        if object_id:
            if not object_id in self.offline_tokens:
                msg = (_("Unknown offline token: %s") % object_id)
                raise OTPmeException(msg)
            # Get instance from cache.
            instance = self.offline_tokens[object_id]['instance']
            # Make sure token is in offline mode to get read/write methods
            # replaced by their offline versions.
            instance.offline = True
            if instance._load():
                return instance
            return None
        else:
            login_token = None
            cached_tokens = { }

            for object_id in self.offline_tokens:
                instance = self.get(object_id)
                if instance.uuid == self.login_token_uuid:
                    login_token = instance
                    cached_tokens['login_token'] = instance
                else:
                    cached_tokens[instance.uuid] = instance

            # If the login token has a second factor token enabled check
            # if we have it (cached).
            if login_token and login_token.second_factor_token_enabled:
                try:
                    login_token.sftoken = cached_tokens[login_token.second_factor_token]
                except:
                    msg = (_("Cannot find second factor token of: %s")
                            % login_token.rel_path)
                    raise OTPmeException(msg)
                self.logger.debug("Found offline second factor token: %s"
                                % login_token.sftoken.rel_path)
            return cached_tokens

    def load(self):
        """ Load offline tokens from disk. """
        # Get list with cached offline token files.
        token_files = self.get_token_files()

        if len(token_files) == 0:
            return {}

        if not os.path.exists(self.login_token_uuid_file):
            msg = (_("Unable to do offline login: No such file or "
                    "directory: %s") % self.login_token_uuid_file)
            raise OTPmeException(msg)

        # Read login token UUID from file.
        try:
            login_config = filetools.read_data_file(self.login_token_uuid_file)
        except Exception as e:
            msg = (_("Error reading file: %s: %s")
                    % (self.login_token_uuid_file, e))
            raise OTPmeException(msg)

        # Get login token and login time.
        self.login_token_uuid = login_config['login_token']
        self.session_uuid = login_config['session_uuid']
        login_time = login_config['login_time']

        if not stuff.is_uuid(self.login_token_uuid):
            msg = (_("Got invalid UUID from %s")
                    % self.login_token_uuid_file)
            raise OTPmeException(msg)

        for t in token_files:
            token_oid = os.path.basename(t)
            token_oid = token_oid.replace(":", "/")
            token_oid = oid.get(object_id=token_oid)
            try:
                object_config = self.read_config(token_oid)
            except Exception as e:
                msg = (_("Failed to load offline token: %s: %s")
                        % (token_oid, e))
                raise OTPmeException(msg)
            # Load object config.
            object_config = ObjectConfig(token_oid, object_config, encrypted=False)
            # Need_encryption indicates that one of the offline tokens needs
            # encryption.
            if not self.need_encryption:
                try:
                    if object_config['NEED_OFFLINE_ENCRYPTION'] == True:
                        self.need_encryption = True
                    else:
                        self.need_encryption = False
                except:
                    # FIXME: what should be the default? raise exception if config does not include this setting???!!!
                    self.need_encryption = True

            if self.need_encryption and not self.offline_enc_parameters:
                if "OTPME_OFFLINE_ENC_PARAMETERS" in object_config:
                    json_string = object_config.pop('OTPME_OFFLINE_ENC_PARAMETERS')
                    self.offline_enc_parameters = json.decode(json_string,
                                                            encoding="base64")
                if not self.enc_salt:
                    try:
                        self.enc_salt = self.offline_enc_parameters['salt']
                    except:
                        pass

                if not self.enc_iterations:
                    try:
                        self.enc_iterations = self.offline_enc_parameters['iterations']
                    except:
                        pass

                if not self.enc_challenge:
                    try:
                        self.enc_challenge = self.offline_enc_parameters['challenge']
                    except:
                        pass

            # Add login token to offline token dict.
            self.add(object_id=token_oid, object_config=object_config)
            # Get token instance.
            instance = self.get(token_oid)

            if instance.uuid != self.login_token_uuid:
                continue

            # Remove outdated login session. This is required because
            # token expiry calculation starts after login session
            # expiry.
            self.remove_outdated_offline_session()
            # If there is no offline login session anymore and the user
            # is not logged in check if cached tokens are expired.
            session_file = self.get_session_file()
            if not os.path.exists(session_file) \
            and not self.username in stuff.get_logged_in_users():
                login_age = int((time.time() - login_time))
                if instance.offline_expiry > 0 \
                and login_age >= instance.offline_expiry:
                    self.logger.info("Removing outdated offline tokens...")
                    self.clear()
                    break
                try:
                    last_token_usage = os.path.getmtime(self.login_token_uuid_file)
                except FileNotFoundError:
                    continue
                unused_age = int((time.time() - last_token_usage))
                if instance.offline_unused_expiry > 0 \
                and unused_age >= instance.offline_unused_expiry:
                    self.logger.info("Removing outdated (unused) offline tokens...")
                    self.clear()
                    break

            if self.need_encryption and not self.enc_key:
                continue

            # Try to get session key.
            if self.keep_session:
                try:
                    session_key = instance.object_config.get('OTPME_SESSION_KEY',
                                                            no_headers=True)
                except:
                    msg = (_("Login token misses session key."))
                    raise OTPmeException(msg)
                # Make sure session key is of type string and not e.g. long.
                session_key = str(session_key)
                # Decode session key.
                self.session_key_private = decode(session_key, "hex")

            # Try to get offline data key.
            try:
                offline_data_key = instance.object_config.get('OTPME_OFFLINE_DATA_KEY',
                                                                no_headers=True)
            except:
                msg = (_("Login token misses offline data key."))
                raise OTPmeException(msg)
            # Make sure offline data key is of type string and not e.g. long.
            offline_data_key = str(offline_data_key)
            offline_data_key = offline_data_key.encode()
            # Decode offline data key.
            self.offline_data_key = decode(offline_data_key, "hex")

    def save(self):
        """ Save offline tokens to disk. """
        # Get all offline tokens.
        offline_tokens = self.get()
        # Call token instance write method. This actually writes the token
        # config to disk.
        for token_oid in offline_tokens:
            instance = offline_tokens[token_oid]
            try:
                instance._write()
            except Exception as e:
                raise OTPmeException(_("Error writing token config: %s") % e)
            msg = ("Cached token '%s' for offline logins." % instance.rel_path)
            self.logger.info(msg)

    def save_rsp(self, session_id, realm, site, rsp, slp, session_key=None,
        login_time=None, session_timeout=None, session_unused_timeout=None,
        session_uuid=None, offline_session=None, shares=None, update=False):
        """ Save RSP to file encrypted with session public key. """
        if update and not session_key:
            msg = "Need session key on update."
            raise OTPmeException(msg)

        if update:
            try:
                cur_session_id = self.get_offline_session()[2]
            except:
                cur_session_id = None
            if cur_session_id != session_id:
                msg = ("Cannot update session: %s: Wrong session id: %s"
                        % (cur_session_id, session_id))
                raise OTPmeException(msg)

        # Set session key if we got one.
        if session_key:
            self.session_key_public = session_key

        session_config = {}
        session_file = self.get_session_file(realm, site, session_id)
        session_dir = os.path.dirname(session_file)
        # Read session from file if it exists.
        if os.path.exists(session_file):
            try:
                session_config = filetools.read_data_file(session_file)
            except Exception as e:
                msg = (_("Error reading session file: %s") % e)
                raise OTPmeException(msg)
            self.session_key_public = decode(session_config['KEY'], "hex")
            # Get RSAKey() instance for our session key.
            key = RSAKey(key=self.session_key_public)
            salt = session_config['SALT']
        else:
            # If no session file exists and update is given nothing more to do.
            if update:
                return None
            # Generate new session key if needed.
            if not self.session_key_public:
                self.gen_session_key()
            # Get RSAKey() instance for our session key.
            key = RSAKey(key=self.session_key_public)
            # Add public key to session config.
            session_config['KEY'] = encode(self.session_key_public, "hex")
            # Generate salt.
            salt = stuff.gen_secret(len=32)
            # Add salt to session config.
            session_config['SALT'] = salt

        if not self.session_key_public:
            msg = (_("No session key available."))
            raise OTPmeException(msg)

        # Make sure session dir exists.
        if not os.path.exists(session_dir):
            filetools.create_dir(path=session_dir,
                                user=self.username,
                                mode=0o700,
                                user_acls=self.dir_acls)

        # Encrypt RSP.
        encrypted_rsp = key.encrypt(cleartext=salt+rsp, cipher=self.rsp_cipher)
        # Encode RSP.
        encrypted_rsp = encode(encrypted_rsp, "hex")

        if update:
            self.logger.debug("Updating RSP in session file...")
        else:
            self.logger.debug("Saving RSP to session file...")

        # Update session data.
        session_config['UPDATE'] = time.time()
        session_config['RSP'] = encrypted_rsp
        session_config['SLP'] = slp
        session_config['REALM'] = realm
        session_config['SITE'] = site
        if login_time is not None:
            session_config['LOGIN'] = login_time
        if session_uuid is not None:
            session_config['SESSION_UUID'] = session_uuid
        if offline_session is not None:
            if offline_session:
                self.logger.info("Offline session keeping is enabled.")
            else:
                self.logger.info("Offline session keeping is disabled.")
            session_config['OFFLINE'] = offline_session
        if shares is not None:
            session_config['SHARES'] = shares
        if session_timeout is not None:
            session_config['TIMEOUT'] = session_timeout
        if session_unused_timeout is not None:
            session_config['UNUSED_TIMEOUT'] = session_unused_timeout
        # Try to write session file.
        try:
            filetools.write_data_file(session_file,
                                    session_config,
                                    full_data_update=True,
                                    user=self.username,
                                    mode=0o600,
                                    user_acls=self.file_acls)
            if update:
                self.logger.debug("Updated RSP in file: %s" % session_file)
            else:
                self.logger.debug("Saved RSP to file: %s" % session_file)
            # Create the "offline session" link.
            offline_session_link = self.get_session_file()
            if os.path.islink(offline_session_link):
                filetools.delete(offline_session_link)
            os.symlink(session_file, offline_session_link)
        except Exception as e:
            msg = (_("Error writing session file: %s") % e)
            raise OTPmeException(msg)
        return True

    def get_offline_sessions(self, object_id):
        """ Get RSPs of latest offline session via session key of login token. """
        # Remove outdated sessions.
        self.remove_outdated_offline_session()

        # Try to get login session data.
        session_realm, \
        session_site, \
        session_id = self.get_offline_session()

        if not session_id:
            raise NoOfflineSessionFound("Found no offline session.")

        # Try to get login token.
        token = self.get(object_id)
        if not token:
            return

        # Without session key to decrypt RSPs we cannot continue.
        if not self.session_key_private:
            return

        # Load session key.
        try:
            key = RSAKey(key=self.session_key_private)
        except Exception as e:
            msg = (_("Failed to load offline session key: %s") % e)
            raise OTPmeException(msg)

        # Get session file.
        session_dir = self.get_session_dir(session_id)

        # Get all server sessions.
        server_sessions = {}
        for x in os.listdir(session_dir):
            # Get session config.
            session_file = os.path.join(session_dir, x)
            session_config = filetools.read_data_file(session_file)
            # Get session data.
            slp = session_config['SLP']
            realm = session_config['REALM']
            site = session_config['SITE']
            login_time = session_config['LOGIN']
            shares = session_config['SHARES']
            session_timeout = session_config['TIMEOUT']
            session_unused_timeout = session_config['UNUSED_TIMEOUT']
            session_key = decode(session_config['KEY'], "hex")
            encrypted_rsp = decode(session_config['RSP'], "hex")
            salt = session_config['SALT']
            salt_rsp = key.decrypt(ciphertext=encrypted_rsp, cipher=self.rsp_cipher)
            salt_rsp = salt_rsp.decode()
            # Remove salt from RSP.
            rsp = salt_rsp.replace(salt, "")
            offline_allowed = session_config['OFFLINE']
            # Sign RSP to be verified by otpme-agent.
            rsp_signature = key.sign(rsp, encoding="hex")

            if realm not in server_sessions:
                server_sessions[realm] = {}
            if site not in server_sessions[realm]:
                server_sessions[realm][site] = {}
            # Add session.
            server_sessions[realm][site]['rsp'] = rsp
            server_sessions[realm][site]['slp'] = slp
            server_sessions[realm][site]['rsp_signature'] = rsp_signature
            server_sessions[realm][site]['session_key'] = session_key
            server_sessions[realm][site]['login_time'] = login_time
            server_sessions[realm][site]['shares'] = shares
            server_sessions[realm][site]['offline_allowed'] = offline_allowed
            server_sessions[realm][site]['session_timeout'] = session_timeout
            server_sessions[realm][site]['session_unused_timeout'] = session_unused_timeout

        return server_sessions

    def get_slp(self, realm, site, session_id):
        """ Get SLP from session file. """
        session_file = self.get_session_file(realm, site, session_id)
        if not os.path.exists(session_file):
            return
        try:
            session_config = filetools.read_data_file(session_file)
        except Exception as e:
            msg = (_("Error reading login session file: %s") % e)
            raise OTPmeException(msg)
        try:
            slp = session_config['SLP']
        except:
            msg = (_("SLP missing in login session file."))
            raise OTPmeException(msg)
        return slp

    def remove_session(self, session_id=None, force=False):
        """ Remove login session. """
        if not session_id:
            session_realm, \
            session_site, \
            session_id = self.get_offline_session()
            if not session_id:
                msg = (_("No session found."))
                raise OTPmeException(msg)

        session_dir = self.get_session_dir(session_id)
        if not os.path.exists(session_dir):
            return

        remove_session = False
        server_sessions = os.listdir(session_dir)
        if len(server_sessions) == 0:
            remove_session = True

        if force:
            remove_session = True

        if not remove_session:
            return

        self.logger.debug("Removing login session: %s" % session_id)
        try:
            shutil.rmtree(session_dir)
        except Exception as e:
            msg = (_("Error removing offline session: %s") % e)
            self.logger.critical(msg)
            raise OTPmeException(msg)

    def remove_outdated_session_dirs(self):
        """ Remove outdated session directories. """
        if not os.path.exists(self.env_dir):
            return
        sessions = os.listdir(self.env_dir)
        for i in sessions:
            login_pid = i.split(":")[0]
            session_dir = "%s/%s" % (self.env_dir, i)
            if stuff.check_pid(login_pid):
                continue
            if not os.path.exists(session_dir):
                continue
            if not os.path.isdir(session_dir):
                continue
            agent_vars = None
            agent_vars_file = "%s/%s/%s" % (self.env_dir, i,
                                        config.agent_vars_filename)
            if os.path.exists(agent_vars_file):
                try:
                    fd = open(agent_vars_file, "r")
                    agent_vars = fd.read()
                    fd.close()
                except Exception as e:
                    self.logger.warning("Unable to read SSH agent PID from file: %s"
                                    % e)
            if agent_vars:
                # Try to get agent variables from file.
                ssh_agent_name, \
                ssh_agent_pid, \
                ssh_auth_sock, \
                gpg_agent_info = stuff.get_agent_vars(agent_vars)
                if ssh_agent_pid and ssh_agent_name:
                    pids = stuff.get_pid(user=self.username, name=ssh_agent_name)
                    for pid in pids:
                        if str(pid) == str(ssh_agent_pid):
                            self.logger.debug("Killing orphan SSH agent: %s (%s)"
                                        % (ssh_agent_name, ssh_agent_pid))
                            stuff.kill_pid(ssh_agent_pid, timeout=5)
                            break
            self.logger.debug("Removing outdated session dir: %s" % session_dir)
            try:
                shutil.rmtree(session_dir)
            except Exception as e:
                msg = (_("Error removing session directory: %s") % e)
                raise OTPmeException(msg)

    def remove_outdated_offline_session(self):
        """ Remove outdated offline session. """
        session_realm, \
        session_site, \
        session_id = self.get_offline_session()
        if not session_id:
            return
        session_file = self.get_session_file(realm=session_realm,
                                            site=session_site,
                                            session_id=session_id)
        if not os.path.exists(session_file):
            return

        session_dir = os.path.dirname(session_file)
        server_sessions = os.listdir(session_dir)

        # Check if there is any valid server session.
        for x in list(server_sessions):
            session_file = "%s/%s" % (session_dir, x)
            session_config = filetools.read_data_file(session_file)
            login_time = session_config['LOGIN']
            update_time = session_config['UPDATE']
            session_timeout = session_config['TIMEOUT']
            session_unused_timeout = session_config['UNUSED_TIMEOUT']
            session_age = time.time() - login_time
            unused_age = time.time() - update_time
            # Remove session outdated by timeout.
            if session_age > session_timeout * 60:
                self.logger.debug("Removing outdated session: %s" % session_file)
                filetools.delete(session_file)
            elif unused_age > session_unused_timeout * 60:
                self.logger.debug("Removing outdated (unused) session: %s"
                            % session_file)
                filetools.delete(session_file)
        # Remove login session if no more server session exists.
        self.remove_session(session_id)

    def update_offline_session(self, session_id):
        """ Update offline session to new session ID. """
        old_session_realm, \
        old_session_site, \
        old_session_id = self.get_offline_session()
        if not old_session_id:
            raise NoOfflineSessionFound("No offline session exists.")
        old_session_file = self.get_session_file(realm=old_session_realm,
                                                site=old_session_site,
                                                session_id=old_session_id)
        old_session_dir = os.path.dirname(old_session_file)
        new_session_file = self.get_session_file(realm=old_session_realm,
                                                site=old_session_site,
                                                session_id=session_id)
        new_session_dir = os.path.dirname(new_session_file)
        old_login_pid = old_session_id.split(":")[0]
        # If the login PID of the offline session is still running we must create
        # a copy of the session directory.
        if stuff.check_pid(old_login_pid):
            shutil.copytree(old_session_dir, new_session_dir)
        else:
            os.rename(old_session_dir, new_session_dir)
        offline_session_link = self.get_session_file()
        if os.path.islink(offline_session_link):
            filetools.delete(offline_session_link)
        os.symlink(new_session_file, offline_session_link)

    def save_script(self, script_id, script_uuid, script, script_path,
        script_options=None, script_signs=None):
        """ Save script to file. """
        if not script:
            msg = "No %s script given" % script_id
            raise OTPmeException(msg)

        if not script_uuid:
            msg = "No %s script UUID given" % script_id
            raise OTPmeException(msg)

        if not script_path:
            msg = "No %s script path given" % script_id
            raise OTPmeException(msg)

        if not os.path.exists(self.script_dir):
            filetools.create_dir(path=self.script_dir,
                                user=self.username,
                                mode=0o700,
                                user_acls=self.dir_acls)
        # Set empty string if not given.
        if script_options is None:
            script_options = []
        if script_signs is None:
            script_signs = ""
        else:
            # Encode signatures dict.
            script_signs = json.encode(script_signs, encoding="base64")
        object_config = {
                'SCRIPT'            : encode(script, "base64"),
                'SCRIPT_UUID'       : script_uuid,
                'SCRIPT_PATH'       : script_path,
                'SCRIPT_OPTIONS'    : ",".join(script_options),
                'SCRIPT_SIGNATURES' : script_signs,
                }
        # Try to write script to file.
        script_file = self.get_script_file_path(script_id)
        try:
            filetools.write_data_file(script_file,
                                    object_config,
                                    full_data_update=True,
                                    user=self.username,
                                    mode=0o600,
                                    user_acls=self.file_acls)
            self.logger.debug("Saved script to file: %s" % script_file)
        except Exception as e:
            msg = (_("Error writing script file: %s") % e)
            raise OTPmeException(msg)

    def get_script(self, script_id):
        """ Read script from file. """
        # Try to read script file.
        script_file = self.get_script_file_path(script_id)
        if not os.path.exists(script_file):
            msg = (_("Script not cached."))
            raise OTPmeException(msg)
        try:
            object_config = filetools.read_data_file(script_file)
        except Exception as e:
            msg = (_("Error reading script file: %s") % e)
            raise OTPmeException(msg)
        script = decode(object_config['SCRIPT'], "base64")
        script_uuid = object_config['SCRIPT_UUID']
        script_path = object_config['SCRIPT_PATH']
        script_options = object_config['SCRIPT_OPTIONS']
        if len(script_options) > 0:
            script_options = script_options.split(",")
        else:
            script_options = []
        script_signs = object_config['SCRIPT_SIGNATURES']
        if script_signs.startswith("JSON{"):
            script_signs = json.decode(script_signs, encoding="base64")
        else:
            script_signs = None
        return script_path, script_options, script_uuid, script_signs, script

    def get_config_paths(self, object_id):
        """ Get path to object config dirs/files. """
        if not self.username:
            msg = (_("Missing username."))
            raise OTPmeException(msg)
        if not self.user_uuid:
            msg = (_("Missing user UUID."))
            raise OTPmeException(msg)
        object_type = object_id.object_type
        config_paths = {}
        config_paths['config_file'] = False

        if object_type == "token":
            config_dir = self.token_cache_dir
            config_file = "%s/%s" % (config_dir, object_id.replace("/", ":"))
            config_paths['config_file'] = config_file
            config_paths['config_dir'] = config_dir
            if os.path.exists(config_file):
                try:
                    token_uuid = filetools.read_data_file(config_file, ['UUID'])['UUID']
                except Exception as e:
                    msg = (_("Error reading token UUID: %s") % e)
                    self.logger.critical(msg)
                    raise OTPmeException(msg)
                used_otp_dir = "%s/%s/otp/%s" % (self.used_dir,
                                                self.user_uuid,
                                                token_uuid)
                token_counter_dir = "%s/%s/counter/%s" % (self.used_dir,
                                                        self.user_uuid,
                                                        token_uuid)
                config_paths['used_otp_dir'] = used_otp_dir
                config_paths['token_counter_dir'] = token_counter_dir

        elif object_type == "used_otp":
            token_uuid = object_id.token_uuid
            otp_hash = object_id.object_hash
            config_dir = "%s/%s/otp/%s/%s" % (self.used_dir,
                                            self.user_uuid,
                                            token_uuid, otp_hash)
            config_file = "%s/%s" % (config_dir, config.object_config_file_name)
            config_paths['config_file'] = config_file
            config_paths['config_dir'] = config_dir
            config_paths['remove_on_delete'] = [config_file]
            config_paths['rmdir_on_delete'] = [config_dir]

        elif object_type == "token_counter":
            token_uuid = object_id.token_uuid
            counter_hash = object_id.object_hash

            config_dir = "%s/%s/counter/%s/%s" % (self.used_dir,
                                                self.user_uuid,
                                                token_uuid,
                                                counter_hash)
            config_file = "%s/%s" % (config_dir, config.object_config_file_name)
            config_paths['config_file'] = config_file
            config_paths['config_dir'] = config_dir
            config_paths['remove_on_delete'] = [config_file]
            config_paths['rmdir_on_delete'] = [config_dir]

        return config_paths

    def read_config(self, object_id, decrypt=True, **kwargs):
        """ Read encrypted object config (e.g. login token) from cache file. """
        object_type = object_id.object_type
        object_config = None

        # Get config file path.
        config_file = self.get_config_paths(object_id)['config_file']
        if os.path.exists(config_file):
            try:
                object_config = filetools.read_data_file(config_file)
            except Exception as e:
                object_config = None

        if object_type == "token":
            # Fallback to offline token dict if we got no object config from file.
            if not object_config:
                try:
                    object_config = self.offline_tokens[object_id]['object_config']
                except:
                    pass

        if not object_config:
            return None

        # Decrypt object config.
        decrypt_key = None
        if decrypt:
            if object_type == "token" and self.enc_passphrase and self.enc_salt:
                # Derive encryption key if needed.
                if not self.enc_key:
                    result = self.derive_key()
                    self.enc_key = result['key']
                decrypt_key = self.enc_key
            if object_type == "used_otp" or object_type == "token_counter":
                decrypt_key = self.offline_data_key
                if not decrypt_key:
                    msg = (_("Decryption of %s failed: Decryption key missing")
                            % object_type)
                    raise OTPmeException(msg)
        # Decrypt object config.
        if decrypt_key:
            try:
                # Decrypt object config.
                object_config = ObjectConfig(object_id, object_config)
                object_config = object_config.decrypt(decrypt_key)
            except Exception as e:
                msg = "Failed to decrypt offline token."
                raise OTPmeException(msg)
        else:
            msg = ("Loading offline %s without decrypting: %s"
                    % (object_type, object_id))
            self.logger.debug(msg)
            try:
                object_config = ObjectConfig(object_id, object_config, encrypted=False)
                object_config = object_config.remove_headers()
            except Exception as e:
                msg = "Failed to load offline token: %s" % e
                raise OTPmeException(msg)

        return object_config

    def write_config(self, instance=None, object_id=None,
        object_config=None, encrypt=True, **kwargs):
        """ Write encrypted object config (e.g. login token) to cache file. """
        # Get config from instance.
        if instance is not None:
            object_id = instance.oid
            object_config = instance.object_config

        # Get config file path.
        config_dir = self.get_config_paths(object_id)['config_dir']
        config_file = self.get_config_paths(object_id)['config_file']

        if not os.path.exists(config_dir):
            filetools.create_dir(path=config_dir,
                                user=self.username,
                                mode=0o700,
                                user_acls=self.dir_acls)
        # Get object type.
        object_type = object_id.object_type

        if object_type == "token":
            if self.need_encryption:
                # Derive encryption key if needed.
                if not self.enc_key:
                    result = self.derive_key()
                    self.enc_key = result['key']
                    self.enc_salt = result['salt']
                if not self.enc_key:
                    msg = (_("Encryption of offline token required "
                        "but got no key to encrypt!"))
                    raise OTPmeException(msg)
                # Set encryption stuff AFTER running self.derive_key()!
                offline_enc_parameters = json.encode(self.offline_enc_parameters,
                                                    encoding="base64")
                object_config['OTPME_OFFLINE_ENC_PARAMETERS'] = offline_enc_parameters

        # Add offline token data key.
        if self.offline_data_key and object_type == "token":
            token_uuid = object_config['UUID']
            if token_uuid == self.login_token_uuid:
                encryption = None
                offline_data_key = encode(self.offline_data_key, "hex")
                if self.need_encryption:
                    encryption = self.enc_type
                else:
                    msg = ("Saving offline data key to unencrypted "
                            "offline token!!")
                    self.logger.warning(msg)
                object_config.add(key='OTPME_OFFLINE_DATA_KEY',
                                    value=offline_data_key,
                                    encryption=encryption)

        # Add session key to login token config if enabled.
        if self.session_key_private and self.keep_session and object_type == "token":
            token_uuid = object_config['UUID']
            if token_uuid == self.login_token_uuid:
                # Make sure session key is a one line string.
                encryption = None
                session_key = encode(self.session_key_private, "hex")
                if self.need_encryption:
                    encryption = self.enc_type
                else:
                    msg = ("Saving session key to unencrypted offline token!!")
                    self.logger.warning(msg)
                object_config.add(key='OTPME_SESSION_KEY',
                                value=session_key,
                                encryption=encryption)

        encrypt_key = None
        need_encryption = False
        if object_type == "token" and self.need_encryption:
            encrypt_key = self.enc_key
            need_encryption = True
        if object_type == "used_otp" or object_type == "token_counter":
            encrypt_key = self.offline_data_key
            need_encryption = True

        # Encrypt object config
        fake_encryption = True
        if need_encryption and encrypt:
            if not encrypt_key:
                msg = (_("Encryption of %s failed: Encryption key missing")
                        % object_type)
                raise OTPmeException(msg)
            fake_encryption = False

        # Encrypt object config.
        object_config = ObjectConfig(object_id=object_id,
                                    object_config=object_config,
                                    encrypted=False)
        object_config = object_config.encrypt(encrypt_key, fake=fake_encryption)

        # Write config file.
        try:
            filetools.write_data_file(config_file,
                                    object_config,
                                    full_data_update=True,
                                    user=self.username,
                                    mode=0o600,
                                    user_acls=self.file_acls)
        except Exception as e:
            config.raise_exception()
            msg = (_("Error writing cache file for: %s: %s")
                    % (object_id, e))
            raise OTPmeException(msg)

        return True

    def delete_object(self, object_id):
        """ Delete object from users cache directory. """
        status_message = ""
        exit_status = True

        config_paths = self.get_config_paths(object_id)
        try:
            remove_files = config_paths['remove_on_delete']
        except:
            remove_files = []

        try:
            remove_dirs = config_paths['rmdir_on_delete']
        except:
            remove_dirs = []

        try:
            rmtree_dirs = config_paths['rmtree_on_delete']
        except:
            rmtree_dirs = []

        for i in remove_files:
            if os.path.exists(i):
                try:
                    filetools.delete(i)
                except Exception as e:
                    status_message = (_("Error removing file '%s': %s") % (i, e))
                    exit_status = False

        for i in remove_dirs:
            if os.path.exists(i):
                try:
                    os.rmdir(i)
                except Exception as e:
                    status_message = (_("Error removing directory '%s': %s") % (i, e))
                    exit_status = False

        for i in rmtree_dirs:
            if os.path.exists(i):
                try:
                    shutil.rmtree(i)
                except Exception as e:
                    status_message = (_("Error removing directory '%s': %s") % (i, e))
                    exit_status = False

        if not exit_status:
            raise OTPmeException(status_message)

        return True

    def _get_used_otps(self, object_id):
        """ Get list of used OTPs for given token OID. """
        used_otps_list = []
        used_otps_dir = self.get_config_paths(object_id)['used_otp_dir']
        if os.path.exists(used_otps_dir):
            for otp_hash in os.listdir(used_otps_dir):
                used_otp_file = os.path.join(used_otps_dir, otp_hash, "object.json")
                if not os.path.exists(used_otp_file):
                    continue
                try:
                    object_config = filetools.read_data_file(used_otp_file)
                except Exception as e:
                    msg = (_("Error reading token counter file: %s") % e)
                    raise OTPmeException(msg)
                token_uuid = object_config['TOKEN_UUID']
                used_otp_oid = oid.get(object_type="used_otp",
                                        realm=object_id.realm,
                                        site=object_id.site,
                                        token_uuid=token_uuid,
                                        object_hash=otp_hash)
                used_otps_list.append((used_otp_oid, object_config))
        return used_otps_list

    def get_used_otps(self, object_id):
        """ Get list of used OTPs for given token OID. """
        used_otps_list = []
        for used_otp_oid, object_config in self._get_used_otps(object_id):
            used_otp = UsedOTP(object_id=used_otp_oid,
                                no_transaction=True)
            # Make sure token is in offline mode to get read/write methods
            # replaced by their offline versions.
            used_otp.offline = True
            self.set_replacement_methods(used_otp.oid)
            used_otp._load()
            used_otps_list.append(used_otp)
        return used_otps_list

    def _get_token_counter(self, object_id):
        """ Get list of token counters for given token OID. """
        counter_list = []
        try:
            counter_dir = self.get_config_paths(object_id)['token_counter_dir']
        except:
            return counter_list
        if not os.path.exists(counter_dir):
            return counter_list
        for counter_hash in os.listdir(counter_dir):
            counter_file = os.path.join(counter_dir, counter_hash, "object.json")
            if not os.path.exists(counter_file):
                continue
            try:
                object_config = filetools.read_data_file(counter_file)
            except Exception as e:
                msg = (_("Error reading token counter file: %s") % e)
                raise OTPmeException(msg)
            token_uuid = object_config['TOKEN_UUID']
            counter_oid = oid.get(object_type="token_counter",
                                    realm=object_id.realm,
                                    site=object_id.site,
                                    token_uuid=token_uuid,
                                    object_hash=counter_hash)
            counter_list.append((counter_oid, object_config))
        return counter_list

    def get_token_counter(self, object_id):
        """ Get list of token counters for given token OID. """
        counter_list = []
        for counter_oid, object_config in self._get_token_counter(object_id):
            token_counter = TokenCounter(object_id=counter_oid,
                                        no_transaction=True)
            # Make sure token is in offline mode to get read/write methods
            # replaced by their offline versions.
            token_counter.offline = True
            self.set_replacement_methods(token_counter.oid)
            token_counter._load()
            counter_list.append(token_counter)
        return counter_list

    def clear(self):
        """ Remove cached offline tokens and login session file. """
        if not os.path.exists(self.offline_dir):
            return
        # Remove offline tokens dir.
        try:
            shutil.rmtree(self.offline_dir)
        except Exception as e:
            msg = (_("Error removing offline token directory: %s") % e)
            self.logger.critical(msg)
            raise OTPmeException(msg)
