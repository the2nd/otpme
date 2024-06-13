# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from datetime import datetime
from datetime import timedelta

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import cli
from otpme.lib import srp
from otpme.lib import oid
from otpme.lib import json
from otpme.lib import sotp
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib import encryption
from otpme.lib import otpme_pass
from otpme.lib import mschap_util
from otpme.lib.locking import object_lock
from otpme.lib.protocols.utils import register_commands
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.classes.otpme_object import OTPmeLockObject

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

SESSIONS_DIR = "%s/sessions" % config.data_dir

commands = {
    'list'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.list_sessions,
                    'oargs'             : [
                                        'show_all',
                                        ],
                    'job_type'          : None,
                    },
                'exists'    : {
                    'method'            : cli.list_sessions,
                    'oargs'             : [
                                        'show_all',
                                        ],
                    'job_type'          : None,
                    },
                },
            },
    'show'   : {
            'OTPme-mgmt-1.0'    : {
                'missing'    : {
                    'method'            : cli.show_sessions,
                    'oargs'             : [
                                        'max_len',
                                        'show_all',
                                        'output_fields',
                                        'search_regex',
                                        'reverse_sort',
                                        'header',
                                        'csv',
                                        'csv_sep',
                                        'sort_by'
                                        ],
                    'job_type'          : 'thread',
                    },
                'exists'    : {
                    'method'            : 'show',
                    'job_type'          : 'thread',
                    },
                },
            },
    'del'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'delete',
                    'oargs'             : ['recursive', 'force'],
                    'job_type'          : 'process',
                    },
                },
            },
    }

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.token"]

def register():
    register_oid()
    #register_config()
    register_backend()
    register_sync_settings()
    register_commands("session", commands)

#def register_config():
#    """ Register config stuff. """
#    #config.register_config_var("rsp_len", int, 65)

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'name' ]
    read_oid_schema = [ 'realm', 'site', 'name' ]
    session_oid_re = 'session|([a-fA-F\d]{32})'
    oid.register_oid_schema(object_type="session",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=session_oid_re)
    rel_path_getter = lambda x: x[2:]
    oid.register_rel_path_getter(object_type="session",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_cluster_sync(object_type="session")

def register_backend():
    """ Register object for the file backend. """
    backend.register_data_dir(name="session",
                            path=SESSIONS_DIR,
                            drop=True,
                            perms=0o770)
    def path_getter(object_id):
        session_name = object_id.name
        config_file_name = "%s.sqlite" % session_name
        config_file = os.path.join(SESSIONS_DIR, config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['remove_on_delete'] = [config_file]
        return config_paths
    # Register object to config.
    config.register_object_type(object_type="session",
                            tree_object=False,
                            uniq_name=False,
                            object_cache=1024,
                            cache_region="session",
                            backup_attributes=['realm', 'site', 'name'])
    # Register index attributes.
    config.register_index_attribute('client')
    config.register_index_attribute('session_id')
    config.register_index_attribute('session_type')
    config.register_index_attribute('creation_time')
    def oid_getter(session_file):
        session_name = ".".join(session_file.split(".")[:-1])
        session_oid = oid.OTPmeOid(object_type="session",
                                    realm=config.realm,
                                    site=config.site,
                                    name=session_name)
        return session_oid
    def index_rebuild():
        counter = 0
        session_files = filetools.list_dir(SESSIONS_DIR)
        files_count = len(session_files)
        for session_file in session_files:
            counter += 1
            x_path = os.path.join(SESSIONS_DIR, session_file)
            msg = ("Processing session (%s/%s): %s"
                % (counter, files_count, x_path))
            logger.debug(msg)
            x_oid = oid_getter(session_file)
            backend.index_add(object_id=x_oid,
                            object_config="auto",
                            full_index_update=True)
    # Register object to backend.
    session_dir_extension = "session"
    class_getter = lambda: Session
    backend.register_object_type(object_type="session",
                                tree_object=False,
                                dir_name_extension=session_dir_extension,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter)

class Session(OTPmeLockObject):
    """ OTPme session object. """
    def __init__(self, session_type=None, username=None, access_group=None,
        object_id=None, object_config=None, uuid=None, cache=False,
        pass_hash=None, pass_hash_params=None, session_id=None, token=None,
        client=None, client_ip=None, slp=None):
        """ Init. """
        super(Session, self).__init__()
        self.realm = config.realm
        self.site = config.site
        #if pass_hash is not None:
        #    if pass_hash_params is None:
        #        msg = "Need <pass_hash_params>."
        #        raise OTPmeException(msg)
        # Set password hash.
        self.pass_hash = pass_hash
        self.pass_hash_params = pass_hash_params
        self.slp = slp
        # Stuff for session renegotiation.
        self.reneg_started = False
        self.last_reneg = False
        self.reneg_hash = None
        # Some default values.
        self.last_login = None
        self.login_count = 0
        self.child_sessions = []
        self.offline_data_key = None
        self._modified = False
        self.pickable = True
        self.origin = None
        self.last_modified = None
        # Be compatible with OTPmeLockObject.
        self.offline = False
        self.no_transaction = False
        # How long to cache a session e.g. in redis.
        self.cache_expire = 300
        self._lock = None

        # Set our object type.
        self.type = "session"

        # Old checksum.
        self.old_checksum = None

        if object_id:
            self.oid = object_id

        self.kwargs_object_config = None
        if object_config:
            self.kwargs_object_config = object_config
            # Load object.
            self._load()
            self._load_object()
            # Build search index.
            self.build_index()
            return

        # Set session type.
        self.session_type = session_type
        # Set session username.
        self.username = username
        # Set token that was used to authenticate the user.
        self.auth_token = token
        # Indicates if this is a cache session to speedup static password
        # requests.
        self.cache = cache
        # Set access group for this session.
        self.access_group = access_group

        # Set session ID.
        if session_id:
            self.session_id = session_id
        else:
            self.session_id = self.gen_session_id()

        # Set client.
        if client:
            self.client = client
        else:
            self.client = ""

        # Set client_ip.
        if client_ip:
            self.client_ip = client_ip
        else:
            self.client_ip = ""

        # Try to resolve user UUID.
        result = backend.search(object_type="user",
                                attribute="name",
                                value=username,
                                return_type="uuid")
        if not result:
            msg = "Unknown user: %s" % username
            raise OTPmeException(msg)
        self.user_uuid = result[0]

        # Try to resolve accessgroup UUID.
        result = backend.search(object_type="accessgroup",
                                attribute="name",
                                value=access_group,
                                realm=config.realm,
                                site=config.site,
                                return_type="uuid")
        if not result:
            msg = "Unknown accessgroup: %s" % access_group
            raise OTPmeException(msg)
        self.access_group_uuid = result[0]

        # Generate session UUID.
        if uuid is None:
            uuid = stuff.gen_uuid()

        # Set session UUID. This UUID is used to uniquely identify a
        # session (e.g. on client side) because the session ID may
        # change on renegotiation.
        self.uuid = uuid

        # Node the session was created on.
        self.origin = config.uuid

        # Set session name.
        self.name = self.get_session_name()

        # Set our OID.
        self.set_oid()

        # Build search index.
        self.build_index()

    @property
    def checksum(self):
        """ Get object checksum from backend. """
        checksum = self.object_config.checksum
        return checksum

    @property
    def sync_checksum(self):
        """ Get object sync_checksum from backend. """
        sync_checksum = self.object_config.sync_checksum
        return sync_checksum

    @property
    def last_used(self):
        """ Get last used timestamp. """
        last_used_timestamp = backend.get_last_used(self.realm,
                                                    self.site,
                                                    self.type,
                                                    self.uuid)
        return last_used_timestamp

    @last_used.setter
    def last_used(self, timestamp):
        """ Set last used timestamp. """
        backend.set_last_used(self.realm,
                            self.site,
                            self.type,
                            self.uuid, timestamp)

    @property
    def cache_expire_time(self):
        return self.cache_expire

    def build_index(self):
        # Add index.
        self.index = []
        self.add_index("session_id", self.session_id)
        self.add_index("user_uuid", self.user_uuid)
        self.add_index("token_uuid", self.auth_token)
        self.add_index("session_type", self.session_type)
        self.add_index("accessgroup", self.access_group_uuid)
        self.add_index("client", self.client)
        self.add_index('origin', self.origin)

    def set_oid(self):
        """ Set session OID. """
        self.oid = oid.OTPmeOid(object_type=self.type,
                                realm=self.realm,
                                site=self.site,
                                name=self.name)

    def add_index(self, key, value):
        """ Add attribute to session index. """
        if [key, value] in self.index:
            return
        self.index.append([key, value])

    def del_index(self, key, value=None):
        """ Remove attribute from object index. """
        if value is not None:
            try:
                self.index.remove([key, value])
            except:
                pass
            return
        for x in list(self.index):
            x_key = x[0]
            if x_key != key:
                continue
            self.index.remove(x)

    def gen_session_id(self):
        """ Gen session ID. """
        # Get salt from user.
        result = backend.search(object_type="user",
                                attribute="name",
                                value=self.username,
                                return_type="instance",
                                realm=self.realm)
        if not result:
            msg = (_("Unknown user: %s") % self.username)
            raise OTPmeException(msg)

        user = result[0]
        salt = user.used_pass_salt
        if not salt:
            msg = (_("Unable to generate session ID: User is missing "
                            "used_pass_salt parameter"))
            raise OTPmeException(msg)
        # Generate session ID.
        hash_value = "%s:%s" % (self.access_group, self.pass_hash)
        session_id = encryption.derive_key(hash_value,
                                            hash_type="HKDF",
                                            hash_algo="SHA256",
                                            salt=salt,
                                            key_len=16)['key']
        return session_id

    def get_session_name(self):
        """ Gen session name. """
        session_name = "%s:%s:%s:%s:%s" % (self.username,
                                        self.access_group,
                                        self.session_type,
                                        self.uuid,
                                        self.session_id)
        return session_name

    def export_config(self, callback=default_callback, **kwargs):
        """ Export session config. """
        if not self.exists():
            msg = (_("Object '%s' does not exist.") % self.oid)
            return callback.error(msg)
        # FIXME: read object config from backend on export and optionally encrypt config!! (see OTPmeObject().export_config())
        object_config = json.dumps(self.object_config, indent=4, sort_keys=True)
        return callback.ok(object_config)

    def outdate(self):
        """ Delete expired session. """
        # FIXME: IS THIS STILL THE CASE?
        # FIXME: how and when to run a function or method to remove expired sessions from backend?
        #       there may be orphan session (those who have expired without beeing reused after expiry)
        # If session is expired remove it.
        now = time.time()
        expire_time = self.expire_time()
        if now > expire_time:
            msg = ("Session '%s' is expired by session timeout. "
                    "Removing..." % self.name)
            logger.debug(msg)
            self.delete(force=True, recursive=True, verify_acls=False)
            return False
        # If session is expired remove it and all childs that exist.
        unused_expire_time = self.unused_expire_time()
        if now > unused_expire_time:
            msg = ("Session '%s' is expired by unused session timeout. "
                    "Removing..." % self.name)
            logger.debug(msg)
            self.delete(force=True, recursive=True, verify_acls=False)
            return False
        return True

    def _load_object(self):
        """ Do anything to load the object from the object config. """
        # Set instance variables
        self.set_variables()

    def exists(self, outdate=False, **kwargs):
        """ Check if session exists. """
        # Without config we do not exist :)
        if not self._load():
            return False
        # Load object.
        self._load_object()
        if outdate:
            return self.outdate()
        return True

    def _load(self, read_from_cache=True):
        """ Read session config from backend. """
        # Check if we got the object config via kwargs.
        object_config = None
        if self.kwargs_object_config:
            object_config = ObjectConfig(object_id=self.oid,
                                object_config=self.kwargs_object_config,
                                encrypted=False)
            self.kwargs_object_config = None

        # Try to get object config from backend.
        if not object_config:
            object_config = backend.read_config(object_id=self.oid,
                                    read_from_cache=read_from_cache)
        if not object_config:
            return False

        # Set old checksum. Used in backend to decide
        # if a full data update is required.
        if not self.old_checksum:
            try:
                self.old_checksum = object_config['CHECKSUM']
            except KeyError:
                pass

        self.object_config = object_config

        return True

    def get_config_parameter(self, parameter):
        """ Try to get config parameter from object_config. """
        try:
            val = self.object_config.get(parameter, no_headers=True)
        except KeyError:
            val = None
        return val

    def get_sync_config(self, **kwargs):
        """ Get sync object config .  """
        # Get a copy of our object config.
        sync_config = self.object_config.copy()
        return sync_config

    @object_lock()
    def write_config(self):
        """ Write session config to backend. """
        # Set object config.
        self.object_config = ObjectConfig(self.oid)

        self.last_modified = time.time()

        # Make sure password hashes etc. get encrypted.
        self.object_config.add(key='PASS_HASH', value=self.pass_hash,
                                    encryption=config.disk_encryption)
        self.object_config.add(key='SLP', value=self.slp,
                                    encryption=config.disk_encryption)
        if self.offline_data_key:
            self.object_config.add(key='OFFLINE_DATA_KEY',
                                    value=self.offline_data_key,
                                    encryption=config.disk_encryption)
        self.object_config['PASS_HASH_PARAMS'] = self.pass_hash_params
        self.object_config['REALM'] = self.realm
        self.object_config['SITE'] = self.site
        self.object_config['NAME'] = self.name
        self.object_config['UUID'] = self.uuid
        self.object_config['CREATION_TIME'] = self.creation_time
        self.object_config['CHILD_SESSIONS'] = ",".join(self.child_sessions)
        self.object_config['SESSION_TYPE'] = self.session_type
        self.object_config['USER_UUID'] = self.user_uuid
        self.object_config['ACCESS_GROUP_UUID'] = self.access_group_uuid
        self.object_config['CLIENT'] = self.client
        self.object_config['CLIENT_IP'] = self.client_ip
        self.object_config['AUTH_TOKEN'] = self.auth_token
        self.object_config['LAST_LOGIN'] = self.last_login
        self.object_config['LOGIN_COUNT'] = self.login_count
        self.object_config['SESSION_TIMEOUT'] = self.timeout
        self.object_config['UNUSED_SESSION_TIMEOUT'] = self.unused_timeout
        self.object_config['SESSION_ID'] = self.session_id
        self.object_config['INDEX'] = self.index
        self.object_config['ORIGIN'] = self.origin
        self.object_config['LAST_MODIFIED'] = self.last_modified
        self.object_config['CHECKSUM'] = self.checksum
        self.object_config['SYNC_CHECKSUM'] = self.sync_checksum

        # Update reneg stuff.
        self.object_config['RENEG_STARTED'] = self.reneg_started
        self.object_config['RENEG_HASH'] = self.reneg_hash
        self.object_config['LAST_RENEG'] = self.last_reneg
        self.object_config['OLD_CHECKSUM'] = self.old_checksum

        # Write session config.
        try:
            backend.write_config(object_id=self.oid,
                                instance=self,
                                cluster=True,
                                full_index_update=True)
        except Exception as e:
            msg = "Failed to write session: %s: %s" % (self.oid, e)
            logger.warning(msg)
            config.raise_exception()
            return False

        return True

    def set_variables(self):
        """ Set instance variables. """
        # Get session name.
        self.name = self.get_config_parameter('NAME')

        self.uuid = self.get_config_parameter('UUID')
        self.session_id = self.get_config_parameter('SESSION_ID')
        self.offline_data_key = self.get_config_parameter('OFFLINE_DATA_KEY')

        # Get child sessions from config.
        if self.get_config_parameter('CHILD_SESSIONS') != "":
            self.child_sessions = self.get_config_parameter('CHILD_SESSIONS').split(',')

        self.realm = self.get_config_parameter('REALM')
        self.site = self.get_config_parameter('SITE')
        self.creation_time = self.get_config_parameter('CREATION_TIME')
        self.user_uuid = self.get_config_parameter('USER_UUID')
        self.pass_hash = self.get_config_parameter('PASS_HASH')
        self.slp = self.get_config_parameter('SLP')
        self.pass_hash_params = self.get_config_parameter('PASS_HASH_PARAMS')
        self.session_type = self.get_config_parameter('SESSION_TYPE')
        self.access_group_uuid = self.get_config_parameter('ACCESS_GROUP_UUID')
        self.client = self.get_config_parameter('CLIENT')
        self.client_ip = self.get_config_parameter('CLIENT_IP')
        self.auth_token = self.get_config_parameter('AUTH_TOKEN')
        self.last_login = self.get_config_parameter('LAST_LOGIN')
        self.login_count = self.get_config_parameter('LOGIN_COUNT')
        self.timeout = self.get_config_parameter('SESSION_TIMEOUT')
        self.unused_timeout = self.get_config_parameter('UNUSED_SESSION_TIMEOUT')
        self.origin = self.get_config_parameter('ORIGIN')
        self.last_modified = self.get_config_parameter('LAST_MODIFIED')

        user_oid = backend.get_oid(self.user_uuid,
                                object_type="user",
                                instance=True)
        if user_oid:
            self.username = user_oid.name
        else:
            self.username = "Unknown user: %s" % self.user_uuid

        accessgroup_oid = backend.get_oid(self.access_group_uuid,
                                        object_type="accessgroup",
                                        instance=True)
        if accessgroup_oid:
            self.access_group = accessgroup_oid.name
        else:
            self.access_group = ("Unknown accessgroup: %s"
                                % self.access_group_uuid)

        # Get reneg stuff.
        reneg_started = self.get_config_parameter('RENEG_STARTED')
        if isinstance(reneg_started, bool) or isinstance(reneg_started, float):
            self.reneg_started = reneg_started
        last_reneg = self.get_config_parameter('LAST_RENEG')
        if isinstance(last_reneg, bool) or isinstance(last_reneg, float):
            self.last_reneg = last_reneg
        reneg_hash = self.get_config_parameter('RENEG_HASH')
        if reneg_hash != "":
            self.reneg_hash = reneg_hash

        # Get object index.
        try:
            self.index = self.object_config['INDEX']
        except:
            pass

        return True

    def update_last_used_time(self, update_child_sessions=False, force=False):
        """ Update the time this session was last used. """
        if not force:
            # Update last used timestamp only every 30 seconds to save some IOPS.
            last_used_age = time.time() - self.last_used
            if last_used_age < 30:
                return

        logger.debug("Updating last used timestamp of session: %s"
                    % self.name)
        self.last_used = time.time()

        if not update_child_sessions:
            return

        # Update child sessions.
        for session_id in self.child_sessions:
            result = backend.get_sessions(session_id=session_id,
                                        return_type="instance")
            if not result:
                continue
            session = result[0]
            if not session:
                continue
            # FIXME: Do we need this? disabled groups would be still denied
            #        in User().authenticate(). does this check have a big performance impact?
            # Create group instance for this session to check if it is enabled.
            session_group = backend.get_object(object_type="accessgroup",
                                                name=session.access_group,
                                                realm=self.realm,
                                                site=self.site)
            if not session_group:
                logger.critical("Accessgroup of session '%s' does not exist "
                                "anymore: %s" % (session.name,
                                session.access_group))
                continue
            if not session_group.enabled:
                logger.debug("Not updating timestamp for disabled child "
                                "session '%s'." % session.name)
                continue
            session.update_last_used_time(update_child_sessions=True,
                                             force=force)
    @object_lock()
    def count_login(self,):
        """ Counts a login for this session. """
        # Count up login counter.
        self.login_count += 1
        # Set last login time.
        self.last_login = time.time()
        # Call method to update last used timestamp. This method also
        # writes the session config via write_config()
        self.update_last_used_time(update_child_sessions=True, force=True)
        return self.write_config()

    def expire_time(self):
        """ Return session expiration timestamp. """
        # calculate session expiration timestamp
        creation_time = datetime.fromtimestamp(float(self.creation_time))
        timeout = timedelta(seconds=float(self.timeout))
        session_expire_timestring = creation_time + timeout
        session_expire = time.mktime(session_expire_timestring.timetuple())
        return session_expire

    def unused_expire_time(self):
        """ Return expiration timestamp when session is unused. """
        session_expire = self.expire_time()
        # Calculate unused session expiration timestamp.
        last_used = datetime.fromtimestamp(float(self.last_used))
        unused_timeout = timedelta(seconds=float(self.unused_timeout))
        unused_session_expire_timestring = last_used + unused_timeout
        unused_session_expire = time.mktime(unused_session_expire_timestring.timetuple())
        # Set unused expiry time to session expiry time if it would be after
        # session expiry
        if unused_session_expire > session_expire:
            unused_session_expire = session_expire
        return unused_session_expire

    @object_lock()
    def start_reneg(self, pass_hash):
        """ Mark session as waiting for renegotiation to finish. """
        # Set new password hash.
        self.reneg_hash = pass_hash
        # Update start timestamp.
        self.reneg_started = time.time()
        # Write it to session config.
        if self.write_config():
            logger.debug("Started session renegotiation: %s" % self.name)
            status = True
        else:
            logger.critical("Error writing renegotiation parameters: "
                            "reneg_start: %s" % self.name)
            status = False
        return status

    @object_lock()
    def finish_reneg(self):
        """ Finalize session renegotiation (e.g. change session ID etc.). """
        # Set new session hash.
        old_pass_hash = self.pass_hash
        self.pass_hash = self.reneg_hash
        # The old session hash is kept in self.reneg_hash to allow
        # SOTPs generated from the old hash to be verified as long
        # as the are valid.
        self.reneg_hash = old_pass_hash
        # Update timestamp.
        self.last_reneg = time.time()
        # Reset reneg status.
        self.reneg_started = False
        # Write new session.
        if self.write_config():
            logger.debug("Session renegotiation successful: %s" % self.name)
            status = True
        else:
            logger.critical("Error writing renegotiation parameters: "
                            "reneg_finish: %s" % self.name)
            status = False
        return status

    def verify(self, password=None, password_hash=None,
        challenge=None, response=None, **kwargs):
        """ Verify session. """
        if not password and not password_hash and not (challenge and response):
            msg = (_("Need 'password' or 'challenge' + 'response'!"))
            raise OTPmeException(msg)
        session_hashes = [ self.pass_hash ]
        # If we have a renegotiation hash we have to check it too.
        if self.reneg_hash:
            session_hashes.append(self.reneg_hash)

        for session_hash in session_hashes:
            if password:
                verify_reply = self._verify(auth_type="clear-text",
                                            session_hash=session_hash,
                                            password_hash=password_hash,
                                            password=password, **kwargs)
            elif challenge and response:
                verify_reply = self._verify(auth_type="mschap",
                                            session_hash=session_hash,
                                            challenge=challenge,
                                            response=response, **kwargs)
            verify_status = verify_reply['status']
            if verify_status is not None:
                return verify_reply
        return verify_reply

    def _verify(self, auth_type, session_hash, password=None,
        password_hash=None, challenge=None, response=None, check_sotp=False,
        do_reneg=False, reneg_salt=None, rsp_hash_type=None, auth_ag=None,
        check_auth=True, check_slp=True, check_srp=True):
        """ Verify given session hash via password or MSCHAP challenge/response. """
        # default should be None -> session does not match request
        verify_reply = {'status' : None}

        if auth_type == "clear-text":
            logger.debug("Doing clear-text session verification.")

        if auth_type == "mschap":
            logger.debug("Doing MSCHAP session verification.")

        # If the given hash is the old (before renegotiation) session hash
        # we dont need to verify it.
        if not self.reneg_started and session_hash == self.reneg_hash:
            check_auth = False
            check_srp = False
            check_slp = False

        if auth_type == "clear-text":
            if not password:
                if do_reneg or check_sotp or check_srp or check_slp:
                    raise OTPmeException("Need password.")
            if not password_hash:
                if do_reneg or check_auth:
                    raise OTPmeException("Need password_hash.")

        if auth_type == "mschap":
            if not challenge or not response:
                raise OTPmeException("Need MSCHAP challenge/response.")

            if do_reneg:
                msg = ("Unable to do session renegotiation for MSCHAP requests.")
                raise OTPmeException(msg)

        # Check for session renegotiation.
        if do_reneg:
            # First check for already started session renegotiation.
            if self.reneg_started:
                reneg_match = False
                if self.reneg_hash == password_hash:
                    reneg_match = True

                if reneg_match:
                    status = self.finish_reneg()
                    verify_reply = {
                                    'type'      : 'reneg_end',
                                    'status'    : status,
                                    }
                    return verify_reply

            # Check for new session renegotiation.
            if auth_type == "clear-text":
                sotp_verify_status = sotp.verify(password_hash=session_hash,
                                                password=password, reneg=True)
                if sotp_verify_status:
                    srotp = password

            if auth_type == "mschap":
                sotp_verify_status, \
                nt_key, \
                _srotp, \
                srotp_hash = sotp.verify(password_hash=session_hash,
                                        challenge=challenge,
                                        response=response,
                                        reneg=True)
                if sotp_verify_status:
                    srotp = _srotp

            if sotp_verify_status:
                if self.reneg_started:
                    msg = ("Got repeated renegotiation request: %s" % self.name)
                    logger.warning(msg)

                logger.debug("Generating new RSP for session: %s" % self.name)
                # FIXME: where to get len of new session password from???
                # Generate new session hash.
                new_session_pass = sotp.derive_rsp(secret=srotp,
                                            hash_type=rsp_hash_type,
                                            salt=reneg_salt)
                if auth_type == "mschap":
                    new_session_hash = stuff.gen_nt_hash(new_session_pass)
                else:
                    new_session_hash = otpme_pass.gen_one_iter_hash(self.username,
                                                            new_session_pass)

                status = self.start_reneg(new_session_hash)
                verify_reply = {
                                'type'      : 'reneg_start',
                                'status'    : status,
                                }
                return verify_reply

        # Verify session.
        if check_auth:
            # Try to verify session with given clear-text password.
            if auth_type == "clear-text":
                if session_hash == password_hash:
                    verify_reply = {
                                    'type'      : 'auth',
                                    'status'    : True,
                                    }
                    return verify_reply

            # Try to verify session with given MSCHAP challenge/response.
            if auth_type == "mschap":
                try:
                    verify_status, nt_key = mschap_util.verify(session_hash,
                                                            challenge, response)
                except Exception as e:
                    verify_status = None
                    msg = ("Error verifying MSCHAP request (auth): %s: %s"
                            % (self.session_id, e))
                    logger.critical(msg)
                if verify_status:
                    verify_reply = {
                                    'type'      : 'auth',
                                    'status'    : True,
                                    'nt_key'    : nt_key,
                                    }
                    return verify_reply

        # Check for SLP.
        if check_slp:
            if auth_type == "clear-text":
                # Check if given password matches logout password of this
                # session.
                if self.slp == password:
                    verify_reply = {
                                    'type'      : 'logout',
                                    'status'    : True,
                                    'slp'       : self.slp,
                                    }
                    return verify_reply

            if auth_type == "mschap":
                # Generate password hash of logout password of this session.
                _slp_hash = stuff.gen_nt_hash(self.slp)
                # Try to verify challenge/response with logout password hash for
                # this session.
                try:
                    verify_status, nt_key = mschap_util.verify(_slp_hash,
                                                                challenge,
                                                                response)
                except Exception as e:
                    verify_status = None
                    msg = ("Error verifying MSCHAP request (SLP): %s: %s"
                            % (self.session_id, e))
                    logger.critical(msg)
                if verify_status:
                    verify_reply = {
                                    'type'      : 'logout',
                                    'status'    : True,
                                    'slp'       : self.slp,
                                    'slp_hash'  : _slp_hash,
                                    'nt_key'    : nt_key,
                                    }
                    return verify_reply

        # Check for SRP.
        if check_srp:
            # Build refresh pass from session hash.
            _srp = srp.gen(session_hash)

            if auth_type == "clear-text":
                # Verify given password matches refresh password of this session.
                if _srp == password:
                    verify_reply = {
                                    'type'      : 'refresh',
                                    'status'    : True,
                                    'srp'       : _srp,
                                    }
                    return verify_reply

            if auth_type == "mschap":
                # Generate password hash of refresh password of this session.
                _srp_hash = stuff.gen_nt_hash(_srp)
                # Try to verify challenge/response with refresh password hash
                # for this session.
                try:
                    mschap_verify_status, nt_key = mschap_util.verify(_srp_hash,
                                                                        challenge,
                                                                        response)
                except Exception as e:
                    mschap_verify_status = None
                    msg = ("Error verifying MSCHAP request (SRP): %s: %s"
                            % (self.session_id, e))
                    logger.critical(msg)

                if mschap_verify_status:
                    verify_reply = {
                                    'type'      : 'refresh',
                                    'status'    : True,
                                    'srp'       : _srp,
                                    'srp_hash'  : _srp_hash,
                                    'nt_key'    : nt_key,
                                    }
                    return verify_reply

        # Check for SOTP.
        if check_sotp:
            if auth_type == "clear-text":
                auth_ag_uuid = None
                if auth_ag:
                    # Get sotp auth accessgroup.
                    result = backend.search(object_type="accessgroup",
                                            attribute="name",
                                            value=auth_ag,
                                            return_type="uuid")
                    if not result:
                        msg = "Unknown accessgroup: %s" % auth_ag
                        logger.critical(msg)
                        return verify_reply
                    auth_ag_uuid = result[0]
                # Check if given password matches an SOTP of this session.
                sotp_verify_status = sotp.verify(password_hash=session_hash,
                                                password=password,
                                                access_group=auth_ag_uuid)
                if sotp_verify_status:
                    verify_reply = {
                                    'type'      : 'reauth',
                                    'status'    : True,
                                    'sotp'     : password,
                                    }
                    return verify_reply

            if auth_type == "mschap":
                try:
                    sotp_verify_status, \
                    nt_key, \
                    _sotp, \
                    _sotp_hash = sotp.verify(password_hash=session_hash,
                                                challenge=challenge,
                                                response=response)
                except Exception as e:
                    verify_status = None
                    msg = ("Error verifying MSCHAP request (SOTP): %s: %s"
                            % (self.session_id, e))
                    logger.critical(msg)

                if sotp_verify_status:
                    verify_reply = {
                                    'type'      : 'reauth',
                                    'status'    : True,
                                    'sotp'      : _sotp,
                                    'sotp_hash' : _sotp_hash,
                                    'nt_key'    : nt_key,
                                    }
                    return verify_reply

        # Return default status.
        return verify_reply

    @object_lock()
    def add_child_session(self, session_id):
        """ Add session ID to child sessions. """
        # Add child session if its not already there.
        if session_id in self.child_sessions:
            return True
        self.child_sessions.append(session_id)
        return self.write_config()

    # FIXME: create_child_sessions() creates all child sessions regardless if
    #        the token used for the request is allowed for the child session/group.
    #        Verification if the user/token is allowed for a session is done in
    #        session verification section. Maybe this behavior is a good idea
    #        because you can add permissions to access a child group/session
    #        after the user has logged in. (e.g. no re-login needed). A ugly
    #        side effect is the added amount of not used sessions to verify for
    #        each request.
    @object_lock()
    def create_child_sessions(self, groups_processed=None,
        offline_data_key=None, start_group=None, access_group=None):
        """
        Walk through all child groups and add child sessions
        to parent session.
        """
        # If groups_processed is not set we where not called from ourselves
        # (see below in this method) so we create ourselves if needed and add
        # our access group to groups_processed.
        if not groups_processed:
            # Add ourselves.
            if not self.exists():
                logger.debug("Adding session '%s'" % self.name)
                self.add(offline_data_key=offline_data_key)
                # Reload session config.
                self.exists()
            groups_processed = [ self.access_group ]
            access_group = self.access_group

        # Create group instance.
        group = backend.get_object(object_type="accessgroup",
                                    name=access_group,
                                    realm=self.realm,
                                    site=self.site)
        if not group:
            return False

        # Start group used to pass on timeout values.
        if not start_group:
            start_group = group

        # We only create sessions for enabled groups.
        if not group.enabled:
            logger.debug("Group '%s' is disabled, will not create sessions."
                            % group.name)
            return False

        # Walk through all child sessions of the current group.
        for c in group.childs(sessions=True):
            # FIXME: Should child sessions inherit client and client_ip from parent session?
            #        Currently they dont as for child sessions there was no direct client request
            client = None
            client_ip = None

            # Create child group instance.
            child_group = backend.get_object(object_type="accessgroup",
                                            realm=self.realm,
                                            site=self.site,
                                            name=c)
            # Skip orphan groups.
            if not child_group:
                continue
            # Only process enabled child groups.
            if not child_group.enabled:
                continue

            # Create child session instance for each child group.
            child_session = Session(self.session_type,
                                    self.username,
                                    pass_hash=self.pass_hash,
                                    pass_hash_params=self.pass_hash_params,
                                    token=self.auth_token,
                                    access_group=c,
                                    client=client,
                                    client_ip=client_ip)
            # Add child session if it does not exist.
            if not child_session.exists():
                logger.debug("Adding child session '%s'." % child_session.name)
                child_session.add()

                # Check if child sessions should inherit timeouts from parent group.
                if start_group.timeout_pass_on:
                    child_session.timeout = start_group.session_timeout
                    child_session.unused_timeout = start_group.unused_session_timeout
                # Write changes.
                child_session.write_config()
                # Add session to child sessions.
                self.child_sessions.append(child_session.session_id)

            # Write config.
            self.write_config()

            # Skip already processed groups.
            if c in groups_processed:
                continue

            # Add child group to list of already processed groups.
            groups_processed.append(c)

            # Create child sessions for this child session.
            child_session.create_child_sessions(groups_processed=groups_processed,
                                                start_group=start_group, access_group=c)
        return True

    def get_child_sessions(self, child_sessions=False, tree_level=0):
        """
        Return dictionary with all child sessions and their tree level recursive.
        """
        # If we got no child_sessions we where not called from ourselves.
        if not child_sessions:
            child_sessions = {}

        # Walk through child sessions.
        for session_id in self.child_sessions:
            # Get child session instance by ID.
            result = backend.get_sessions(session_id=session_id,
                                        return_type="instance")
            # Skip child sessions that do not exist anymore.
            if not result:
                continue
            child = result[0]
            # Skip already processed child sessions.
            if child.session_id in list(child_sessions):
                continue
            # Append child session to list.
            child_sessions[str(child.session_id)] = str(tree_level)
            # Get child session childs.
            child_sessions = child.get_child_sessions(child_sessions=child_sessions,
                                                    tree_level=tree_level + 1)
        return child_sessions

    @object_lock()
    def add(self, offline_data_key=None):
        """ Add a session. """
        # Set session creation time.
        self.creation_time = time.time()
        self.add_index('creation_time', self.creation_time)
        # Set session last used time.
        self.last_used = time.time()

        self.offline_data_key = offline_data_key

        # Check which timeout values we must use for this session.
        if self.cache:
            # For cache sessions get timeout values from config.
            self.timeout = config.static_pass_timeout
            self.unused_timeout = config.static_pass_unused_timeout
        else:
            # Create group instance to get timeout values from.
            group = backend.get_object(object_type="accessgroup",
                                name=self.access_group,
                                realm=self.realm,
                                site=self.site)
            # FIXME: search group via backend.search!?
            #        what to do if group does not exist?
            # Get time values from group.
            if not group:
                msg = "Unknown group: %s" % self.access_group
                raise OTPmeException(msg)
            # Set timeouts from accessgroup
            self.timeout = group.session_timeout
            self.unused_timeout = group.unused_session_timeout

        return self.write_config()

    @object_lock()
    def delete(self, force=False, recursive=False, verify_acls=True,
        callback=default_callback, **kwargs):
        """ Delete session. """
        if verify_acls and config.auth_token:
            if config.auth_token.uuid != config.admin_token_uuid:
                # Try to get auth token of session.
                t = backend.get_object(object_type="token",
                                    uuid=self.auth_token)
                if not t:
                    msg = ("Permission denied: Session token missing")
                    return callback.error(msg, exception=PermissionDenied)
                # Try to get session user.
                u = backend.get_object(object_type="user", uuid=t.owner_uuid)
                if not u:
                    msg = ("Permission denied: Session user missing")
                    return callback.error(msg, exception=PermissionDenied)
                # Check if the current user is allowed to delete sessions of
                # the user.
                if not u.verify_acl("delete:session"):
                    msg = ("Permission denied.")
                    return callback.error(msg, exception=PermissionDenied)

        # Get all child sessions.
        child_sessions = {}
        if self.child_sessions:
            for c in self.child_sessions:
                result = backend.get_sessions(session_id=c,
                                            return_type="instance")
                if not result:
                    continue
                s = result[0]
                child_sessions[s.name] = s

        if not force:
            if child_sessions:
                if config.auth_token and config.auth_token.confirmation_policy != "force":
                    if recursive:
                        msg = (_("Session '%(session_name)s' has child "
                                "sessions:\n%(child_sessions)s\n"
                                "Delete session and all child sessions?: ")
                                % {"session_name":self.name,
                                "child_sessions":"\n".join(child_sessions)})
                        answer = callback.ask(msg)
                        if answer.lower() != "y":
                            return callback.abort()
                    else:
                        msg = (_("Session '%(session_name)s' has child "
                                "sessions:\n%(child_sessions)s\n"
                                "Delete session AND LEAVE child sessions?: ")
                                % {"session_name":self.name,
                                "child_sessions":"\n".join(child_sessions)})
                        answer = callback.ask(msg)
                        if answer.lower() != "y":
                            return callback.abort()
            else:
                if config.auth_token and config.auth_token.confirmation_policy == "paranoid":
                    answer = callback.ask(_("Delete session '%s'?: ") % self.name)
                    if answer.lower() != "y":
                        return callback.abort()

        # Remove child sessions.
        if recursive:
            for s in child_sessions:
                session = child_sessions[s]
                session.delete(recursive=recursive,
                                force=True,
                                verify_acls=verify_acls)

        try:
            backend.delete_object(self.oid, cluster=True)
        except UnknownObject:
            pass
        except Exception as e:
            config.raise_exception()
            msg = (_("Error removing session '%s': %s") % (self.name, e))
            return callback.error(msg)

        return callback.ok()
