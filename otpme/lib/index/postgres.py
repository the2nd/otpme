# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import shutil

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib.backends.file.index import INDEX_DIR
from otpme.lib.backends.file.index import create_db_indices
from otpme.lib.third_party.dogpile_caching.caching_query import query_callable

from otpme.lib.exceptions import *

engine = None
Session = None
need_start = True
cache_regions = {}

REGISTER_BEFORE = []
REGISTER_AFTER = []

DBAPI = "psycopg2"
#DBAPI = "pg8000"
#DBAPI = "psycopg2cffi"
#DBAPI = "pygresql"
#DBAPI = "pypostgresql"
DB_NAME = "otpme"
CONF_FILE_NAME = "postgresql.conf"
CONF_FILE = os.path.join(INDEX_DIR, CONF_FILE_NAME)
LOGFILE = os.path.join(config.log_dir, "postgresql.log")
ETC_CONF_FILE = os.path.join(config.config_dir, CONF_FILE_NAME)

LC_TIME="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LC_MESSAGES="en_US.UTF-8"
LC_MONETARY="en_US.UTF-8"

AUTOVACUUM = "on"
AUTOVACUUM_WORK_MEM = -1
AUTOVACUUM_MAX_WORKERS = 5
AUTOVACUUM_NAPTIME = "1min"
AUTOVACUUM_FREEZE_MAX_AGE = 100000
#AUTOVACUUM_FREEZE_MAX_AGE = 200000000
AUTOVACUUM_VACUUM_THRESHOLD = 50
AUTOVACUUM_ANALYZE_THRESHOLD = 50

FSYNC = "on"
WORK_MEM = "128MB"
MAX_CONNECTIONS = 500
RANDOM_PAGE_COST = 1.0
#RANDOM_PAGE_COST = 4.0
ENABLE_HASHJOIN = "off"
#ENABLE_HASHJOIN = "on"
SHARED_BUFFERS = "512MB"
SYNCHRONOUS_COMMIT = "off"
MAINTENANCE_WORK_MEM = "256MB"
EFFECTIVE_CACHE_SIZE = "512MB"
DYNAMIC_SHARED_MEMORY_TYPE = "posix"

DATESTYLE = "iso, mdy"
TIMEZONE = "Europe/Berlin"
LOG_TIMEZONE = "Europe/Berlin"
DEFAULT_TEXT_SEARCH_CONFIG = "pg_catalog.english"

def register():
    register_config_vars()

def register_config_vars():
    config.register_config_var("psql_bin", str, "psql",
                        config_file_parameter="POSTGRES_PSQL_BIN")
    config.register_config_var("createdb_bin", str, "createdb",
                        config_file_parameter="POSTGRES_CREATEDB_BIN")
    config.register_config_var("createuser_bin", str, "createuser",
                        config_file_parameter="POSTGRES_CREATEUSER_BIN")
    config.register_config_var("pg_isready_bin", str, "pg_isready",
                        config_file_parameter="POSTGRES_PG_ISREADY_BIN")
    config.register_config_var("pg_ctl_bin", str, "pg_ctl",
                        config_file_parameter="POSTGRES_PG_CTL_BIN")
    config.register_config_var("postgres_socket_dir", str, None,
                        config_file_parameter="POSTGRES_SOCKET_DIR")
    config.register_config_var("postgres_dbapi", str, DBAPI,
                                config_file_parameter="POSTGRES_DBAPI")
    # Tuning parameters.
    config.register_config_var("postgres_work_mem", str, WORK_MEM,
                        config_file_parameter="POSTGRES_WORK_MEM")
    config.register_config_var("postgres_shared_buffers", str, SHARED_BUFFERS,
                        config_file_parameter="POSTGRES_SHARED_BUFFERS")
    config.register_config_var("postgres_synchronous_commit", str, SYNCHRONOUS_COMMIT,
                        config_file_parameter="POSTGRES_SYNCHRONOUS_COMMIT")
    config.register_config_var("postgres_effective_cache_size", str, EFFECTIVE_CACHE_SIZE,
                        config_file_parameter="POSTGRES_EFFECTIVE_CACHE_SIZE")
    config.register_config_var("postgres_maintenance_work_mem", str, MAINTENANCE_WORK_MEM,
                        config_file_parameter="POSTGRES_MAINTENANCE_WORK_MEM")
    config.register_config_var("postgres_dynamic_shared_memory_type", str, DYNAMIC_SHARED_MEMORY_TYPE,
                        config_file_parameter="POSTGRES_DYNAMIC_SHARED_MEMORY_TYPE")
    config.register_config_var("postgres_max_connections", int, MAX_CONNECTIONS,
                        config_file_parameter="POSTGRES_MAX_CONNECTIONS")
    config.register_config_var("postgres_autovacuum", str, AUTOVACUUM,
                        config_file_parameter="POSTGRES_AUTOVACUUM")
    config.register_config_var("postgres_autovacuum_work_mem", int, AUTOVACUUM_WORK_MEM,
                        config_file_parameter="POSTGRES_AUTOVACUUM_WORK_MEM")
    config.register_config_var("postgres_autovacuum_naptime", str, AUTOVACUUM_NAPTIME,
                        config_file_parameter="POSTGRES_AUTOVACUUM_NAPTIME")
    config.register_config_var("postgres_autovacuum_max_workers", int, AUTOVACUUM_MAX_WORKERS,
                        config_file_parameter="POSTGRES_AUTOVACUUM_MAX_WORKERS")
    config.register_config_var("postgres_autovacuum_freeze_max_age", int, AUTOVACUUM_FREEZE_MAX_AGE,
                        config_file_parameter="POSTGRES_AUTOVACUUM_FREEZE_MAX_AGE")
    config.register_config_var("postgres_autovacuum_vacuum_threshold", int, AUTOVACUUM_VACUUM_THRESHOLD,
                        config_file_parameter="POSTGRES_AUTOVACUUM_VACUUM_THRESHOLD")
    config.register_config_var("postgres_autovacuum_analyze_threshold", int, AUTOVACUUM_ANALYZE_THRESHOLD,
                        config_file_parameter="POSTGRES_AUTOVACUUM_ANALYZE_THRESHOLD")
    config.register_config_var("postgres_datestyle", str, DATESTYLE,
                        config_file_parameter="POSTGRES_DATESTYLE")
    config.register_config_var("postgres_timezone", str, TIMEZONE,
                        config_file_parameter="POSTGRES_TIMEZONE")
    config.register_config_var("postgres_log_timezone", str, LOG_TIMEZONE,
                        config_file_parameter="POSTGRES_LOG_TIMEZONE")
    config.register_config_var("postgres_lc_time", str, LC_TIME,
                        config_file_parameter="POSTGRES_LC_TIME")
    config.register_config_var("postgres_lc_numeric", str, LC_NUMERIC,
                        config_file_parameter="POSTGRES_LC_NUMERIC")
    config.register_config_var("postgres_lc_messages", str, LC_MESSAGES,
                        config_file_parameter="POSTGRES_LC_MESSAGES")
    config.register_config_var("postgres_lc_monetary", str, LC_MONETARY,
                        config_file_parameter="POSTGRES_LC_MONETARY")
    config.register_config_var("postgres_default_text_search_config", str, DEFAULT_TEXT_SEARCH_CONFIG,
                        config_file_parameter="POSTGRES_DEFAULT_TEXT_SEARCH_CONFIG")
    config.register_config_var("postgres_fsync", str, FSYNC,
                        config_file_parameter="POSTGRES_FSYNC")
    config.register_config_var("postgres_random_page_cost", float, RANDOM_PAGE_COST,
                        config_file_parameter="POSTGRES_RANDOM_PAGE_COST")
    config.register_config_var("postgres_enable_hashjoin", str, ENABLE_HASHJOIN,
                        config_file_parameter="POSTGRES_ENABLE_HASHJOIN")

def get_default_config():
    default_config = []
    max_connections = "max_connections = %s" % config.postgres_max_connections
    shared_buffers = "shared_buffers = %s" % config.postgres_shared_buffers
    work_mem = "work_mem = %s" % config.postgres_work_mem
    maintenance_work_mem = "maintenance_work_mem = %s" % config.postgres_maintenance_work_mem
    synchronous_commit = "synchronous_commit = %s" % config.postgres_synchronous_commit
    random_page_cost = "random_page_cost = %s" % config.postgres_random_page_cost
    enable_hashjoin = "enable_hashjoin = %s" % config.postgres_enable_hashjoin
    effective_cache_size = "effective_cache_size = %s" % config.postgres_effective_cache_size
    dynamic_shared_memory_type = "dynamic_shared_memory_type = %s" % config.postgres_dynamic_shared_memory_type
    timezone = "timezone = '%s'" % config.postgres_timezone
    datestyle = "datestyle = '%s'" % config.postgres_datestyle
    log_timezone = "log_timezone = '%s'" % config.postgres_log_timezone
    #lc_time = "lc_time = '%s'" % config.postgres_lc_time
    #lc_numeric = "lc_numeric = '%s'" % config.postgres_lc_numeric
    #lc_messages = "lc_messages = '%s'" % config.postgres_lc_messages
    #lc_monetary = "lc_monetary = '%s'" % config.postgres_lc_monetary
    autovacuum = "autovacuum = %s" % config.postgres_autovacuum
    autovacuum_naptime = "autovacuum_naptime = %s" % config.postgres_autovacuum_naptime
    autovacuum_work_mem = "autovacuum_work_mem = %s" % config.postgres_autovacuum_work_mem
    autovacuum_max_workers = "autovacuum_max_workers = %s" % config.postgres_autovacuum_max_workers
    autovacuum_vacuum_threshold = "autovacuum_vacuum_threshold = %s" % config.postgres_autovacuum_vacuum_threshold
    autovacuum_analyze_threshold = "autovacuum_analyze_threshold = %s" % config.postgres_autovacuum_analyze_threshold
    autovacuum_freeze_max_age = "autovacuum_freeze_max_age = %s" % config.postgres_autovacuum_freeze_max_age
    default_text_search_config = "default_text_search_config = '%s'" % config.postgres_default_text_search_config
    fsync = "fsync = %s" % config.postgres_fsync

    default_config.append(max_connections)
    default_config.append(shared_buffers)
    default_config.append(work_mem)
    default_config.append(maintenance_work_mem)
    default_config.append(effective_cache_size)
    default_config.append(dynamic_shared_memory_type)
    default_config.append(log_timezone)
    default_config.append(datestyle)
    default_config.append(timezone)
    #default_config.append(lc_messages)
    #default_config.append(lc_monetary)
    #default_config.append(lc_numeric)
    #default_config.append(lc_time)
    default_config.append(default_text_search_config)
    default_config.append(autovacuum)
    default_config.append(autovacuum_work_mem)
    default_config.append(autovacuum_naptime)
    default_config.append(autovacuum_max_workers)
    default_config.append(autovacuum_vacuum_threshold)
    default_config.append(autovacuum_analyze_threshold)
    default_config.append(autovacuum_freeze_max_age)
    default_config.append(fsync)
    default_config.append(synchronous_commit)
    default_config.append(random_page_cost)
    default_config.append(enable_hashjoin)
    default_config = "\n".join(default_config)
    return default_config

def cleanup():
    global Session
    if Session:
        Session.remove()
    Session = None

def atfork():
    global engine
    global Session
    engine = None
    Session = None

def print_message(msg, **kwargs):
    from otpme.lib.messages import message
    prefix = "* "
    message(msg, prefix=prefix, **kwargs)

def get_socket_dir():
    """ Get socket dir. """
    socket_dir = config.postgres_socket_dir
    if socket_dir is None:
        socket_dir = os.path.join(config.sockets_dir, "postgres")
    return socket_dir

def cli():
    from otpme.lib import system_command
    socket_dir = get_socket_dir()
    cli_cmd = [config.psql_bin, "-h", socket_dir, "-s", DB_NAME]
    return_code = system_command.run(command=cli_cmd,
                                #user=config.user,
                                #group=config.group,
                                call=True)
    if return_code == 0:
        return True
    return False

def wait_for_start(timeout=5):
    timeout = timeout * 10
    msg = "Waiting for postgres to start up..."
    print_message(msg)
    counter = 0
    while not status():
        counter += 1
        if counter >= timeout:
            return False
        time.sleep(0.1)
    return True

def status():
    from otpme.lib import system_command
    socket_dir = get_socket_dir()
    status_cmd = [ config.pg_isready_bin, "-h", socket_dir, ]
    return_code = system_command.run(command=status_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=None,
                                    stderr=None,
                                    call=True)
    if return_code == 0:
        return True
    return False

def start():
    from otpme.lib import system_command
    # Init dirs, permissions etc.
    init_dirs()
    if status():
        msg = "Postgres already running."
        raise AlreadyRunning(msg)
    conf_file = CONF_FILE
    if os.path.exists(ETC_CONF_FILE):
        msg = ("Using custom postgres config: %s" % ETC_CONF_FILE)
        print(msg)
        conf_file = ETC_CONF_FILE
    else:
        set_default_config()
    logger = config.logger
    msg = "Starting postgresql..."
    logger.debug(msg)
    msg = "Using config file: %s" % conf_file
    logger.debug(msg)
    socket_dir = get_socket_dir()
    postgres_opts = "-h '' -k %s -c config_file=%s" % (socket_dir, conf_file)
    start_cmd = [
                config.pg_ctl_bin,
                "-D", INDEX_DIR,
                "-l", LOGFILE,
                "-o", postgres_opts,
                "start",
                ]
    return_code = system_command.run(command=start_cmd,
                                    user=config.user,
                                    group=config.group,
                                    close_fds=True,
                                    stdout=None,
                                    shell=False,
                                    call=False)
    if return_code == 0:
        return True
    return False

def _reload():
    from otpme.lib import system_command
    if not status():
        msg = "Postgres not running."
        raise NotRunning(msg)
    logger = config.logger
    msg = "Reloading postgresql..."
    logger.debug(msg)
    reload_cmd = [config.pg_ctl_bin, "-D", INDEX_DIR, "reload"]
    return_code = system_command.run(command=reload_cmd,
                                    user=config.user,
                                    group=config.group,
                                    call=True)
    if return_code == 0:
        return True
    return False

def stop():
    from otpme.lib import system_command
    global engine
    global Session
    engine = None
    Session = None
    if not status():
        msg = "Postgres not running."
        raise NotRunning(msg)
    logger = config.logger
    msg = "Stopping postgresql..."
    logger.info(msg)
    stop_cmd = [config.pg_ctl_bin, "-D", INDEX_DIR, "-m", "immediate", "stop"]
    return_code = system_command.run(command=stop_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=None,
                                    call=True)
    if return_code == 0:
        return True
    return False

def create_db_user(username):
    from otpme.lib import system_command
    socket_dir = get_socket_dir()
    create_user_cmd = [config.createuser_bin, "-h", socket_dir, "-s", username]
    return_code = system_command.run(command=create_user_cmd,
                                    user=config.user,
                                    group=config.group,
                                    call=True)
    if return_code == 0:
        return True
    return False

def create_db(dbname):
    from otpme.lib import system_command
    socket_dir = get_socket_dir()
    create_db_cmd = [config.createdb_bin, "-h", socket_dir, dbname]
    return_code = system_command.run(command=create_db_cmd,
                                    user=config.user,
                                    group=config.group,
                                    call=True)
    if return_code == 0:
        return True
    return False

def set_default_config():
    default_config = get_default_config()
    filetools.create_file(CONF_FILE, default_config)
    #fd = open(CONF_FILE, "w")
    #fd.write(default_config)
    #fd.close()

def init_db():
    from otpme.lib import system_command
    header = "----------------------- initdb start ------------------------"
    footer = "----------------------- initdb end --------------------------"
    print_message(header)
    init_cmd = [config.pg_ctl_bin, "initdb", "-D", INDEX_DIR]
    return_code = system_command.run(command=init_cmd,
                                    user=config.user,
                                    group=config.group,
                                    call=True)
    print_message(footer)
    if return_code != 0:
        msg = "Postgres initdb failed."
        raise OTPmeException(msg)
    init_msg = []
    if os.path.exists(CONF_FILE):
        org_conf = "%s.org" % CONF_FILE
        init_msg.append("Using otpme default config. Please try original "
                    "config file if you run into issues: %s" % org_conf)
        os.rename(CONF_FILE, org_conf)
    set_default_config()
    msg = "Starting postgres..."
    print_message(msg)
    start()
    wait_for_start()
    msg = "Creating postgres user (root)..."
    print_message(msg)
    create_db_user("root")
    msg = "Creating postgres user (otpme)..."
    print_message(msg)
    create_db_user("otpme")
    msg = "Creating otpme DB..."
    print_message(msg)
    create_db(DB_NAME)
    msg = "You can use 'otpme-tool index [start|stop]' to start/stop postgres."
    init_msg.append(msg)
    init_msg = "\n".join(init_msg)
    print(init_msg)
    return True

def drop():
    """ Remove DB directory. """
    if not os.path.exists(INDEX_DIR):
        return True
    if status():
        stop()
    try:
        shutil.rmtree(INDEX_DIR)
    except Exception as e:
        msg = "Failed to delete index dir: %s" % e
        raise OTPmeException(msg)
    return True

def command(command):
    """ Receive index command. """
    from otpme.lib.backends.file.file import index_rebuild
    # Handle command.
    if command == "create_db_indices":
        create_db_indices(desc=True)
    elif command == "drop_db_indices":
        create_db_indices(desc=True, drop=True)
    elif command == "rebuild":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return index_rebuild()
    elif command == "init":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return init_db()
    elif command == "start":
        start()
        return wait_for_start()
    elif command == "wait":
        return wait_for_start()
    elif command == "stop":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return stop()
    elif command == "reload":
        _reload()
    elif command == "restart":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        try:
            stop()
        except NotRunning:
            pass
        start()
        wait_for_start()
    elif command == "status":
        if not status():
            msg = "Postgres not running"
            raise NotRunning(msg)
    elif command == "drop":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return drop()
    elif command == "cli":
        if not status():
            msg = "Postgres not running"
            raise NotRunning(msg)
        cli()
    else:
        msg = "Unknown index command: %s" % command
        raise OTPmeException(msg)

def init_dirs():
    from otpme.lib import filetools
    socket_dir = get_socket_dir()
    directories = ({
                INDEX_DIR   : 0o700,
                socket_dir  : 0o770,
                })

    if config.handle_files_dirs:
        # Make sure DB dir exists.
        filetools.ensure_fs_permissions(directories=directories, files=None)
    else:
        for x in directories:
            if os.path.exists(x):
                continue
            msg = ("No such file or directory: %s" % x)
            raise OTPmeException(msg)

def init(init_file_dir_perms=False):
    #from sqlalchemy_utils import database_exists
    #from sqlalchemy_utils import create_database

    if config.system_user() != config.user and config.system_user() != "root":
        return True

    if init_file_dir_perms:
        init_dirs()

    # Make sure DB exists.
    #engine = get_db_engine()
    #if database_exists(engine.url):
    #    return
    #create_database(engine.url)

    # FIXME: Dogpile caching leads to deadlocks! Running 3 concurrent user add
    # processes hangs sometimes.
    config.dogpile_caching = False

def is_available(write=True):
    """ Check if backend is available. """
    if write:
        if not os.access(INDEX_DIR, os.W_OK):
            return False
    if not os.access(INDEX_DIR, os.R_OK):
        return False
    return True

def get_db_engine():
    # Import here to speedup import time.
    from sqlalchemy import exc
    from sqlalchemy import event
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.orm import scoped_session
    global engine
    global Session
    global cache_regions
    if not engine:
        socket_dir = get_socket_dir()
        postgres_driver = config.postgres_dbapi
        if postgres_driver == "pg8000":
            socket_file = os.path.join(socket_dir, ".s.PGSQL.5432")
            db_uri = ("postgresql+pg8000://%s:root@/%s?unix_sock=%s"
                    % (config.system_user(), DB_NAME, socket_file))
        elif postgres_driver == "pygresql":
            db_uri = ("postgresql+pygresql://%s:root@/%s?host=%s"
                    % (config.system_user(), DB_NAME, socket_dir))

        elif postgres_driver == "psycopg2cffi":
            db_uri = ("postgresql+psycopg2cffi://%s:@/%s?host=%s"
                    % (config.system_user(), DB_NAME, socket_dir))
        elif postgres_driver == "psycopg2":
            socket_dir = get_socket_dir()
            #db_uri = ("postgresql+psycopg2://%s:@%s:%s/%s"
            #        % (config.system_user(), "127.0.0.1", 5433, DB_NAME))
            db_uri = ("postgresql+psycopg2://%s:@/%s?host=%s"
                    % (config.system_user(), DB_NAME, socket_dir))
        else:
            msg = "Unknown sqlalchemy driver: %s" % postgres_driver
            raise OTPmeException(msg)

        #from sqlalchemy.pool import QueuePool
        #from sqlalchemy.pool import NullPool
        engine = create_engine(db_uri,
                            #isolation_level="SERIALIZABLE",
                            #isolation_level="READ UNCOMMITTED",
                            isolation_level="READ COMMITTED",
                            #isolation_level="REPEATABLE READ",
                            connect_args={'sslmode':'disable'},
                            #convert_unicode=True,
                            #pool_recycle=3600,
                            #pool_size=20,
                            #max_overflow=10,
                            #poolclass=QueuePool,
                            pool_pre_ping=False,
                            echo=False)

        # https://docs.sqlalchemy.org/en/20/core/pooling.html#switching-pool-implementations
        @event.listens_for(engine, "connect")
        def connect(dbapi_connection, connection_record):
            connection_record.info["pid"] = os.getpid()

        @event.listens_for(engine, "checkout")
        def checkout(dbapi_connection, connection_record, connection_proxy):
            pid = os.getpid()
            if connection_record.info["pid"] != pid:
                connection_record.dbapi_connection = connection_proxy.dbapi_connection = None
                raise exc.DisconnectionError(
                    "Connection record belongs to pid %s, "
                    "attempting to check out in pid %s" % (connection_record.info["pid"], pid)
                )

        #@event.listens_for(engine, "before_cursor_execute")
        #def before_cursor_execute(conn, cursor, statement,
        #                        parameters, context, executemany):
        #    conn.info.setdefault('query_start_time', []).append(time.time())
        #    #print("Start Query: %s" % statement)

        #@event.listens_for(engine, "after_cursor_execute")
        #def after_cursor_execute(conn, cursor, statement,
	    #                        parameters, context, executemany):
        #    total = time.time() - conn.info['query_start_time'].pop(-1)
        #    if total >= 0.01:
        #        print(statement)
        #        print("Total Time: %f" % total)

        # Create dogpile cache regions.
        sessionmaker_kwargs = {'bind':engine}
        if config.dogpile_caching:
            if not cache_regions:
                _cache = config.get_cache_module()
                for x in config.object_types:
                    region_name = config.get_cache_region(x)
                    if region_name in cache_regions:
                        continue
                    x_region = _cache.get_dogpile_region(region_name)
                    cache_regions[region_name] = x_region
            query_cls = query_callable(cache_regions)
            sessionmaker_kwargs['query_cls'] = query_cls

        # Create session factory.
        session_factory = sessionmaker(**sessionmaker_kwargs)
        # Create thread safe session.
        # https://docs.sqlalchemy.org/en/13/orm/contextual.html#thread-local-scope
        Session = scoped_session(session_factory)

        #session_factory = sessionmaker(bind=engine)
        ## Create thread safe session.
        ## https://docs.sqlalchemy.org/en/13/orm/contextual.html#thread-local-scope
        #Session = scoped_session(session_factory)
    return engine

def get_db_connection():
    global Session
    if Session is None:
        get_db_engine()
    session = Session()
    #class TestSession:
    #    def __init__(self, x):
    #        self.session = x
    #        #print("IIIII", id(self.session))
    #    def close(self, *args, **kwargs):
    #        print("CCCCC", id(self.session))
    #        from otpme.lib import debug
    #        debug.trace()
    #        return self.session.close(*args, **kwargs)
    #    def __getattr__(self, name):
    #        attr = self.session.__getattribute__(name)
    #        return attr
    #session = TestSession(session)
    return session
