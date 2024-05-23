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

DB_NAME = "otpme"
CONF_FILE_NAME = "mysql.cnf"
CONF_FILE = os.path.join(INDEX_DIR, CONF_FILE_NAME)
LOGFILE = os.path.join(config.log_dir, "mysqld.log")
ETC_CONF_FILE = os.path.join(config.config_dir, CONF_FILE_NAME)

DBAPI = "cymysql"
#DBAPI = "mysqldb"
#DBAPI = "pymysql"
MAX_CONNECTIONS = 500
KEY_BUFFER_SIZE = "160M"
THREAD_STACK = "192K"
MAX_ALLOWED_PACKET = "512M"
THREAD_CACHE_SIZE = 8
MAX_CONNECTIONS = 512
QUERY_CACHE_LIMIT = "10M"
QUERY_CACHE_SIZE = "160M"
EXPIRE_LOGS_DAYS = 10
MAX_BINLOG_SIZE = "100M"
CHARACTER_SET_SERVER = "utf8mb4"
COLLATION_SERVER = "utf8mb4_general_ci"
MYISAM_RECOVER_OPTIONS = "BACKUP"

def register():
    register_config_vars()

def register_config_vars():
    config.register_config_var("mysql_bin", str, "mysql",
                                config_file_parameter="MYSQL_BIN")
    config.register_config_var("mysqld_bin", str, "/usr/sbin/mysqld",
                                config_file_parameter="MYSQLD_BIN")
    config.register_config_var("mysql_admin_bin", str, "mysqladmin",
                                config_file_parameter="MYSQL_ADMIN_BIN")
    config.register_config_var("mysql_install_db", str, "mysql_install_db",
                                config_file_parameter="MYSQL_INSTALL_DB")
    config.register_config_var("mysql_socket_dir", str, None,
                                config_file_parameter="MYSQL_SOCKET_DIR")
    config.register_config_var("mysql_dbapi", str, DBAPI,
                                config_file_parameter="MYSQL_DBAPI")
    config.register_config_var("mysql_key_buffer_size", str, KEY_BUFFER_SIZE,
                                config_file_parameter="MYSQL_KEY_BUFFER_SIZE")
    config.register_config_var("mysql_thread_stack", str, THREAD_STACK,
                                config_file_parameter="MYSQL_THREAD_STACK")
    config.register_config_var("mysql_max_allowed_packet", str, MAX_ALLOWED_PACKET,
                                config_file_parameter="MYSQL_MAX_ALLOWED_PACKET")
    config.register_config_var("mysql_thread_cache_size", int, THREAD_CACHE_SIZE,
                                config_file_parameter="MYSQL_THREAD_CACHE_SIZE")
    config.register_config_var("mysql_myisam_recover_options", str, MYISAM_RECOVER_OPTIONS,
                                config_file_parameter="MYSQL_MYISAM_RECOVER_OPTIONS")
    config.register_config_var("mysql_max_connections", int, MAX_CONNECTIONS,
                                config_file_parameter="MYSQL_MAX_CONNECTIONS")
    config.register_config_var("mysql_query_cache_limit", str, QUERY_CACHE_LIMIT,
                                config_file_parameter="MYSQL_QUERY_CACHE_LIMIT")
    config.register_config_var("mysql_query_cache_size", str, QUERY_CACHE_SIZE,
                                config_file_parameter="MYSQL_QUERY_CACHE_SIZE")
    config.register_config_var("mysql_expire_logs_days", int, EXPIRE_LOGS_DAYS,
                                config_file_parameter="MYSQL_EXPIRE_LOGS_DAYS")
    config.register_config_var("mysql_max_binlog_size", str, MAX_BINLOG_SIZE,
                                config_file_parameter="MYSQL_MAX_BINLOG_SIZE")
    config.register_config_var("mysql_character_set_server", str, CHARACTER_SET_SERVER,
                                config_file_parameter="MYSQL_CHARACTER_SET_SERVER")
    config.register_config_var("mysql_collation_server", str, COLLATION_SERVER,
                                config_file_parameter="MYSQL_COLLATION_SERVER")

def get_default_config():
    default_config = ['[mysqld]']
    db_user = "user = %s" % config.user
    pid_file = os.path.join(config.pidfile_dir, "mysql")
    pid_file = "pid-file = %s" % pid_file
    log_error = "log_error = %s" % LOGFILE
    socket_file = get_socket_file()
    socket_file = "socket = %s" % socket_file
    tmp_dir= "tmpdir = %s" % config.tmp_dir
    data_dir = "datadir = %s" % INDEX_DIR

    key_buffer_size = "key_buffer_size = %s" % config.mysql_key_buffer_size
    max_allowed_packet = "max_allowed_packet = %s" % config.mysql_max_allowed_packet
    thread_stack = "thread_stack = %s" % config.mysql_thread_stack
    thread_cache_size = "thread_cache_size = %s" % config.mysql_thread_cache_size
    myisam_recover_options = "myisam_recover_options = %s" % config.mysql_myisam_recover_options
    max_connections = "max_connections = %s" % config.mysql_max_connections
    #table_cache            = 64
    #thread_concurrency     = 10
    query_cache_limit = "query_cache_limit = %s" % config.mysql_query_cache_limit
    query_cache_size = "query_cache_size = %s" % config.mysql_query_cache_size
    expire_logs_days = "expire_logs_days = %s" % config.mysql_expire_logs_days
    max_binlog_size = "max_binlog_size = %s" % config.mysql_max_binlog_size
    character_set_server_ = "character-set-server = %s" % config.mysql_character_set_server
    collation_server = "collation-server = %s" % config.mysql_collation_server

    default_config.append(db_user)
    default_config.append(pid_file)
    default_config.append(log_error)
    default_config.append(socket_file)
    default_config.append(data_dir)
    default_config.append(tmp_dir)
    default_config.append(key_buffer_size)
    default_config.append(max_allowed_packet)
    default_config.append(thread_stack)
    default_config.append(thread_cache_size)
    default_config.append(myisam_recover_options)
    default_config.append(max_connections)
    #default_config.append(table_cache            = 64
    #default_config.append(thread_concurrency     = 10
    default_config.append(query_cache_limit)
    default_config.append(query_cache_size)
    default_config.append(expire_logs_days)
    default_config.append(max_binlog_size)
    default_config.append(character_set_server_)
    default_config.append(collation_server)
    default_config = "\n".join(default_config)
    return default_config

def cleanup():
    global Session
    if Session:
        Session.remove()

def atfork():
    pass

def print_message(msg, **kwargs):
    from otpme.lib.messages import message
    prefix = "* "
    message(msg, prefix=prefix, **kwargs)

def get_socket_dir():
    """ Get socket dir. """
    socket_dir = config.mysql_socket_dir
    if socket_dir is None:
        socket_dir = os.path.join(config.sockets_dir, "mysql")
    return socket_dir

def get_socket_file():
    """ Get socket file. """
    socket_dir = get_socket_dir()
    socket_file = os.path.join(socket_dir, "mysqld.sock")
    return socket_file

def cli():
    from otpme.lib import system_command
    socket_file = get_socket_file()
    cli_cmd = [config.mysql_bin, "-u", config.user,
                "-S", socket_file,
                "-p%s" % config.user, DB_NAME]
    return_code = system_command.run(command=cli_cmd,
                                user=config.user,
                                group=config.group,
                                call=True)
    if return_code == 0:
        return True
    return False

def wait_for_start(timeout=5):
    timeout = timeout * 10
    msg = "Waiting for mysql to start up..."
    print_message(msg)
    counter = 0
    while not status():
        counter += 1
        if counter >= timeout:
            return False
        time.sleep(0.1)
    return True

def wait_for_socket(timeout=5):
    timeout = timeout * 10
    msg = "Waiting for mysql socket to appear..."
    print_message(msg)
    counter = 0
    socket_file = get_socket_file()
    while not os.path.exists(socket_file):
        counter += 1
        if counter >= timeout:
            return False
        time.sleep(0.1)
    return True

def status():
    from otpme.lib import system_command
    socket_file = get_socket_file()
    status_cmd = [ config.mysql_admin_bin,
                "-u", config.user,
                "-p%s" % config.user,
                "-S", socket_file,
                'ping']
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
    if status():
        msg = "Mysql already running."
        raise AlreadyRunning(msg)
    conf_file = CONF_FILE
    if os.path.exists(ETC_CONF_FILE):
        msg = ("Using custom mysql config: %s" % ETC_CONF_FILE)
        print(msg)
        conf_file = ETC_CONF_FILE
    else:
        set_default_config()
    logger = config.logger
    msg = "Starting mysql..."
    logger.debug(msg)
    msg = "Using config file: %s" % conf_file
    logger.debug(msg)
    start_cmd = [config.mysqld_bin,
                "--defaults-file=%s" % conf_file,
                "--skip-networking", ]
    system_command.run(command=start_cmd,
                        user=config.user,
                        group=config.group,
                        close_fds=True,
                        return_proc=True,
                        shell=False,
                        call=False)
    return False

def stop():
    from otpme.lib import system_command
    if not status():
        msg = "Mysql not running."
        raise NotRunning(msg)
    logger = config.logger
    msg = "Stopping mysql..."
    logger.info(msg)
    socket_file = get_socket_file()
    stop_cmd = [ config.mysql_admin_bin,
                "-u", config.user,
                "-p%s" % config.user,
                "-S", socket_file,
                "shutdown"]
    return_code = system_command.run(command=stop_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=None,
                                    stderr=None,
                                    call=True)
    if return_code == 0:
        return True
    return False

def _reload():
    from otpme.lib import system_command
    if not status():
        msg = "Mysql not running."
        raise NotRunning(msg)
    logger = config.logger
    msg = "Stopping mysql..."
    logger.debug(msg)
    socket_file = get_socket_file()
    reload_cmd = [ config.mysql_admin_bin,
                "-u", config.user,
                "-p%s" % config.user,
                "-S", socket_file,
                "--local",
                "flush-error-log",
                "flush-engine-log",
                "flush-general-log",
                "flush-slow-log",
                ]
    return_code = system_command.run(command=reload_cmd,
                                    user=config.user,
                                    group=config.group,
                                    stdout=None,
                                    stderr=None,
                                    call=True)
    if return_code == 0:
        return True
    return False

def create_db_user(username):
    from otpme.lib import system_command
    socket_file = get_socket_file()
    user_statement = ("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';"
                % (config.user, config.user))
    user_cmd = [config.mysql_bin,
                "-u", config.system_user(),
                "-S", socket_file,
                "-e", user_statement]
    return_code = system_command.run(command=user_cmd,
                                    user=config.system_user(),
                                    group=config.system_group(),
                                    call=True)
    # Grant all permissions (e.g. to shutdown mysql).
    grant_statement = ("GRANT ALL PRIVILEGES ON *.* TO '%s'@'localhost';"
                % config.user)
    grant_cmd = [config.mysql_bin,
                "-u", config.system_user(),
                "-S", socket_file,
                "-e", grant_statement]
    return_code = system_command.run(command=grant_cmd,
                                    user=config.system_user(),
                                    group=config.system_group(),
                                    call=True)
    if return_code == 0:
        return True
    return False

def set_db_user_pass(username):
    from otpme.lib import system_command
    socket_file = get_socket_file()
    user_statement = ("ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';"
                % (config.user, config.user))
    user_cmd = [config.mysql_bin,
                "-u", config.system_user(),
                "-S", socket_file,
                "-e", user_statement]
    return_code = system_command.run(command=user_cmd,
                                    user=config.system_user(),
                                    group=config.system_group(),
                                    call=True)
    # Grant all permissions (e.g. to shutdown mysql).
    grant_statement = ("GRANT ALL PRIVILEGES ON *.* TO '%s'@'localhost';"
                % config.user)
    grant_cmd = [config.mysql_bin,
                "-u", config.system_user(),
                "-S", socket_file,
                "-e", grant_statement]
    return_code = system_command.run(command=grant_cmd,
                                    user=config.system_user(),
                                    group=config.system_group(),
                                    call=True)
    if return_code == 0:
        return True
    return False

def create_db(dbname):
    from otpme.lib import system_command
    socket_file = get_socket_file()
    db_statement = "create database %s;" % dbname
    db_create_cmd = [config.mysql_bin,
                "-u", config.system_user(),
                "-S", socket_file,
                "-e", db_statement]
    return_code = system_command.run(command=db_create_cmd,
                                    user=config.system_user(),
                                    group=config.system_group(),
                                    call=True)
    if return_code == 0:
        return True
    return False

def set_default_config():
    default_config = get_default_config()
    fd = open(CONF_FILE, "w")
    fd.write(default_config)
    fd.close()

def init_db():
    from otpme.lib import system_command
    header = "----------------------- initdb start ------------------------"
    footer = "----------------------- initdb end --------------------------"
    print_message(header)
    init_msg = []
    if os.path.exists(CONF_FILE):
        org_conf = "%s.org" % CONF_FILE
        init_msg.append("Using otpme default config. Please try original "
                    "config file if you run into issues: %s" % org_conf)
        os.rename(CONF_FILE, org_conf)
    # Create default config.
    set_default_config()
    # Init DB directory.
    init_cmd = [config.mysql_install_db, '--defaults-file=%s' % CONF_FILE,]
    return_code = system_command.run(command=init_cmd,
                                    user=config.user,
                                    group=config.group,
                                    close_fds=True,
                                    call=True)
    # Start mysql after init.
    start()
    wait_for_socket()
    # Create database.
    msg = "Creating otpme DB..."
    create_db(DB_NAME)
    print_message(msg)
    ## Create user.
    #msg = "Creating mysql user (%s)..." % config.user
    #print_message(msg)
    #create_db_user(config.user)
    # Set DB user password.
    msg = "Set password for mysql user (%s)..." % config.user
    print_message(msg)
    set_db_user_pass(config.user)
    print_message(footer)
    if return_code != 0:
        msg = "MySQL initdb failed."
        raise OTPmeException(msg)
    msg = "You can use 'otpme-tool index [start|stop]' to start/stop mysql."
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
    # Init dirs, permissions etc.
    init_dirs()
    # Handle command.
    if command == "create_db_indices":
        create_db_indices(left_prefix=True)
    elif command == "drop_db_indices":
        create_db_indices(drop=True)
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
    elif command == "reload":
        return _reload()
    elif command == "status":
        if not status():
            msg = "Mysql not running"
            raise NotRunning(msg)
    elif command == "drop":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return drop()
    elif command == "cli":
        if not status():
            msg = "Mysql not running"
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
    # FIXME: make this a config file option.
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
        mysql_dbapi = config.mysql_dbapi
        if mysql_dbapi == "mysqldb" \
        or mysql_dbapi == "pymysql" \
        or mysql_dbapi == "cymysql":
            socket_file = get_socket_file()
            db_uri = ("mysql+%s://%s:%s@/%s?unix_socket=%s"
                    % (mysql_dbapi, config.user, config.user, DB_NAME, socket_file))
        else:
            msg = "Unknown sqlalchemy mysql dbapi: %s" % mysql_dbapi
            raise OTPmeException(msg)

        #from sqlalchemy.pool import QueuePool
        # FIXME: Using NullPool to prevent "Aborted connection ..." error in mysqld.log.
        # https://www.mail-archive.com/sqlalchemy@googlegroups.com/msg45126.html
        from sqlalchemy.pool import NullPool
        engine = create_engine(db_uri,
                            # FIXME: make this a config file option.
                            pool_pre_ping=False,
                            #isolation_level="SERIALIZABLE",
                            isolation_level="READ UNCOMMITTED",
                            #isolation_level="READ COMMITTED",
                            #isolation_level="REPEATABLE READ",
                            #connect_args={'connect_timeout ':10},
                            connect_args={'connect_timeout': 10,},
                            #convert_unicode=True,
                            #pool_recycle=3600,
                            #pool_size=64,
                            #max_overflow=16,
                            #poolclass=QueuePool,
                            poolclass=NullPool,
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
    session = Session()
    return session
