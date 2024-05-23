# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.backends.file.index import INDEX_DIR
from otpme.lib.backends.file.index import create_db_indices

from otpme.lib.exceptions import *

Base = None
classes = {}
cache_regions = {}

engine = None
Session = None
need_start = False

logger = config.logger

TIMEOUT = 60
BUSY_TIMEOUT = TIMEOUT * 1000
INDEX_DB = "%s/objects.sqlite" % INDEX_DIR
DB_URI = "sqlite:////%s" % INDEX_DB

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    register_config_vars()

def register_config_vars():
    config.register_config_var("sqlite3_bin", str, "sqlite3",
                        config_file_parameter="SQLITE3_BIN")
    config.register_config_var("sqlite3_pragma_synchronous", str, "OFF",
                        config_file_parameter="SQLITE3_PRAGMA_SYNCHRONOUS")

def cleanup():
    pass

def atfork():
    """ Reload backend stuff. """
    global engine
    if not engine:
        return
    engine.dispose()

def sqlite3_cli():
    from otpme.lib import system_command
    cli_cmd = [config.sqlite3_bin, INDEX_DB]
    return_code = system_command.run(command=cli_cmd,
                                user=config.user,
                                group=config.group,
                                call=True)
    if return_code == 0:
        return True
    return False

def drop():
    """ Remove all data from DB. """
    if not os.path.exists(INDEX_DB):
        return
    os.remove(INDEX_DB)

def status():
    return

def start():
    return

def stop():
    return

def command(command):
    """ Receive index command. """
    from otpme.lib.backends.file.file import index_rebuild
    # Init dirs, permissions etc.
    init_dirs()
    # Handle command.
    if command == "create_db_indices":
        create_db_indices()
    elif command == "drop_db_indices":
        create_db_indices(drop=True)
    elif command == "rebuild":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return index_rebuild()
    elif command == "init":
        return init()
    elif command == "start":
        msg = "Invalid command for sqlite3."
        raise OTPmeException(msg)
    elif command == "wait":
        msg = "Invalid command for sqlite3."
        raise OTPmeException(msg)
    elif command == "stop":
        msg = "Invalid command for sqlite3."
        raise OTPmeException(msg)
    elif command == "restart":
        msg = "Invalid command for sqlite3."
        raise OTPmeException(msg)
    elif command == "status":
        msg = "Invalid command for sqlite3."
        raise OTPmeException(msg)
    elif command == "drop":
        if stuff.controld_status():
            msg = "Please stop otpme daemon first."
            raise OTPmeException(msg)
        return drop()
    elif command == "cli":
        sqlite3_cli()
    else:
        msg = "Unknown index command: %s" % command
        raise OTPmeException(msg)

def init_dirs():
    from otpme.lib import filetools
    files = ({
                INDEX_DB    : 0o660,
                })
    directories = ({
                INDEX_DIR   : 0o770,
                })

    if config.handle_files_dirs:
        filetools.ensure_fs_permissions(directories=directories, files=files)
    else:
        for x in directories:
            if os.path.exists(x):
                continue
            msg = ("No such file or directory: %s" % x)
            raise OTPmeException(msg)

def init(init_file_dir_perms=False):
    if config.system_user() != config.user and config.system_user() != "root":
        return True
    if init_file_dir_perms:
        init_dirs()
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
    import sqlite3
    from sqlalchemy import event
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.orm import scoped_session
    global engine
    global Session
    def creator():
        db_uri = INDEX_DB
        conn = sqlite3.connect(db_uri, timeout=TIMEOUT, isolation_level=None)
        conn.execute('PRAGMA journal_mode=WAL')
        #conn.execute('PRAGMA journal_mode=MEMORY')
        conn.execute('PRAGMA busy_timeout = %s' % BUSY_TIMEOUT)
        if config.sqlite3_pragma_synchronous == "OFF":
            conn.execute("PRAGMA synchronous=OFF")
        if config.sqlite3_pragma_synchronous == "FULL":
            conn.execute("PRAGMA synchronous=FULL")
        if config.sqlite3_pragma_synchronous == "EXTRA":
            conn.execute("PRAGMA synchronous=EXTRA")
        if config.sqlite3_pragma_synchronous == "NORMAL":
            conn.execute("PRAGMA synchronous=NORMAL")
        return conn
    if not engine:
        # Get DB engine
        engine = create_engine('sqlite://', creator=creator, echo=False)
        # Starting IMMEDIATE transaction is essential for the sqlite index
        # to work with sqlalchemy session.begin_nested(). Without it the
        # 'sqlite3.OperationalError) database is locked' exception occurs.
        # https://stackoverflow.com/questions/30438595/sqlite3-ignores-sqlite3-busy-timeout
        # https://stackoverflow.com/questions/55306196/sqlalchemy-how-to-make-sqlite-transactions-immediate/55387746
        @event.listens_for(engine, "connect")
        def do_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None
        @event.listens_for(engine, "begin")
        def do_begin(conn):
            conn.execute("BEGIN IMMEDIATE")

        # Create session factory.
        session_factory = sessionmaker(bind=engine)
        # Create thread safe session.
        # https://docs.sqlalchemy.org/en/13/orm/contextual.html#thread-local-scope
        Session = scoped_session(session_factory)
    return engine

def get_db_connection():
    global Session
    session = Session()
    return session

# FIXME: Implement otpme-tool backup using clone DB???
#def clone_db(clone_db=":memory:"):
#    """ Clone sqlite DB. """
#    # https://lambdafu.net/2010/08/27/how-to-use-sqlites-backup-in-python/
#    # Get connection to src DB via apsw.
#    src_db = apsw.Connection(INDEX_DB)
#    # Set timeout when waiting for locks.
#    src_db.setbusytimeout(BUSY_TIMEOUT)
#    # Get connection to dst DB.
#    dst_db = apsw.Connection(clone_db)
#    # Set timeout when waiting for locks.
#    dst_db.setbusytimeout(BUSY_TIMEOUT)
#    # Copy src DB to dst DB.
#    with dst_db.backup("main", src_db, "main") as backup:
#        while not backup.done:
#            try:
#                backup.step(100)
#            except apsw.BusyError:
#                time.sleep(0.1)
#    backup.close()
#    # Use in-memory connection via sqlalchemy.
#    _pool = pool.SingletonThreadPool(lambda: sqlite3.connect(dst_db))
#    engine = create_engine('sqlite://', pool=_pool, echo=False)
#    session = sessionmaker(bind=engine)
#    # Create thread safe session.
#    # https://docs.sqlalchemy.org/en/13/orm/contextual.html#thread-local-scope
#    session = scoped_session(session)
#    src_db.close()
#    return dst_db, engine, session

#def clone_db(dst):
#    """ Clone sqlite DB. """
#    # Get connection (engine) to index DB.
#    get_db_connection(DB_URI)
#    src = engine
#
#    # Create tables in transaction DB.
#    Base.metadata.create_all(bind=dst)
#
#    # Copy data.
#    tables = Base.metadata.tables
#    for x in tables:
#        data = tables[x].select()
#        data = src.execute(data).fetchall()
#        if not data:
#            continue
#        dst.execute(tables[x].insert(), data)
#
#    return dst

