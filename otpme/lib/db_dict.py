# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from sqlalchemy import exc
from sqlalchemy import Table
from sqlalchemy import types
from sqlalchemy import select
from sqlalchemy import insert
from sqlalchemy import delete
from sqlalchemy import update
from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import bindparam
from sqlalchemy import create_engine
from sqlalchemy import TypeDecorator
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.exc import IntegrityError
#from sqlalchemy.dialects.sqlite import JSON
#from sqlalchemy.dialects.sqlite import insert
#from sqlalchemy.exc import ResourceClosedError

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
#from otpme.lib import config
#from otpme.lib import filetools
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

sessions = {}

from sqlalchemy import event
db_uri = "postgresql+psycopg2://root:@/otpme?host=/var/run/otpme/sockets/postgres"
engine = create_engine(db_uri,
                    #isolation_level="READ COMMITTED",
                    isolation_level="AUTOCOMMIT",
                    connect_args={'sslmode':'disable'},
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

class JSON(TypeDecorator):
    cache_ok = True
    @property
    def python_type(self):
        return object
    impl = types.String
    def process_bind_param(self, value, dialect):
        return json.dumps(value)
    def process_literal_param(self, value, dialect):
        return value
    def process_result_value(self, value, dialect):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None

def get_dict_name():
    dict_name = stuff.gen_uuid()
    dict_name = "sqlite_dict.%s" % dict_name
    return dict_name

def get_list_name():
    list_name = stuff.gen_uuid()
    list_name = "sqlite_list.%s" % list_name
    return list_name

class SQLiteObject(object):
    def __init__(self, uuid):
        self.uuid = uuid
        self.meta = MetaData()
        dict_attrs_table_name = "dict_attrs.%s" % self.uuid
        self.dict_attrs_table = Table(
            dict_attrs_table_name, self.meta,
            Column('id', Integer, primary_key=True),
            Column('attribute', String, unique=True),
            Column('key', JSON, unique=False),
            Column('value', JSON),
        )
        list_attrs_table_name = "list_attrs.%s" % self.uuid
        self.list_attrs_table = Table(
            list_attrs_table_name, self.meta,
            Column('id', Integer, primary_key=True),
            Column('attribute', String),
            Column('value', JSON),
        )
        self.meta.create_all(engine)

    @property
    def session(self):
        session = self.get_session()
        return session

    def get_session(self):
        global sessions
        thread_id = multiprocessing.get_id()
        try:
            session = sessions[thread_id]
        except:
            session_factory = sessionmaker(bind=engine)
            Session = scoped_session(session_factory)
            session = Session()
            sessions[thread_id] = session
        #print("IIII", id(session))
        #session.begin()
        return session

    def commit(self):
        self.session.commit()

    def close(self):
        return
        thread_id = multiprocessing.get_id()
        try:
            session = sessions.pop(thread_id)
        except KeyError:
            pass
        session.close()

    def drop(self):
        self.dict_attrs_table.drop(engine)
        self.list_attrs_table.drop(engine)

class SQLiteDict(SQLiteObject):
    def __init__(self, uuid, name=None, data={}, **kwargs):
        if name is None:
            name = "sqlite_dict.start"
        self.name = name
        self.type = "dict"
        super(SQLiteDict, self).__init__(uuid, **kwargs)
        if data:
            self.bulk_insert(data)

    #def __del__(self):
    #    try:
    #        self.session.commit()
    #    except ResourceClosedError:
    #        pass

    def __getitem__(self, key):
        #print("db_dict.__getitem__")
        sql_stmt = select(self.dict_attrs_table)
        attr_id = "%s.%s" % (self.name, key)
        sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute == attr_id)
        result = self.session.execute(sql_stmt)
        try:
            value = result.first()
            value = value[3]
        except TypeError:
            raise KeyError()
        if not isinstance(value, str):
            return value
        if value.startswith("sqlite_dict."):
            value = SQLiteDict(uuid=self.uuid, name=value)
        elif value.startswith("sqlite_list."):
            value = SQLiteList(uuid=self.uuid, name=value)
        return value

    def bulk_insert(self, _dict):
        #print("db_dict.bulk_insert")
        # Bulk insert data.
        if not _dict:
            return
        #print("BBB_dict")
        # Build list with inserts/upserts dicts.
        inserts = []
        upserts = []
        for key in _dict:
            value = _dict[key]
            if isinstance(value, dict):
                # Get random dict name.
                dict_name = get_dict_name()
                # Create dict with the given data..
                value = SQLiteDict(uuid=self.uuid, name=dict_name, data=value)
            # If the given value is a list we have to create a SQLiteList from it.
            elif isinstance(value, list):
                # Get random list name.
                list_name = get_list_name()
                # Create list with the given data..
                value = SQLiteList(uuid=self.uuid, name=list_name, data=value)
            # Use object name as reverence for it.
            if isinstance(value, SQLiteDict):
                value = value.name
            if isinstance(value, SQLiteList):
                value = value.name
            attr_id = "%s.%s" % (self.name, key)
            x_insert = {'attribute':attr_id, 'key':key, 'value':value}
            inserts.append(x_insert)
            x_upsert = {'attr_id':attr_id, 'key':key, 'value':value}
            upserts.append(x_upsert)
        # Try to run bulk insert.
        sql_stmt = insert(self.dict_attrs_table)
        try:
            self.session.execute(sql_stmt, inserts)
        except IntegrityError:
            self.session.rollback()
            # If inserts already exists try upsert.
            sql_stmt = update(self.dict_attrs_table)
            sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute == bindparam("attr_id"))
            self.session.connection().execute(sql_stmt, upserts)

    def __setitem__(self, key, value):
        #print("db_dict.__setitem__")
        # Get current value.
        try:
            cur_val = self.__getitem__(key)
        except KeyError:
            cur_val = None
        clear_cur_val = None
        # If given value is SQLiteDict it needs special handling.
        if isinstance(value, SQLiteDict):
            # Check if given SQLiteDict is the same as we already have.
            if isinstance(cur_val, SQLiteDict):
                if cur_val.name == value.name:
                    return
            # If its a new SQLiteDict we just have to add a reverence via its name.
            value = value.name
            clear_cur_val = False
        # If given value is SQLiteList it needs special handling.
        if isinstance(value, SQLiteList):
            # Check if given SQLiteList is the same we already have.
            if isinstance(cur_val, SQLiteList):
                if cur_val.name == value:
                    return
            # If its a new SQLiteList we just have to add a reverence via its name.
            value = value.name
            clear_cur_val = False

        # If clearing was not set to False check if we have to clear the current value.
        if clear_cur_val is None:
            if isinstance(cur_val, SQLiteDict):
                clear_cur_val = True
            if isinstance(cur_val, SQLiteList):
                clear_cur_val = True

        # Clear current dict/list.
        if clear_cur_val:
            cur_val.clear()

        # If the given value is a dict we have to create a SQLiteDict from it.
        if isinstance(value, dict):
            # Get random dict name.
            dict_name = get_dict_name()
            # Create dict with the given data..
            x_dict = SQLiteDict(uuid=self.uuid, name=dict_name, data=value)
            # Use dict name as reverence for it.
            value = x_dict.name
        # If the given value is a list we have to create a SQLiteList from it.
        elif isinstance(value, list):
            # Get random dict name.
            list_name = get_list_name()
            # Create dict with the given data..
            x_list = SQLiteList(uuid=self.uuid, name=list_name, data=value)
            # Use dict name as reverence for it.
            value = x_list.name

        # Build attribute ID.
        attr_id = "%s.%s" % (self.name, key)
        # Build insert data dict.
        x_insert = {'attribute':attr_id, 'key':key, 'value':value}
        # Build insert statement.
        sql_stmt = insert(self.dict_attrs_table)
        # Try to execute insert statement.
        try:
            self.session.execute(sql_stmt, x_insert)
        except IntegrityError:
            self.session.rollback()
            # If the attribute exists in DB try update statement.
            sql_stmt = update(self.dict_attrs_table)
            sql_stmt = sql_stmt.values(x_insert)
            sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute == attr_id)
            self.session.execute(sql_stmt)
        #self.session.commit()

    def __delitem__(self, key):
        #print("db_dict.__delitem__")
        attr_id = "%s.%s" % (self.name, key)
        sql_stmt = delete(self.dict_attrs_table)
        sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute == attr_id)
        self.session.execute(sql_stmt)

    def get_all(self):
        #print("db_dict.get_all")
        attr_id = "%s.%s" % (self.name, "%")
        sql_stmt = select(self.dict_attrs_table)
        sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute.like(attr_id))
        result = self.session.execute(sql_stmt)
        result = result.all()
        return result

    def get_dict(self):
        #print("db_dict.get_dict")
        result = self.get_all()
        _dict = {}
        for x in result:
            x_key = x[2]
            x_val = x[3]
            if isinstance(x_val, str):
                if x_val.startswith("sqlite_dict."):
                    x_val = SQLiteDict(uuid=self.uuid, name=x_val)
                elif x_val.startswith("sqlite_list."):
                    x_val = SQLiteList(uuid=self.uuid, name=x_val)
            _dict[x_key] = x_val
        return _dict

    def __str__(self):
        #print("db_dict.__str__")
        _dict = self.get_dict()
        _str = _dict.__str__()
        return _str

    def copy(self):
        #print("db_dict.copy")
        _dict = self.get_dict()
        for x_key in _dict:
            x_val = _dict[x_key]
            if isinstance(x_val, SQLiteDict):
                x_val = x_val.copy()
                if not isinstance(x_val, dict):
                    raise OTPmeException()
            if isinstance(x_val, SQLiteList):
                x_val = x_val.copy()
                if not isinstance(x_val, list):
                    raise OTPmeException()
            _dict[x_key] = x_val
        return _dict.copy()

    def __eq__(self, other):
        #print("db_dict.__eq__")
        return self.__str__() == other.__str__()

    def __ne__(self, other):
        #print("db_dict.__ne__")
        return self.__str__() != other.__str__()

    def __lt__(self, other):
        #print("db_dict.__lt__")
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        #print("db_dict.__gt__")
        return self.__str__() > other.__str__()

    def __len__(self):
        #print("db_dict.__len__")
        _dict = self.get_dict()
        return len(_dict)

    def __iter__(self):
        #print("db_dict.__iter__")
        _dict = self.get_dict()
        return iter(_dict)

    def __repr__(self):
        #print("db_dict.__repr__")
        return self.__str__()

    def values(self):
        #print("db_dict.values")
        _dict = self.get_dict()
        return _dict.values()

    def items(self):
        #print("db_dict.items")
        _dict = self.get_dict()
        return _dict.items()

    def keys(self):
        #print("db_dict.keys")
        _dict = self.get_dict()
        return _dict.keys()

    def pop(self, key):
        #print("db_dict.pop")
        del_val = self.__getitem__(key)
        self.__delitem__(key)
        return del_val

    def clear(self):
        #print("db_dict.clear")
        # Clear dict.
        _dict = self.get_dict()
        for x_key in _dict:
            x_val = _dict[x_key]
            # Check for SQLiteDict/SQLiteList to clear.
            if isinstance(x_val, SQLiteDict):
                x_val.clear()
            if isinstance(x_val, SQLiteList):
                x_val.clear()
        attr_id = "%s.%s" % (self.name, "%")
        sql_stmt = delete(self.dict_attrs_table)
        sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute.like(attr_id))
        self.session.execute(sql_stmt)

class SQLiteList(SQLiteObject):
    def __init__(self, uuid, name=None, data={}, **kwargs):
        if name is None:
            name = "sqlite_list.start"
        self.name = name
        self.type = "list"
        #SQLiteObject.__init__(self, **kwargs)
        super(SQLiteList, self).__init__(uuid, **kwargs)
        if data:
            self.bulk_insert(data)

    #def __del__(self):
    #    try:
    #        self.session.commit()
    #    except ResourceClosedError:
    #        pass

    def bulk_insert(self, _list):
        #print("db_list.bulk_insert")
        # Bulk insert data.
        if not _list:
            return
        #print("BBB_list", _list)
        # Build list with inserts/upserts dicts.
        inserts = []
        upserts = []
        for value in _list:
            #if isinstance(value, dict):
            #    # Get random dict name.
            #    dict_name = get_dict_name()
            #    # Create dict with the given data..
            #    value = SQLiteDict(uuid=self.uuid, name=dict_name, data=value)
            ## If the given value is a list we have to create a SQLiteList from it.
            #elif isinstance(value, list):
            #    # Get random list name.
            #    list_name = get_list_name()
            #    # Create list with the given data..
            #    value = SQLiteList(uuid=self.uuid, name=list_name, data=value)
            ## Use object name as reverence for it.
            #if isinstance(value, SQLiteDict):
            #    value = value.name
            #if isinstance(value, SQLiteList):
            #    value = value.name
            attr_id = self.name
            x_insert = {'attribute':attr_id, 'value':value}
            inserts.append(x_insert)
            x_upsert = {'attr_id':attr_id, 'value':value}
            upserts.append(x_upsert)
        # Try to run bulk insert.
        sql_stmt = insert(self.list_attrs_table)
        try:
            self.session.execute(sql_stmt, inserts)
        except IntegrityError:
            self.session.rollback()
            # If inserts already exists try upsert.
            sql_stmt = update(self.list_attrs_table)
            sql_stmt = sql_stmt.where(self.list_attrs_table.c.attribute == bindparam("attr_id"))
            self.session.connection().execute(sql_stmt, upserts)

    def get_list(self):
        #print("db_list.get_list")
        _list = []
        attr_id = self.name
        sql_stmt = select(self.list_attrs_table.c.value)
        sql_stmt = sql_stmt.where(self.list_attrs_table.c.attribute == attr_id)
        #sql_stmt = sql_stmt.order_by("value")
        result = self.session.execute(sql_stmt)
        for x in result.all():
            x_val = x[0]
            #if isinstance(x_val, str):
            #    if x_val.startswith("sqlite_dict."):
            #        x_val = SQLiteDict(uuid=self.uuid, name=x_val)
            #    elif x_val.startswith("sqlite_list."):
            #        x_val = SQLiteList(uuid=self.uuid, name=x_val)
            _list.append(x_val)
        return _list

    def __getitem__(self, pos):
        #print("db_list.__getitem__")
        _list = self.get_list()
        value = _list[pos]
        #if not isinstance(value, str):
        #    return value
        #if value.startswith("sqlite_dict."):
        #    value = SQLiteDict(uuid=self.uuid, name=value)
        #elif value.startswith("sqlite_list."):
        #    value = SQLiteList(uuid=self.uuid, name=value)
        return value

    def __setitem__(self, index, item):
        msg = "Not implemented."
        raise OTPmeException(msg)

    def __delitem__(self, index):
        msg = "Not implemented."
        raise OTPmeException(msg)

    def __str__(self):
        #print("db_list.__str__")
        _list = self.get_list()
        _str = _list.__str__()
        return _str

    def copy(self):
        #print("db_list.copy")
        _list = self.get_list()
        _list_copy = []
        for x_val in _list:
            if isinstance(x_val, SQLiteDict):
                x_val = x_val.copy()
                if not isinstance(x_val, dict):
                    raise OTPmeException()
            if isinstance(x_val, SQLiteList):
                x_val = x_val.copy()
                if not isinstance(x_val, list):
                    raise OTPmeException()
            _list_copy.append(x_val)
        return _list_copy

    def __eq__(self, other):
        #print("db_list.__eq__")
        return self.__str__() == other.__str__()

    def __ne__(self, other):
        #print("db_list.__ne__")
        return self.__str__() != other.__str__()

    def __lt__(self, other):
        #print("db_list.__lt__")
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        #print("db_list.__gt__")
        return self.__str__() > other.__str__()

    def __len__(self):
        #print("db_list.__len__")
        _list = self.get_list()
        return len(_list)

    def __iter__(self):
        #print("db_list.__iter__")
        _list = self.get_list()
        return iter(_list)

    def __repr__(self):
        #print("db_list.__repr__")
        return self.__str__()

    def append(self, value):
        #print("db_list.append")
        ## If the given value is a dict we have to create a SQLiteDict from it.
        #if isinstance(value, dict):
        #    # Get random dict name.
        #    dict_name = get_dict_name()
        #    # Create dict with the given data..
        #    value = SQLiteDict(uuid=self.uuid, name=dict_name, data=value)
        ## If the given value is a list we have to create a SQLiteList from it.
        #elif isinstance(value, list):
        #    # Get random list name.
        #    list_name = get_list_name()
        #    # Create dict with the given data..
        #    value = SQLiteList(uuid=self.uuid, name=list_name, data=value)

        ## Use object name as reverence for it.
        #if isinstance(value, SQLiteDict):
        #    value = value.name
        #if isinstance(value, SQLiteList):
        #    value = value.name

        # Build attribute ID.
        attr_id = self.name
        # Build insert data dict.
        x_insert = {'attribute':attr_id, 'value':value}
        # Build insert statement.
        sql_stmt = insert(self.list_attrs_table)
        # Try to execute insert statement.
        try:
            self.session.execute(sql_stmt, x_insert)
        except IntegrityError:
            self.session.rollback()
            # If the attribute exists in DB try update statement.
            sql_stmt = update(self.dict_attrs_table)
            sql_stmt = sql_stmt.values({'value':value})
            sql_stmt = sql_stmt.where(self.dict_attrs_table.c.attribute == attr_id)
            self.session.execute(sql_stmt)

    def insert(self, index, value):
        msg = "Not implemented."
        raise OTPmeException(msg)

    def pop(self, index=-1):
        msg = "Not implemented."
        raise OTPmeException(msg)

    def remove(self, value):
        #print("db_list.remove")
        attr_id = self.name
        sql_stmt = select(self.list_attrs_table.c.id, self.list_attrs_table.c.value)
        sql_stmt = sql_stmt.where(self.list_attrs_table.c.attribute == attr_id)
        sql_stmt = sql_stmt.where(self.list_attrs_table.c.value == value)
        result = self.session.execute(sql_stmt)
        one_entry = result.first()
        if not one_entry:
            raise ValueError()
        entry_id = one_entry[0]
        sql_stmt = delete(self.list_attrs_table)
        sql_stmt = sql_stmt.where(self.list_attrs_table.c.id == entry_id)
        self.session.execute(sql_stmt)

    def clear(self):
        #print("db_list.clear")
        # Clear list.
        #_list = self.get_list()
        #for x_val in _list:
        #    # Check for SQLiteDict/SQLiteList to clear.
        #    if isinstance(x_val, SQLiteDict):
        #        x_val.clear()
        #    if isinstance(x_val, SQLiteList):
        #        x_val.clear()
        attr_id = self.name
        sql_stmt = delete(self.list_attrs_table)
        sql_stmt = sql_stmt.where(self.list_attrs_table.c.attribute.like(attr_id))
        self.session.execute(sql_stmt)
