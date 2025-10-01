# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

Base = None
classes = {}
logger = config.logger
INDEX_DIR = f"{config.data_dir}/index"

def cleanup():
    _index = config.get_index_module()
    return _index.cleanup()

def atfork():
    _index = config.get_index_module()
    return _index.atfork()

def init(init_file_dir_perms=False):
    """ Init sqlite stuff. """
    from otpme.lib import filetools
    from sqlalchemy.ext.declarative import declarative_base
    global Base
    global classes
    if config.system_user() != config.user and config.system_user() != "root":
        return True

    if init_file_dir_perms:
        directories = ({
                    # Postgresql requires 0700!
                    INDEX_DIR : 0o700,
                    })

        if config.handle_files_dirs:
            filetools.ensure_fs_permissions(directories=directories, files=None)
        else:
            for x in directories:
                if os.path.exists(x):
                    continue
                msg = _("No such file or directory: {x}")
                msg = msg.format(x=x)
                raise OTPmeException(msg)

    # Init DB.
    _index = config.get_index_module()
    _index.init(init_file_dir_perms=init_file_dir_perms)

    # Get base.
    Base = declarative_base()

    # Create per object type classes.
    classes.clear()
    for x in config.object_types:
        create_classes(x)

    # Make sure index DB is populated.
    engine = _index.get_db_engine()
    Base.metadata.create_all(engine)

def get_class(otype):
    """ Get class for object type. """
    if otype not in classes:
        msg = _("Unknown object type: {otype}")
        msg = msg.format(otype=otype)
        raise UnknownObjectType(msg)
    object_class = classes[otype]['object']
    attr_class = classes[otype]['attr']
    acl_class = classes[otype]['acl']
    return object_class, attr_class, acl_class

def create_class(class_name, super_classes=(), attrs_dict={}):
    """ Create class. """
    new_class = type(class_name, super_classes, attrs_dict)
    # Register class to make it pickable.
    # https://stackoverflow.com/questions/16377215/how-to-pickle-a-namedtuple-instance-correctly
    globals()[class_name] = new_class
    return new_class

def create_classes(otype):
    """ Create dynamic classes for given object type. """
    from sqlalchemy import Column
    from sqlalchemy import Integer
    from sqlalchemy import ForeignKey
    from sqlalchemy.orm import relationship
    from .models import IndexObject
    from .models import IndexObjectACL
    from .models import IndexObjectAttribute
    global classes
    if otype in classes:
        return
    objects_table = f"{otype}s"
    attrs_table = f"{otype}_attrs"
    acls_table = f"{otype}_acls"

    attr_class_name = f"{otype}Attribute"
    super_classes = (IndexObjectAttribute, Base)
    attrs_dict = {
            '__tablename__'     : attrs_table,
            #'__table_args__'   : {'extend_existing': True},
            '__mapper_args__'   : {'confirm_deleted_rows': False},
            'ioid'              : Column(Integer, ForeignKey(f'{objects_table}.id')),
            }
    attr_class = create_class(attr_class_name, super_classes, attrs_dict)

    acl_class_name = f"{otype}ACL"
    super_classes = (IndexObjectACL, Base)
    attrs_dict = {
            '__tablename__'     : acls_table,
            #'__table_args__'   : {'extend_existing': True},
            '__mapper_args__'   : {'confirm_deleted_rows': False},
            'ioid'              : Column(Integer, ForeignKey(f'{objects_table}.id')),
            }
    acl_class = create_class(acl_class_name, super_classes, attrs_dict)

    object_class_name = f"{otype}Object"
    super_classes = (IndexObject, Base)
    attrs_dict = {
        '__tablename__'     : objects_table,
        '__mapper_args__'   : {'confirm_deleted_rows': False},
        #'__table_args__'    : {'extend_existing': True},
        'attributes'        : relationship(attr_class_name,
                                cascade = "all,delete",
                                backref=objects_table,
                                lazy=True),
                                #lazy='dynamic'),
        'acls'              : relationship(acl_class_name,
                                cascade = "all,delete",
                                backref=objects_table,
                                lazy=True),
                                #lazy='dynamic'),
        }
    object_class = create_class(object_class_name, super_classes, attrs_dict)
    classes[otype] = {}
    classes[otype]['object'] = object_class
    classes[otype]['attr'] = attr_class
    classes[otype]['acl'] = acl_class

def get_all_tables():
    """ Get all tables with their columns. """
    from sqlalchemy import Table
    from sqlalchemy import inspect
    from sqlalchemy import MetaData
    all_tables = {}
    _index = config.get_index_module()
    engine = _index.get_db_engine()
    metadata = MetaData()
    metadata.reflect(bind=engine)
    inspector = inspect(engine)
    for table_name in inspector.get_table_names():
        table = Table(table_name, metadata, autoload=True)
        columns = [m.key for m in table.columns]
        all_tables[table_name] = {}
        all_tables[table_name]['column_names'] = columns
        all_tables[table_name]['columns'] = table.columns
    return all_tables

def create_db_indices(drop=False, desc=False,
    left_prefix=False, create_trigram_index=False):
    """ Create DB indices. """
    from sqlalchemy import text
    from sqlalchemy.types import VARCHAR
    index_names = []
    all_tables = get_all_tables()
    _index = config.get_index_module()
    session = _index.get_db_connection()
    if create_trigram_index:
        trigram_ext_cmd = "CREATE EXTENSION pg_trgm;"
        try:
            session.execute(trigram_ext_cmd)
        except Exception as e:
            msg = _("Index command failed: {e}")
            msg = msg.format(e=e)
            print(msg)
            session.rollback()
    for table_name in sorted(all_tables):
        columns = list(all_tables[table_name]['columns'])
        #column_names = all_tables[table_name]['column_names']
        for x in list(columns):
            if isinstance(x.type, VARCHAR):
                if x.type.length > 737:
                    columns.remove(x)
        # Remove too long VARCHAR columns.
        column_names = []
        for x in columns:
            if isinstance(x.type, VARCHAR):
                if left_prefix:
                    column_names.append(f"{x.name}(32)")
                else:
                    column_names.append(x.name)
        column_list = ",".join(column_names)
        asc_index_name = f"{table_name}_asc_covering_ix"
        if drop:
            log_msg = _("Removing DB convering index (ASC) for table: {table_name}", log=True)[1]
            log_msg = log_msg.format(table_name=table_name)
            asc_index_cmd = f"DROP INDEX {asc_index_name};"
            asc_index_cmd = text(asc_index_cmd)
        else:
            log_msg = _("Creating DB convering index (ASC) for table: {table_name}", log=True)[1]
            log_msg = log_msg.format(table_name=table_name)
            asc_index_cmd = f"CREATE INDEX {asc_index_name} ON {table_name} ({column_list} ASC);"
            asc_index_cmd = text(asc_index_cmd)
        logger.debug(log_msg)
        #print(asc_index_cmd)
        if asc_index_name in index_names:
            msg = _("Index name already used: {asc_index_name}")
            msg = msg.format(asc_index_name=asc_index_name)
            raise OTPmeException(msg)
        index_names.append(asc_index_name)
        try:
            session.execute(asc_index_cmd)
        except Exception as e:
            msg = _("Index command failed: {e}")
            msg = msg.format(e=e)
            print(msg)
            session.rollback()
            raise OTPmeException(msg)
        finally:
            session.commit()
        if desc:
            desc_index_name = f"{table_name}_desc_covering_ix"
            if drop:
                log_msg = _("Removing DB convering index (DESC) for table: {table_name}", log=True)[1]
                log_msg = log_msg.format(table_name=table_name)
                desc_index_cmd = f"DROP INDEX {desc_index_name};"
                desc_index_cmd = text(desc_index_cmd)
            else:
                log_msg = _("Creating DB convering index (DESC) for table: {table_name}", log=True)[1]
                log_msg = log_msg.format(table_name=table_name)
                desc_index_cmd = f"CREATE INDEX {desc_index_name} ON {table_name} ({column_list} DESC);"
                desc_index_cmd = text(desc_index_cmd)
            if desc_index_name in index_names:
                msg = _("Index name already used: {desc_index_name}")
                msg = msg.format(desc_index_name=desc_index_name)
                raise OTPmeException(msg)
            index_names.append(desc_index_name)
            logger.debug(log_msg)
            #print(desc_index_cmd)
            try:
                session.execute(desc_index_cmd)
            except Exception as e:
                msg = _("Index command failed: {e}")
                msg = msg.format(e=e)
                print(msg)
                session.rollback()
                print(index_names)
                raise OTPmeException(msg)
            finally:
                session.commit()
        for column in columns:
            column_name = column.name
            session = _index.get_db_connection()
            asc_index_name = f"{table_name}_{column_name}_asc_ix"
            if drop:
                msg = _("Removing DB index (ASC) for table: {column_name}")
                msg = msg.format(column_name=column_name)
                asc_index_cmd = f"DROP INDEX {asc_index_name};"
                asc_index_cmd = text(asc_index_cmd)
            else:
                msg = _("Creating DB index (ASC) for table: {column_name}")
                msg = msg.format(column_name=column_name)
                asc_index_cmd = f"CREATE INDEX {asc_index_name} ON {table_name} ({column_name} ASC);"
                asc_index_cmd = text(asc_index_cmd)
            if asc_index_name in index_names:
                msg = _("Index name already used: {asc_index_name}")
                msg = msg.format(asc_index_name=asc_index_name)
                raise OTPmeException(msg)
            index_names.append(asc_index_name)
            try:
                session.execute(asc_index_cmd)
            except Exception as e:
                msg = _("Index command failed: {e}")
                msg = msg.format(e=e)
                print(msg)
                session.rollback()
                print(index_names)
                raise OTPmeException(msg)
            finally:
                session.commit()
            if desc:
                desc_index_name = f"{table_name}_{column_name}_desc_ix"
                if drop:
                    msg = _("Removing DB index (DESC) for table: {column_name}")
                    msg = msg.format(column_name=column_name)
                    desc_index_cmd = f"DROP INDEX {desc_index_name};"
                    desc_index_cmd = text(desc_index_cmd)
                else:
                    msg = _("Creating DB index (DESC) for table: {column_name}")
                    msg = msg.format(column_name=column_name)
                    desc_index_cmd = f"CREATE INDEX {desc_index_name} ON {table_name} ({column_name} DESC);"
                    desc_index_cmd = text(desc_index_cmd)
                if desc_index_name in index_names:
                    msg = _("Index name already used: {desc_index_name}")
                    msg = msg.format(desc_index_name=desc_index_name)
                    raise OTPmeException(msg)
                index_names.append(desc_index_name)
                #print(msg)
                try:
                    session.execute(desc_index_cmd)
                except Exception as e:
                    msg = _("Index command failed: {e}")
                    msg = msg.format(e=e)
                    print(msg)
                    session.rollback()
                    print(index_names)
                    raise OTPmeException(msg)
                finally:
                    session.commit()

            if not create_trigram_index:
                continue

            trgm_index_name = f"{table_name}_{column_name}_trgm_ix"
            if drop:
                msg = _("Removing DB trigram index (ASC) for table: {column_name}")
                msg = msg.format(column_name=column_name)
                asc_index_cmd = f"DROP INDEX {trgm_index_name} ON;"
                asc_index_cmd = text(asc_index_cmd)
            else:
                msg = _("Creating DB trigram index (ASC) for table: {column_name}")
                msg = msg.format(column_name=column_name)
                asc_index_cmd = f"CREATE INDEX CONCURRENTLY {trgm_index_name} ON {table_name} USING gin ({column_name} gin_trgm_ops);"
                asc_index_cmd = text(asc_index_cmd)
            if trgm_index_name in index_names:
                msg = _("Index name already used: {trgm_index_name}")
                msg = msg.format(trgm_index_name=trgm_index_name)
                raise OTPmeException(msg)
            index_names.append(trgm_index_name)
            #print(msg)
            # Trigram index cannot be created within transaction.
            session.execute("COMMIT")
            try:
                session.execute(asc_index_cmd)
            except Exception as e:
                msg = _("Index command failed: {e}")
                msg = msg.format(e=e)
                print(msg)
                print(index_names)
                raise OTPmeException(msg)
