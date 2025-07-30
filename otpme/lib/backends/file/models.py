# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>

from sqlalchemy.types import TypeDecorator

from otpme.lib import config

class JsonEncodedData(TypeDecorator):
    """Enables JSON storage by encoding and decoding on the fly."""
    if config.index_type == "mysql":
        from sqlalchemy.types import TEXT
        impl = TEXT
    else:
        from sqlalchemy.types import VARCHAR
        impl = VARCHAR
    cache_ok = False
    def process_bind_param(self, value, dialect):
        try:
            import simdjson as json
        except:
            try:
                import ujson as json
            except:
                import json
        if value is None:
            return ''
        json_string = json.dumps(value)
        return json_string

    def process_result_value(self, value, dialect):
        try:
            import simdjson as json
        except:
            try:
                import ujson as json
            except:
                import json
        if value is None:
            return
        if value == '':
            return
        try:
            raw_value = json.loads(value)
        except Exception as e:
            msg = "Failed to load JSON value: %s" % e
            config.logger.warning(msg)
            return
        return raw_value

class IndexObject(object):
    """ Index object. """
    # Import here to reduce import time.
    from datetime import datetime
    #from sqlalchemy import Float
    #from sqlalchemy import Text
    from sqlalchemy import Column
    from sqlalchemy import Integer
    from sqlalchemy import String
    from sqlalchemy import Boolean
    from sqlalchemy.dialects.mysql import LONGTEXT
    #from sqlalchemy.dialects.postgresql import TEXT
    #from sqlalchemy.orm import relationship
    # Primary ID.
    id = Column(Integer, primary_key=True)
    # Realm/site this object is from.
    realm = Column(String(256), unique=False, nullable=False, index=False)
    site = Column(String(256), unique=False, nullable=True, index=False)
    # Objects UUID.
    uuid = Column(JsonEncodedData(256), unique=False, nullable=False, index=False)
    # Objects OTPme OID.
    full_oid = Column(String(512), unique=False, nullable=False, index=False)
    # Objects OTPme read OID.
    read_oid = Column(String(512), unique=False, nullable=False, index=False)
    # Object type (e.g. realm, user, token ...)
    object_type = Column(String(256), unique=False, nullable=False, index=False)
    # Object name.
    name = Column(String(256), unique=False, nullable=True, index=False)
    # Objects full path (e.g. /realm/site/Users/root)
    path = Column(String(512), unique=False, nullable=False, index=False)
    # Objects relative path (e.g. Users/root)
    rel_path = Column(String(512), unique=False, nullable=True, index=False)
    # Objects filesystem paths (e.g. config_file, used_dir etc.)
    fs_paths = Column(String(2048), unique=False, nullable=False, index=False)
    # Objects checksum.
    checksum = Column(String(128), unique=False, nullable=False, index=False)
    # Objects sync checksum.
    sync_checksum = Column(String(128), unique=False, nullable=False, index=False)
    # Last modified timestamp of index object.
    last_modified = Column(Integer, index=False)
    # Last used timestamp of index object.
    last_used = Column(Integer, index=False)
    # Indicates this is a template object.
    template = Column(Boolean, default=False, index=False)
    # Objects LDIF.
    if config.index_type == "mysql":
        ldif = Column(LONGTEXT(), unique=False, nullable=True, index=False)
    else:
        ldif = Column(String(10485760), unique=False, nullable=True, index=False)

    def __repr__(self):
        import pprint
        _repr_ = pprint.pformat(self.__dict__)
        return _repr_

    def __str__(self):
        return self.__repr__()

class IndexObjectAttribute(object):
    """ Index object attributes. """
    from sqlalchemy import Column
    from sqlalchemy import String
    from sqlalchemy import Integer
    #from sqlalchemy import ForeignKey
    # Primary ID.
    id = Column(Integer, primary_key=True)
    # Realm/site of index object this attributes belong to.
    realm = Column(String(128), unique=False, nullable=False, index=False)
    site = Column(String(128), unique=False, nullable=True, index=False)
    # Attribute name (e.g. uidNumber)
    name = Column(String(512), unique=False, nullable=False, index=False)
    # Attribute value.
    value = Column(JsonEncodedData(1024000), unique=False, nullable=False, index=False)
    # Object type of the object this attributes belong to.
    object_type = Column(String(128), unique=False, nullable=False, index=False)

    def __repr__(self):
        _repr_ = ("<IndexObjectAttribute (realm='%s', site='%s', name='%s', "
                "value='%s', object_type='%s')>"
                % (self.realm,
                self.site,
                self.name,
                self.value,
                self.object_type))
        return _repr_

    def __str__(self):
        return self.__repr__()

class IndexObjectACL(object):
    """ Index object ACL. """
    from sqlalchemy import Column
    from sqlalchemy import String
    from sqlalchemy import Integer
    #from sqlalchemy import ForeignKey
    # Primary ID.
    id = Column(Integer, primary_key=True)
    # Realm/site of index object this ACL belong to.
    realm = Column(String(128), unique=False, nullable=False, index=False)
    site = Column(String(128), unique=False, nullable=True, index=False)
    # ACL apply ID (e.g. enable:offline)
    value = Column(String(128), unique=False, nullable=False, index=False)
    # Object type of the object this attributes belong to.
    object_type = Column(String(128), unique=False, nullable=False, index=False)

    def __repr__(self):
        _repr_ = ("<IndexObjectACL (realm='%s', site='%s', value='%s', "
                "object_type='%s')>"
                % (self.realm,
                self.site,
                self.value,
                self.object_type))
        return _repr_

    def __str__(self):
        return self.__repr__()
