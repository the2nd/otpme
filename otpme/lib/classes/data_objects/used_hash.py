# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib.typing import match_class_typing
from otpme.lib.classes.otpme_object import OTPmeDataObject

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                ]

def register():
    register_backend()

def register_backend():
    # Register index attributes.
    config.register_index_attribute('user_uuid')
    config.register_index_attribute('token_uuid')

@match_class_typing
class UsedHash(OTPmeDataObject):
    """ Class that implements used hashes object. """
    def __init__(
        self,
        user_uuid: Union[str,None]=None,
        token_uuid: Union[str,None]=None,
        accessgroup_uuid: Union[str,None]=None,
        session_uuid: Union[str,None]=None,
        object_hash: Union[str,None]=None,
        counter: Union[int,None]=None,
        sync_time: Union[float,None]=None,
        expiry: Union[float,None]=None,
        object_id: Union[oid.OTPmeOid,None]=None,
        **kwargs,
        ):
        # Set our type (used in parent class).
        self.user_uuid = user_uuid
        self.token_uuid = token_uuid
        self.session_uuid = session_uuid
        self.accessgroup_uuid = accessgroup_uuid
        self.sync_time = sync_time
        self.object_hash = object_hash
        self.expiry = expiry
        self.counter = counter

        # Call parent class init.
        super(UsedHash, self).__init__(object_id=object_id, **kwargs)

    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'USER_UUID'                 : {
                                                        'var_name'  : 'user_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'TOKEN_UUID'                : {
                                                        'var_name'  : 'token_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'SESSION_UUID'              : {
                                                        'var_name'  : 'session_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'ACCESSGROUP_UUID'          : {
                                                        'var_name'  : 'accessgroup_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : False,
                                                    },
                        'OBJECT_HASH'                 : {
                                                        'var_name'  : 'object_hash',
                                                        'type'      : str,
                                                        'required'  : True,
                                                        'encryption': config.disk_encryption,
                                                    },
                        'COUNTER'                   : {
                                                        'var_name'  : 'counter',
                                                        'type'      : int,
                                                        'required'  : False,
                                                        'encryption': config.disk_encryption,
                                                    },
                        'SYNC_TIME'                 : {
                                                        'var_name'  : 'sync_time',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        'EXPIRY'                    : {
                                                        'var_name'  : 'expiry',
                                                        'type'      : float,
                                                        'required'  : False,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.OTPmeOid(object_type=self.type,
                                realm=self.realm,
                                site=self.site,
                                user_uuid=self.user_uuid,
                                token_uuid=self.token_uuid,
                                accessgroup_uuid=self.accessgroup_uuid,
                                object_hash=self.object_hash)

    def add(self):
        """ Add the object. """
        # Add object reference UUIDs to index.
        if self.user_uuid:
            self.add_index('user_uuid', self.user_uuid)
        if self.token_uuid:
            self.add_index('token_uuid', self.token_uuid)
        if self.accessgroup_uuid:
            self.add_index('accessgroup_uuid', self.accessgroup_uuid)
        if self.session_uuid:
            self.add_index('session_uuid', self.session_uuid)
        if self.expiry:
            self.add_index('expiry', self.expiry)
        # Call base class add method.
        return super(UsedHash, self).add()
