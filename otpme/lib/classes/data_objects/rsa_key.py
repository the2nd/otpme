# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.typing import match_class_typing

from otpme.lib.exceptions import *

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.site",
                ]

def register():
    register_oid()
    register_config()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'fingerprint' ]
    read_oid_schema = [ 'realm', 'fingerprint' ]
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    rsa_key_oid_re = ('rsa_key|%s[/]%s[/][a-z0-9]+'
                    % (realm_name_re, site_name_re))
    oid.register_oid_schema(object_type="rsa_key",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=rsa_key_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="rsa_key",
                                getter=rel_path_getter)

def register_config():
    config.register_object_type(object_type="rsa_key",
                            backend_object=False,
                            object_cache=1024,
                            cache_region="data_object")

@match_class_typing
class OTPmeRSAKey(RSAKey):
    """ Class that implements cacheable OTPme RSA key. """
    def __init__(
        self,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        **kwargs,
        ):
        if not realm:
            msg = "Need <realm>."
            raise OTPmeException(msg)
        if not site:
            msg = "Need <site>."
            raise OTPmeException(msg)
        self.type = "rsa_key"
        self.realm = realm
        self.site = site
        self.pickable = False
        self._modified = False
        self._object_lock = None
        # Call parent class init.
        super(OTPmeRSAKey, self).__init__(**kwargs)
        self.set_oid()

    @property
    def checksum(self):
        return self.fingerprint()

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.OTPmeOid(object_type=self.type,
                                realm=self.realm,
                                site=self.site,
                                fingerprint=self.fingerprint())
