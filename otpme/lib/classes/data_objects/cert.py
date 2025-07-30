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
from otpme.lib.pki.cert import SSLCert
from otpme.lib.typing import match_class_typing

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.realm",
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
    cert_oid_re = ('cert|%s[/]%s[/][a-z0-9]+'
                    % (realm_name_re, site_name_re))
    oid.register_oid_schema(object_type="cert",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=cert_oid_re)
    rel_path_getter = lambda x: x[-1:]
    oid.register_rel_path_getter(object_type="cert",
                                getter=rel_path_getter)

def register_config():
    config.register_object_type(object_type="cert",
                            backend_object=False,
                            object_cache=1024,
                            cache_region="data_object",
                            backup_attributes=['realm', 'site', 'fingerprint'])

@match_class_typing
class OTPmeCert(SSLCert):
    """ Class that implements last used object. """
    def __init__(
        self,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        **kwargs,
        ):
        self.type = "cert"
        self.realm = realm
        self.site = site
        self.pickable = False
        self._modified = False
        self._object_lock = None
        # Call parent class init.
        super(OTPmeCert, self).__init__(**kwargs)
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
