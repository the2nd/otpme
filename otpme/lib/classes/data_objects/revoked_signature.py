# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
from otpme.lib.classes.otpme_object import OTPmeDataObject

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.classes.site"]
REVOKED_DIR = os.path.join(config.data_dir, "data", "revoked_signature")

def register():
    register_oid()
    register_backend()
    register_sync_settings()

def register_oid():
    full_oid_schema = [ 'realm', 'site', 'signer_uuid', 'signature_hash' ]
    read_oid_schema = None
    # OID regex stuff.
    realm_name_re = oid.object_regex['realm']['name']
    site_name_re = oid.object_regex['realm']['name']
    revoked_signature_oid_re = ('revoked_signature|%s[/]%s[/]%s[/][a-f0-9]*'
                            % (realm_name_re, site_name_re, oid.uuid_re))
    oid.register_oid_schema(object_type="revoked_signature",
                            full_schema=full_oid_schema,
                            read_schema=read_oid_schema,
                            oid_regex=revoked_signature_oid_re)
    rel_path_getter = lambda x: x[-2:]
    oid.register_rel_path_getter(object_type="revoked_signature",
                                getter=rel_path_getter)

def register_sync_settings():
    """ Register sync settings. """
    config.register_cluster_sync(object_type="revoked_signature")
    config.register_object_sync(host_type="node", object_type="revoked_signature")
    config.register_object_sync(host_type="host", object_type="revoked_signature")

def register_backend():
    """ Register object for the file backend. """
    path_id = "revoked_signature"
    backend.register_data_dir(name=path_id,
                            path=REVOKED_DIR,
                            drop=True,
                            perms=0o770)
    def oid_getter(path):
        if not path.startswith(REVOKED_DIR):
            return
        x_dir_name = os.path.dirname(path)
        x_dir_name = os.path.dirname(x_dir_name)
        x_dir_name = os.path.basename(x_dir_name)
        if x_dir_name != path_id:
            return
        object_realm = config.realm
        object_site = config.site
        signer_uuid = os.path.dirname(path)
        signer_uuid = os.path.basename(signer_uuid)
        signature_hash = os.path.basename(path)
        object_id = oid.OTPmeOid(object_type="revoked_signature",
                                realm=object_realm,
                                site=object_site,
                                signer_uuid=signer_uuid,
                                signature_hash=signature_hash)
        return object_id
    def path_getter(object_id):
        revoked_signs_dir = backend.get_data_dir(path_id)
        sign_hash = object_id.signature_hash
        signer_uuid = object_id.signer_uuid
        config_dir = os.path.join(revoked_signs_dir, signer_uuid)
        config_dir = os.path.join(config_dir, sign_hash)
        config_file = os.path.join(config_dir, config.object_config_file_name)
        config_paths = {}
        config_paths['config_file'] = config_file
        config_paths['config_dir'] = config_dir
        config_paths['remove_on_delete'] = [config_file]
        config_paths['rmdir_on_delete'] = [config_dir]
        return config_paths
    def index_rebuild():
        revoked_sign_dir = backend.get_data_dir(path_id)
        for user_uuid in filetools.list_dir(revoked_sign_dir):
            if not stuff.is_uuid(user_uuid):
                continue
            revoked_signs_dir = os.path.join(revoked_sign_dir, user_uuid)
            revoked_sign_files = filetools.list_dir(revoked_signs_dir)
            counter = 0
            files_count = len(revoked_sign_files)
            for x in revoked_sign_files:
                counter += 1
                x_path = os.path.join(revoked_signs_dir, x)
                x_file = os.path.join(x_path, config.object_config_file_name)
                msg = ("Processing %s (%s/%s): %s"
                    % (path_id, counter, files_count, x_file))
                logger.debug(msg)
                x_oid = oid_getter(x_path)
                backend.index_add(object_id=x_oid,
                                object_config="auto",
                                full_index_update=True)
    # Register object to config.
    config.register_object_type(object_type="revoked_signature",
                            tree_object=False,
                            uniq_name=False,
                            add_after=["ca"],
                            object_cache=1024,
                            cache_region="data_object")
    # Register index attributes.
    config.register_index_attribute('sign_ref')
    config.register_index_attribute('signer_uuid')
    config.register_index_attribute('revoked_object')
    # Register object to backend.
    class_getter = lambda: RevokedSignature
    backend.register_object_type(object_type="revoked_signature",
                                tree_object=False,
                                class_getter=class_getter,
                                index_rebuild_func=index_rebuild,
                                path_getter=path_getter,
                                oid_getter=oid_getter)

class RevokedSignature(OTPmeDataObject):
    """ Class that implements revoked signature object. """
    def __init__(self, signer=None, signer_uuid=None, sign_tags=None,
        sign_ref=None, signature_hash=None, revoked_object=None,
        revocation_time=None, object_id=None, **kwargs):
        # Set our type (used in parent class).
        self.signer = signer
        self.sign_ref = sign_ref
        self.sign_tags = sign_tags
        self.signer_uuid = signer_uuid
        self.signature_hash = signature_hash
        self.revoked_object = revoked_object
        self.revocation_time = revocation_time
        self.type = "revoked_signature"

        # Call parent class init.
        super(RevokedSignature, self).__init__(object_id=object_id, **kwargs)

        self._sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "SIGNER",
                            "SIGN_REF",
                            "SIGN_TAGS",
                            "SIGNER_UUID",
                            "SIGNATURE_HASH",
                            "REVOKED_OBJECT",
                            "REVOCATION_TIME",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "SIGNER",
                            "SIGN_REF",
                            "SIGN_TAGS",
                            "SIGNER_UUID",
                            "SIGNATURE_HASH",
                            "REVOKED_OBJECT",
                            "REVOCATION_TIME",
                            ]
                        },
                    }


    def _get_object_config(self):
        """ Get object config dict. """
        object_config = {
                        'SIGNER'                    : {
                                                        'var_name'  : 'signer',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'SIGN_REF'                  : {
                                                        'var_name'  : 'sign_ref',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        'SIGN_TAGS'                 : {
                                                        'var_name'  : 'sign_tags',
                                                        'type'      : list,
                                                        'required'  : False,
                                                    },
                        'SIGNER_UUID'                 : {
                                                        'var_name'  : 'signer_uuid',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        'SIGNATURE_HASH'            : {
                                                        'var_name'  : 'signature_hash',
                                                        'type'      : str,
                                                        'required'  : True,
                                                    },
                        'REVOKED_OBJECT'            : {
                                                        'var_name'  : 'revoked_object',
                                                        'type'      : 'uuid',
                                                        'required'  : True,
                                                    },
                        'REVOCATION_TIME'           : {
                                                        'var_name'  : 'revocation_time',
                                                        'type'      : float,
                                                        'required'  : True,
                                                    },
                        }

        return object_config

    def set_oid(self):
        """ Set our OID. """
        self.oid = oid.get(object_type=self.type,
                            realm=self.realm,
                            site=self.site,
                            signer_uuid=self.signer_uuid,
                            signature_hash=self.signature_hash)

    def add(self):
        """ Add the object. """
        # Add object reference UUIDs to index.
        if self.signer_uuid:
            self.add_index('signer_uuid', self.signer_uuid)
        if self.sign_ref:
            self.add_index('sign_ref', self.sign_ref)
        if self.revoked_object:
            self.add_index('revoked_object', self.revoked_object)
        # Call base class add method.
        return super(RevokedSignature, self).add()
