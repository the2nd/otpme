# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import pprint

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import sign_key_cache
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.classes.data_objects.revoked_signature import RevokedSignature

from otpme.lib.exceptions import *

logger = config.logger
#register_module("otpme.lib.classes.data_objects.revoked_signature")

def hash_sign_data(sign_data):
    """ Create sign data hash. """
    data_hash = stuff.gen_md5(sign_data)
    return data_hash

def resolve_tags(tags, from_uuid=True):
    """ Resolve tags from UUID to OID and reverse. """
    object_tags = {}
    # Make sure we do not modify tags list we got.
    tags = list(tags)
    for tag in list(tags):
        object_id = None
        object_uuid = None
        if not from_uuid:
            if oid.is_oid(tag):
                object_id = oid.get(tag)
                object_type = object_id.object_type

        if not object_id:
            try:
                object_type = tag.split(":")[0]
                object_xxx = tag.split(":")[1]
            except:
                continue

        if object_type not in config.tree_object_types:
            continue

        try:
            x_list = object_tags[object_type]
        except:
            x_list = []

        if from_uuid:
            if not stuff.is_uuid(object_xxx):
                msg = "Invalid tag: %s" % tag
                raise InvalidTag(msg)
            try:
                object_id = stuff.resolve_uuid(object_xxx)
            except UnknownUUID as e:
                x_list.append(object_xxx)
            else:
                x_list.append(object_id.full_oid)
        else:
            if not object_id:
                result = stuff.search(object_type=object_type,
                                        attribute="name",
                                        value=object_xxx,
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="full_oid")
                if not result:
                    continue
                object_id = result[0]
                object_id = oid.get(object_id)
            object_uuid = stuff.resolve_oid(object_id)
            tag_str = "%s:%s" % (object_type, object_uuid)
            x_list.append(tag_str)
        # abc
        tags.remove(tag)
        object_tags[object_type] = x_list

    # Sort object tags by object type.
    sorted_tags = []
    for object_type in config.tree_object_types:
        try:
            x_list = object_tags[object_type]
        except:
            continue
        sorted_tags += x_list
    sorted_tags += tags

    return sorted_tags

def get_signers(signer_type, username=None):
    """ Get signers configured for this host. """
    from otpme.lib.classes.command_handler import CommandHandler
    command_handler = CommandHandler(interactive=False)

    global_signers = command_handler.get_signers(signer_type=signer_type,
                                                    private=False)
    if username is None:
        return global_signers

    force_signers_mapping = {
                            'token'         : "force_token_signers",
                            'key_script'    : "force_key_script_signers",
                            'agent_script'  : "force_agent_script_signers",
                        }
    try:
        force_signers_var = force_signers_mapping[signer_type]
        force_signers_para = config.find_conf_para_by_var(force_signers_var)
        force_signers_attr = getattr(config, force_signers_var)
        force_global_signers = True
    except:
        force_signers_attr = None
        force_global_signers = False

    if force_signers_attr == False:
        force_global_signers = False
    elif isinstance(force_signers_attr, list):
        if username is not None:
            if username not in force_signers_attr:
                force_global_signers = False

    private_signers = None
    if signer_type in config.valid_private_signer_types:
        private_signers = command_handler.get_signers(signer_type=signer_type,
                                                    private=True,
                                                    username=username)
    signers = global_signers
    if force_global_signers:
        if private_signers:
            msg = ("Ignoring private signers because of %s config file option."
                    % force_signers_para)
            logger.info(msg)
    else:
        if private_signers:
            signers = private_signers

    for signer in list(signers):
        if not signer.enabled:
            msg = ("Ignoring disabled signer: %s" % signer.object_oid)
            logger.debug(msg)
            signers.remove(signer)
            continue

    return signers

def verify_signatures(signer_type, signers, signatures, sign_data,
    stop_on_fist_match=False):
    """
    Verify given signatures/data with the signers configured for this host.
    """
    found_valid_signature = False
    for signer_uuid in signatures:
        if found_valid_signature:
            if stop_on_fist_match:
                break
        for sign_id in signatures[signer_uuid]:
            signature = signatures[signer_uuid][sign_id]['signature']
            sig = OTPmeSignature(signature=signature)
            if found_valid_signature:
                if stop_on_fist_match:
                    break
            for signer in signers:
                # Only verify signers/signatures that match.
                if sig.signer_uuid not in signer.signers:
                    continue

                sign_info = sig.signer_oid
                try:
                    signer.verify_signature(signature=sig,
                                            sign_data=sign_data,
                                            login_interface="ssh")
                except VerificationFailed as e:
                    msg = (_("Failed to verify signature: %s: %s")
                            % (sign_info, e))
                    logger.warning(msg)
                    continue
                except NoTagsMatch as e:
                    msg = (_("Ignoring signature: %s: %s")
                            % (sign_info, e))
                    logger.debug(msg)
                    continue
                except Exception as e:
                    config.raise_exception()
                    msg = (_("Error verifying signature: %s: %s")
                            % (sign_info, e))
                    logger.warning(msg)
                    continue
                found_valid_signature = True
                if stop_on_fist_match:
                    break

    if not found_valid_signature:
        msg = "No valid signature found."
        raise OTPmeException(msg)


class OTPmeSigner(object):
    """ OTPme signer class. """
    # Object types that can be used get
    # public keys to verify signatures.
    supported_signers = [
                            'user',
                            'role',
                            ]
    # Object types that can be signed.
    supported_signer_types = [
                                'token',
                                'key_script',
                                'push_script',
                                'auth_script',
                                'login_script',
                                'agent_script',
                                ]

    def __init__(self, uuid=None, object_uuid=None,
        signer_type=None, pinned=False, tags=None):
        # Handle UUID.
        if not uuid:
            uuid = stuff.gen_uuid()
        if not stuff.is_uuid(uuid):
            msg = "Invalid UUID: %s" % uuid
            raise OTPmeException(msg)

        # Get logger.
        self.logger = config.logger
        self.uuid = uuid
        self.enabled = True

        # The signer object UUID.
        self.object_uuid = object_uuid
        # The signer object OID.
        self.object_oid = None
        # The signer type (e.g. token or auth_script).
        self.signer_type = signer_type
        # Tags of this signer.
        self.tags = tags
        # Indicates that the signer is pinned (e.g. inclues public key).
        self.pinned = pinned

        # All signers with public keys.
        self.signers = {}
        # Attributes for loads()/dumps().
        self._attributes = [
                            'uuid',
                            'tags',
                            'pinned',
                            'enabled',
                            'object_uuid',
                            'signer_type',
                        ]

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __str__(self):
        tags = None
        if self.object_oid is not None:
            tags = ",".join(self.tags)
        msg = ("OTPmeSigner(type=%s, object_oid=%s, tags=%s)"
            % (self.signer_type, self.object_oid, tags))
        return msg

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def __ne__(self, other):
        return self.__str__() != other.__str__()

    def __lt__(self, other):
        self_str = self.__str__()
        other_str = other.__str__()
        x = [self_str, other_str]
        x = sorted(x)
        if x[0] == self_str:
            return True
        return False

    def replace(self, s, r):
        return self.__str__().replace(s, r)

    def enable(self):
        """ Enable signer. """
        self.enabled = True

    def disable(self):
        """ Disable signer. """
        self.enabled = False

    def load(self):
        """ Load signer(s). """
        msg = "Loading signer..."
        self.logger.debug(msg)

        if not stuff.is_uuid(self.object_uuid):
            msg = (_("Invalid signer UUID: %s") % self.uuid)
            raise UnknownObject(msg)

        if self.signer_type not in self.supported_signer_types:
            msg = "Invalid signer type: %s" % (self.signer_type)
            raise OTPmeException(msg)

        # Get OID
        try:
            object_id = stuff.resolve_uuid(self.object_uuid)
        except UnknownUUID as e:
            msg = (_("Unknown object: %s") % (self.object_uuid))
            raise UnknownObject(msg)
        except Exception as e:
            msg = (_("Unable to resolve UUID to OID: %s: %s")
                    % (self.object_uuid, e))
            raise UnknownObject(msg)

        if not object_id:
            msg = ("Unknown user/role: %s" % self.uuid)
            raise UnknownObject(msg)

        self.object_oid = object_id

        # Check object type.
        object_type = object_id.object_type
        if object_type not in self.supported_signers:
            msg = (_("Got unknown signer type: %s") % object_type)
            raise OTPmeException(msg)

        # For users we are done here.
        if object_type == "user":
            public_key = self.get_signer_key(self.object_uuid)
            signer = {
                        'oid'           : object_id.full_oid,
                        'uuid'          : self.object_uuid,
                        'public_key'    : public_key,
                    }
            self.signers[self.object_uuid] = signer
            return

        # For roles we have to check each member.
        role_members = self.get_role_members(object_id)
        for x_uuid in role_members:
            x_oid = role_members[x_uuid]
            try:
                x_key = self.get_signer_key(x_uuid)
            except:
                # Ignore users without public key.
                continue
            signer = {
                        'oid'           : x_oid.full_oid,
                        'uuid'          : x_uuid,
                        'public_key'    : x_key,
                    }
            self.signers[x_uuid] = signer

        msg = ("Loaded %s users from role: %s"
            % (len(role_members), object_id))
        self.logger.debug(msg)

    def loads(self, data):
        """ Load signer from string. """
        # Decode signer.
        try:
            signer_dict = json.decode(data, "base64")
        except Exception as e:
            msg = (_("Found faulty signer"))
            raise OTPmeException(msg)
        # Get data from signer info.
        for attr in self._attributes:
            if not attr in signer_dict:
                msg =(_("Signer data misses attribute: %s") % attr)
                raise OTPmeException(msg)
            # Set value.
            value = signer_dict[attr]
            setattr(self, attr, value)

        object_oid = signer_dict['object_oid']
        object_oid = oid.get(object_id=object_oid)
        self.object_oid = object_oid

        # Load signers if pinned.
        if not self.pinned:
            return
        self.signers = signer_dict['signers']

    def dumps(self):
        """ Dump signer. """
        dump_data = {}
        for attr in self._attributes:
            value = getattr(self, attr)
            dump_data[attr] = value
        dump_data['object_oid'] = self.object_oid.full_oid
        if self.pinned:
            dump_data['signers'] = self.signers
        signer_string = json.encode(data=dump_data,
                                    encoding="base64")
        return signer_string

    def get_sign_info(self):
        """ Resolve UUIDs to object OIDs. """
        sign_info = {}
        uuid_attributes = [
                            'object_uuid',
                        ]

        for x in self._attributes:
            if x in uuid_attributes:
                uuid = getattr(self, x)
                try:
                    object_id = stuff.resolve_uuid(uuid)
                except UnknownUUID as e:
                    sign_info[x] = uuid
                else:
                    sign_info[x] = object_id.full_oid
                continue

            if x != "tags":
                continue

            tags = resolve_tags(self.tags)
            sign_info[x] = tags

        return sign_info

    def check_outdated(self, uuid=None):
        """
        Check if the signer object or the key of the given
        signer is outdated.
        """
        unknown_val = "unknown"
        removed_val = "removed"
        outdated_val = "outdated"
        # Get copy of this signer object to update and compare.
        c_signer = self.__class__(object_uuid=self.object_uuid,
                                signer_type=self.signer_type,
                                pinned=self.pinned,
                                tags=self.tags)
        # Try to load copy of signer. This will resolve sigern UUIDs etc.
        # and will fail if the signer does not exist anymore.
        try:
            c_signer.load()
        except UnknownObject as e:
            msg = "Unable to load object: %s" % e
            self.logger.warning(msg)
            config.raise_exception()
            return unknown_val

        # FIXME: check if siger role/user does not exist anymore!!!!
        # Check if signer object (e.g. role) itself is outdated.
        if not uuid:
            object_outdated = False
            if self != c_signer:
                object_outdated = True
            # Only pinned signers include signers (role members).
            if self.pinned:
                if self.signers != c_signer.signers:
                    object_outdated = True
            if object_outdated:
                return outdated_val
            return False

        # Check if signer key is outdated.
        try:
            x_signer_key = self.signers[uuid]['public_key']
        except:
            msg = "Invalid signer UUID: %s" % uuid
            raise OTPmeException(msg)

        if uuid not in c_signer.signers:
            return removed_val

        c_signer_key = c_signer.signers[uuid]['public_key']
        if x_signer_key != c_signer_key:
            return outdated_val

        return False

    def get_signer_key(self, uuid):
        """ Get signer public key. """
        # Try to get cached signing key.
        cached_pkey = sign_key_cache.get_cache(user_uuid=uuid)
        if not cached_pkey:
            msg = (_("No signing key found."))
            raise OTPmeException(msg)
        return cached_pkey

    def get_role_members(self, object_id):
        """ Get role members. """
        # For roles we need to get its members.
        from otpme.lib.classes.command_handler import CommandHandler
        role_members = {}
        role_name = object_id.name
        if config.use_backend:
            r = backend.get_object(object_id=object_id)
            for user_uuid in r.get_token_users(return_type="uuid"):
                user_oid = backend.get_oid(user_uuid,
                                        object_type="user",
                                        instance=True)
                if not user_oid:
                    continue
                role_members[user_uuid] = user_oid
        else:
            command_handler = CommandHandler(interactive=False)
            # FIXME: how to make sure to get role users from correct site???
            for x in command_handler.get_role_users(role_name=role_name,
                                                    return_type="uuid"):
                user_oid = stuff.resolve_uuid(x)
                if not user_oid:
                    continue
                role_members[x] = user_oid

        return role_members

    def verify_signature(self, signature, sign_data,
        tags=None, login_interface=None):
        """ Verify signature. """
        if signature.signer_uuid not in self.signers:
            msg = "Signature not singed by this signer."
            raise VerificationFailed(msg)

        # Verify signature data (hash).
        sign_data_hash = hash_sign_data(sign_data)
        if signature.sign_data != sign_data_hash:
            msg = ("Sinature data mismatch: %s" % signature.signer_oid)
            raise VerificationFailed(msg)

        # Get signer key etc.
        entry = self.signers[signature.signer_uuid]
        object_oid = entry['oid']
        signer_key = entry['public_key']

        # Make sure we add additional tags to check for.
        check_tags = list(self.tags)
        if tags:
            for x in tags:
                if x in check_tags:
                    continue
                check_tags.append(x)

        tags = resolve_tags(signature.tags)
        tags_str = ", ".join(tags)
        msg = ("Verifying signature: %s (%s)"
                % (object_oid, tags_str))
        self.logger.debug(msg)

        signature.verify(signer_key,
                        sign_data,
                        tags=check_tags,
                        login_interface=login_interface)

        msg = ("Found valid signature: %s (%s)"
                % (object_oid, tags_str))
        self.logger.debug(msg)

class OTPmeSignature(object):
    """ OTPme signature class. """
    def __init__(self, signature=None, signer_uuid=None,
        signer_oid=None, sign_obj=None, sign_data=None,
        tags=None, sign_ref=None):
        """ Init. """
        if not signature and not tags:
            msg = "Need <tags>."
            raise OTPmeException(msg)

        # Get logger.
        self.logger = config.logger

        self.uuid = stuff.gen_uuid()

        # The signer UUID.
        self.signer_uuid = signer_uuid
        # The signer OID.
        self.signer_oid = signer_oid
        # Tags of this signature.
        self.tags = tags
        # The object UUID this signature belongs to (e.g. script).
        self.sign_obj = sign_obj
        # The object UUID this signature was created for
        # (e.g. role, token, script).
        self.sign_ref = sign_ref
        # The data to be signed (e.g. script or SSH public key).
        self.sign_data = None
        # The RSA signature data.
        self.signature = None

        # Create signature ID.
        if self.tags:
            # Sort tags (needed for sign ID).
            self.tags.sort()
            self.sign_id = stuff.gen_md5(",".join(self.tags))

        # Generate sign data hash.
        if sign_data:
            sign_data_hash = hash_sign_data(sign_data)
            self.sign_data = sign_data_hash


        # Attributes added to the sign template.
        self._attributes = [
                            'uuid',
                            'tags',
                            'sign_id',
                            'sign_obj',
                            'sign_ref',
                            'signer_uuid',
                        ]
        if signature:
            self.loads(signature)

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __str__(self):
        return self.uuid

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def __ne__(self, other):
        return self.__str__() != other.__str__()

    def replace(self, s, r):
        return self.__str__().replace(s, r)

    def loads(self, signature):
        """ Load signature. """
        msg = "Loading signature..."
        self.logger.debug(msg)
        # Decode signature.
        try:
            sig = json.decode(signature, "base64")
            sign_info = sig['sign_info']
            self.signature = sig['signature']
            self.signer_oid = sig['signer_oid']
            self.sign_data = sig['sign_data']
        except Exception as e:
            config.raise_exception()
            msg = (_("Found faulty signature"))
            raise OTPmeException(msg)
        # Get data from signature info.
        for attr in self._attributes:
            if not attr in sign_info:
                msg =(_("Signature data misses attribute: %s") % attr)
                raise OTPmeException(msg)
            # Set value.
            value = sign_info[attr]
            setattr(self, attr, value)

    def dumps(self):
        """ Dump signature. """
        template = self.build_sign_template()
        dump_data = {
                        'sign_info'     : template,
                        'sign_data'     : self.sign_data,
                        'signature'     : self.signature,
                        'signer_oid'    : self.signer_oid,
                    }
        sign_string = json.encode(data=dump_data,
                                encoding="base64")
        return sign_string

    def get_sign_info(self):
        """ Resolve UUIDs from signature and tags to object OIDs. """
        sign_info = self.build_sign_template()

        uuid_attributes = [
                            'sign_obj',
                            'sign_ref',
                            'signer_uuid',
                        ]

        for x in dict(sign_info):
            if x in uuid_attributes:
                uuid = sign_info[x]
                if uuid is None:
                    continue
                try:
                    object_id = stuff.resolve_uuid(uuid)
                except UnknownUUID as e:
                    sign_info[x] = uuid
                else:
                    sign_info[x] = object_id.full_oid
                continue

            if x != "tags":
                continue

            tags = resolve_tags(self.tags)
            sign_info[x] = tags

        return sign_info

    def add_sign(self, data):
        """ Add signature data. """
        try:
            self.get_sign_info()
        except InvalidTag as e:
            msg = "Unable to add signature data: %s" % e
            raise e(msg)
        except Exception as e:
            msg = "Unknown error adding signature data: %s" % e
            raise e(msg)
        self.signature = data

    def revoke(self):
        """ Revoke this signature. """
        tags_str = resolve_tags(self.tags)
        tags_str = ", ".join(tags_str)
        msg = ("Revoking signature: %s (%s)" % (self.signer_oid, tags_str))
        self.logger.debug(msg)
        # Get signature hash.
        signature_hash = self.get_sign_hash()
        # Build revoked object.
        revoked_signature = RevokedSignature(signer=self.signer_oid,
                                            sign_ref=self.sign_ref,
                                            sign_tags=self.tags,
                                            signer_uuid=self.signer_uuid,
                                            signature_hash=signature_hash,
                                            revoked_object=self.sign_obj,
                                            revocation_time=time.time(),
                                            realm=config.realm,
                                            site=config.site)
        # Write revocation object.
        try:
            revoked_signature.add()
        except Exception as e:
            msg = (_("Error writing signature revocation object: %s") % e)
            raise OTPmeException(msg)

    def get_sign_template(self):
        """ Return sign template as json/base64 string. """
        sign_template = self.build_sign_template()
        sign_template = json.encode(data=sign_template,
                                    sort_keys=True,
                                    encoding="base64")
        return sign_template

    def get_sign_hash(self):
        """ Build signature hash for OID. """
        # Build hash of signature.
        sign_dump = self.dumps()
        signature_hash = stuff.gen_md5(sign_dump)
        return signature_hash

    def build_sign_template(self):
        """ Build JSON sign template with given tags. """
        sign_template = {
                    'sign_id'       : self.sign_id,
                    'tags'          : list(self.tags),
                    'uuid'          : self.uuid,
                    'sign_obj'      : self.sign_obj,
                    'sign_ref'      : self.sign_ref,
                    'signer_uuid'   : self.signer_uuid,
                    'sign_data'     : self.sign_data,
                    }
        return sign_template

    def build_revocation_oid(self):
        """ Build signature revocation OID. """
        # Build revocation OID.
        signature_hash = self.get_sign_hash()
        object_id = oid.get(object_type="revoked_signature",
                            realm=config.realm,
                            site=config.site,
                            signer_uuid=self.signer_uuid,
                            signature_hash=signature_hash)
        return object_id

    def check_revoked(self):
        """ Check if signature was revoked. """
        sign_oid = self.build_revocation_oid()
        if not stuff.object_exists(sign_oid):
            return
        msg = "Signature revoked."
        raise OTPmeException(msg)

    def check_tags(self, tags, login_interface=None):
        """ Check if given tags match signature tags. """
        # Get login interface tags.
        login_interfaces = []
        # Create copy of signature tags to be modified while verifying.
        # We need this below when removing the login_interfaces tag.
        verify_tags = list(self.tags)
        found_login_interface_tag = False
        duplicate_login_interfaces_tag = False
        for x in list(verify_tags):
            if not x.startswith("login_interfaces:"):
                continue
            if found_login_interface_tag:
                duplicate_login_interfaces_tag = True
                break
            found_login_interface_tag = True
            login_interface_tag = x
            login_interfaces = login_interface_tag.split(":")[1:]
            verify_tags.remove(x)

        if duplicate_login_interfaces_tag:
            msg = (_("Ignoring invalid signature: More than one "
                    "login_interfaces tag found."))
            raise OTPmeException(msg)

        if login_interfaces:
            login_interface_neg = "-%s" % login_interface
            if login_interface_neg in login_interfaces:
                msg = (_("Ignoring signature: Login interface "
                    "denied by signature tag: %s") % login_interface_tag)
                raise OTPmeException(msg)
            if login_interface not in login_interfaces:
                msg = (_("Ignoring signature: Login interface not "
                    "allowed by signature tag: %s") % login_interface_tag)
                raise OTPmeException(msg)

        # Sort tags.
        verify_tags.sort()

        # Check if the signature includes all the requested tags.
        checked_tags = []
        found_valid_sign_tags = True
        for tag in tags:
            checked_tags.append(tag)
            if tag not in verify_tags:
                found_valid_sign_tags = False

        if checked_tags and not found_valid_sign_tags:
            msg = ("Signature tags do not match: %s" % ",".join(checked_tags))
            raise NoTagsMatch(msg)

    def verify_signature(self, public_key):
        """ Verify signature. """
        # Check if signature was revoked.
        self.check_revoked()
        # Load users public key.
        try:
            key = decode(public_key, "base64")
            key = RSAKey(key=key)
        except Exception as e:
            msg = ("Unable to load public key: %s" % e)
            raise InvalidPublicKey(msg)

        # Verify signature.
        sign_template = self.get_sign_template()
        try:
            signature = decode(self.signature, "base64")
        except Exception as e:
            msg = ("Unable to decode signature: %s" % e)
            raise FaultySignature(msg)

        try:
            verify_status = key.verify(signature, sign_template)
        except Exception as e:
            msg = ("Ignoring faulty signature: %s" % e)
            raise FaultySignature(msg)

        if not verify_status:
            msg = "Invalid signature."
            raise VerificationFailed(msg)

    def verify(self, public_key, sign_data, tags=None, login_interface=None):
        """ Verify signature and tags. """
        # FIXME: how to handle signature check cache?
        ## Check cache.
        #cache_result = self.verify_sign_cache(check_signers,
        #                                    description=description)
        #if cache_result != None:
        #    return cache_result

        # Verify signature data (hash).
        sign_data_hash = hash_sign_data(sign_data)
        if self.sign_data != sign_data_hash:
            msg = ("Sinature data mismatch: %s" % self.signer_oid)
            raise VerificationFailed(msg)

        if tags:
            self.check_tags(tags, login_interface=login_interface)
        self.verify_signature(public_key)
