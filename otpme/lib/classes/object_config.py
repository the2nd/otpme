# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
# NOTE: Its important to use the same JSON module on each host
#       when generating the checksums, so we do not use otpme.lib.json.
import simdjson as json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import re
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.encryption import get_module

from otpme.lib.exceptions import *

class ObjectConfig(object):
    """ Handle object config encryption etc.. """
    def __init__(self, object_id, object_config=None, encrypted=True, **kwargs):
        if object_config is None:
            object_config = {}
        self.object_id = object_id
        self.encrypted = encrypted
        self.deleted_attributes = []
        self.modified_attributes = []
        if self.encrypted:
            self.encrypted_config = dict(object_config)
            self.decrypted_config = {}
        else:
            self.encrypted_config = {}
            self.decrypted_config = dict(object_config)
        super().__init__(**kwargs)

    def __setitem__(self, key, item):
        self.add(key, item)

    def __getitem__(self, key):
        return self.get(key)

    def __repr__(self):
        return repr(self.__dict__)

    def __len__(self):
        return len(self.decrypted_config)

    def __delitem__(self, key):
        self.delete(key)

    def clear(self):
        self.encrypted_config = {}
        self.decrypted_config = {}

    def copy(self):
        return stuff.copy_object(self.decrypted_config)

    def has_key(self, k):
        return k in self

    #def update(self, *args, **kwargs):
    #    return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.decrypted_config.keys()

    def values(self):
        return self.decrypted_config.values()

    def items(self):
        return self.decrypted_config.items()

    def pop(self, *args):
        return self.delete(*args)

    def __contains__(self, item):
        return item in self.decrypted_config

    def __iter__(self):
        return iter(self.decrypted_config)

    def __str__(self):
        return self.decrypted_config.__str__()

    def add(self, key, value, compression=None, encoding=None, encryption=None):
        modified_attr = False
        try:
            cur_val = self.get(key)
        except KeyError:
            modified_attr = True
        else:
            if cur_val != value:
                modified_attr = True
        if modified_attr:
            if key not in self.modified_attributes:
                self.modified_attributes.append(key)
        try:
            self.deleted_attributes.remove(key)
        except Exception:
            pass
        # Handle compression tags. Actual compression is done in backend.
        if compression:
            value = self.set_compression_type(value=value, compression=compression)
        # Handle encoding tags. Actual encoding is done in backend.
        if encoding:
            value = self.set_encoding_type(value=value, encoding=encoding)
        # Handle encryption tags. Actual encryption is done in backend.
        if encryption:
            value = self.set_encryption_type(value=value, encryption=encryption)

        self.decrypted_config[key] = value

    def get(self, key, no_headers=False):
        if key == "CHECKSUM":
            self.update_checksums()
        if key == "SYNC_CHECKSUM":
            self.update_checksums()
        try:
            value = self.decrypted_config[key]
        except Exception:
            raise KeyError(key) from None
        if no_headers:
            # Remove encryption header.
            status, \
            encryption, \
            value = self.get_encryption_type(value)
            # Remove encoding header.
            status, \
            encoding, \
            value = self.get_encoding_type(value)
            # Remove compression header.
            status, \
            compression, \
            value = self.get_compression_type(value)
        return value

    def delete(self, key):
        try:
            deleted_item = self.decrypted_config.pop(key)
        except Exception:
            return
        finally:
            if key not in self.deleted_attributes:
                self.deleted_attributes.append(key)
            try:
                self.modified_attributes.remove(key)
            except Exception:
                pass
            try:
                self.encrypted_config.pop(key)
            except Exception:
                pass
        return deleted_item

    @property
    def salt(self):
        try:
            salt = self.decrypted_config['SALT']
        except Exception:
            try:
                salt = self.encrypted_config['SALT']
            except Exception:
                salt = None
        return salt

    @salt.setter
    def salt(self, new_salt):
        self.encrypted_config['SALT'] = new_salt
        self.decrypted_config['SALT'] = new_salt

    @property
    def _checksum(self):
        try:
            checksum = self.decrypted_config['CHECKSUM']
        except Exception:
            try:
                checksum = self.encrypted_config['CHECKSUM']
            except Exception:
                checksum = None
        return checksum

    @property
    def checksum(self):
        self.update_checksums()
        return self._checksum

    @checksum.setter
    def checksum(self, new_checksum):
        self.encrypted_config['CHECKSUM'] = new_checksum
        self.decrypted_config['CHECKSUM'] = new_checksum

    @property
    def _sync_checksum(self):
        try:
            sync_checksum = self.decrypted_config['SYNC_CHECKSUM']
        except Exception:
            try:
                sync_checksum = self.decrypted_config['SYNC_CHECKSUM']
            except Exception:
                sync_checksum = None
        return sync_checksum

    @property
    def modified(self):
        if self.modified_attributes:
            return True
        if self.deleted_attributes:
            return True
        return False

    def forget_changes_since(self, modified_attributes, deleted_attributes):
        """ Count as changed what was counted before, and nothing since.

        For a change to the config that is not a change to the object:
        bringing a config up to the version of the code, when what is
        stored stays as it is (see OTPmeBaseObject._load() and
        _write()). Without this the object would be written again
        every time, to store what is stored already.

        The caller hands in the two lists as it copied them before.
        """
        self.modified_attributes[:] = modified_attributes
        self.deleted_attributes[:] = deleted_attributes

    def reset_modified(self):
        self.modified_attributes.clear()
        self.deleted_attributes.clear()
        try:
            self.encrypted_config.pop('INCREMENTAL_UPDATES')
        except KeyError:
            pass
        try:
            self.decrypted_config.pop('INCREMENTAL_UPDATES')
        except KeyError:
            pass
        try:
            self.encrypted_config.pop('INDEX_JOURNAL')
        except KeyError:
            pass
        try:
            self.decrypted_config.pop('INDEX_JOURNAL')
        except KeyError:
            pass

    @property
    def sync_checksum(self):
        self.update_checksums()
        return self._sync_checksum

    @sync_checksum.setter
    def sync_checksum(self, new_sync_checksum):
        self.encrypted_config['SYNC_CHECKSUM'] = new_sync_checksum
        self.decrypted_config['SYNC_CHECKSUM'] = new_sync_checksum

    def get_checksum_data(self):
        """ The config as a checksum is taken over it.

        Without the bookkeeping a checksum must not depend on, and
        without any checksum at all: one checksum never covers another,
        or the two would chase each other.

        Used for the checksum of the whole object and, one reduced copy
        at a time, for the checksum of each view of it (see
        OTPmeObject.update_sync_checksums()), so both are taken over
        the same thing.
        """
        checksum_data = stuff.copy_object(self.decrypted_config)

        volatile_attributes = [
                            'CHECKSUM',
                            'SYNC_CHECKSUM',
                            'SYNC_CHECKSUMS',
                            'MODIFIED_ATTRIBUTES',
                            'DELETED_ATTRIBUTES',
                            'INCREMENT_IDS',
                            'INCREMENTAL_UPDATES',
                            'INCREMENTAL_CHECKSUM',
                            'INDEX_JOURNAL',
                            ]
        for attribute in volatile_attributes:
            try:
                checksum_data.pop(attribute)
            except KeyError:
                pass

        # Add object salt. This salt is added to each object config to make
        # brute force attacks against the checksum harder on hosts/nodes where
        # the object config does include sensitive data (e.g. password hashes,
        # PINs etc.)
        if not self.salt:
            self.salt = stuff.gen_secret(len=32)

        # Set salt to temp object config.
        checksum_data['SALT'] = self.salt

        return checksum_data

    def is_authoritative(self):
        """ Whether this host decides what this object is.

        Only the site that owns an object says what its checksums are.
        Everywhere else the object is a copy, and a reduced one at that:
        recomputing a checksum there would give a different answer than
        the one the owner gave, and every peer would go downloading.
        """
        if config.realm_init:
            return True
        if config.site_init:
            return True
        if config.host_data['type'] != "node":
            return False
        if self.object_id.site == config.site:
            return True
        # A realm and a site have no site of their own, so they are
        # answered for by the master node of the realm.
        if self.object_id.object_type == "realm":
            if self.object_id.name == config.realm:
                if config.realm_master_node:
                    return True
        if self.object_id.object_type == "site":
            if config.realm_master_node:
                return True
        return False

    def gen_checksum(self, checksum_data):
        """ The checksum of a config, or of a reduced copy of one.

        Here and nowhere else, so the checksum of a view and the one of
        the whole object are built by the same code down to the JSON
        module they are serialized with.
        """
        checksum = json.dumps(checksum_data, sort_keys=True)
        return stuff.gen_sha512(checksum)

    def update_checksums(self, force=False):
        """ Update object config checksum. """
        if not force:
            if not self.modified_attributes:
                if not self.deleted_attributes:
                    return

        temp_oc = self.get_checksum_data()

        # Gen new checksum.
        object_checksum = self.gen_checksum(temp_oc)
        # Add checksum.
        self.checksum = object_checksum

        handle_sync_checksum = self.is_authoritative()

        # Set sync checksum.
        if handle_sync_checksum:
            self.sync_checksum = object_checksum

    def get_type_header(self, headers, value):
        """ Get header from value (e.g. encoding). """
        # Status "None" means no encoding done or needed.
        status = None
        value_type = None
        # Only string values can have a header.
        if not isinstance(value, str):
            return status, value_type, value

        value_match = False
        header1_re = re.compile(r"^[a-zA-Z0-9_]*[\[].*[\]]*$", re.MULTILINE)
        if header1_re.match(value):
            status = False
            value_match = True
            separator_braces = "[]"
        else:
            header2_re = re.compile(r"^[a-zA-Z0-9_]*[\{].*[\}]*$", re.MULTILINE)
            if header2_re.match(value):
                status = True
                value_match = True
                separator_braces = "{}"

        if value_match:
            value_type = value.split(separator_braces[0])[0]
            if value_type not in headers:
                value_match = False
                value_type = None
                status = None

        # Headers are always uppercase.
        if value_type is not None:
            value_type = value_type.upper()

        if not value_match:
            return status, value_type, value

        count = 0
        for x in separator_braces:
            if count == 0:
                value = value.split(x)[1:]
            else:
                value = value.split(x)[:-1]
            value = x.join(value)
            count += 1

        return status, value_type, value

    def get_compression_type(self, value):
        """
        Detect compression type of given value and return compression type + value.
        """
        headers = list(config.supported_compression_types)
        return self.get_type_header(headers, value)

    def get_encoding_type(self, value):
        """
        Detect encoding type of given value and return encoding type + value.
        """
        headers = list(config.supported_encoding_types)
        return self.get_type_header(headers, value)

    def get_encryption_type(self, value):
        """
        Detect encryption type of given value and return encryption type + value.
        """
        headers = list(config.supported_encryption_types)
        headers.append("NEED_ENC")
        return self.get_type_header(headers, value)

    def set_compression_type(self, value, compression):
        """ Add encoding tag to given value. """
        val = f"{compression.upper()}[{value}]"
        return val

    def set_encoding_type(self, value, encoding):
        """ Add encoding tag to given value. """
        val = f"{encoding.upper()}[{value}]"
        return val

    def set_encryption_type(self, value, encryption):
        """ Add encryption tag to given value. """
        val = f"{encryption.upper()}[{value}]"
        return val

    def remove_headers(self):
        """ Decode object config and remove headers. """
        object_config = dict(self.decrypted_config)
        object_config = self.decode_object_config(object_config)
        for p in dict(object_config):
            value = object_config[p]
            # Remove encryption header.
            status, \
            encryption, \
            value = self.get_encryption_type(value)
            if encryption == "NEED_ENC":
                # Get original encryption header.
                status, \
                encryption, \
                value = self.get_encryption_type(value)
                # Decode "fake" (hex) encrypted value.
                try:
                    value = stuff.decode(value, "hex")
                except Exception:
                    pass
            # Remove encoding header.
            status, \
            encoding, \
            value = self.get_encoding_type(value)
            # Remove compression header.
            status, \
            compression, \
            value = self.get_compression_type(value)
            object_config[p] = value
        return object_config

    def compress_object_config(self, object_config):
        """ Compress object config. """
        compressed_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            compression, \
            value = self.get_compression_type(val)
            # Skip already compressed values.
            if status is not False:
                continue
            if compression.startswith("GZIP"):
                level = 9
                if compression.startswith("GZIP_"):
                    try:
                        level = int(compression.split("_")[1])
                    except Exception:
                        msg = _("Unknown compression string: {compression}")
                        msg = msg.format(compression=compression)
                        raise OTPmeException(msg) from None
                _compression = "gzip"

            elif compression.startswith("BZIP2"):
                level = 9
                if compression.startswith("BZIP2_"):
                    try:
                        level = int(compression.split("_")[1])
                    except Exception:
                        msg = _("Unknown compression string: {compression}")
                        msg = msg.format(compression=compression)
                        raise OTPmeException(msg) from None
                _compression = "bzip"

            elif compression.startswith("ZLIB"):
                level = 6
                if compression.startswith("ZLIB_"):
                    try:
                        level = int(compression.split("_")[1])
                    except Exception:
                        msg = _("Unknown compression string: {compression}")
                        msg = msg.format(compression=compression)
                        raise OTPmeException(msg) from None
                _compression = "zlib"

            else:
                msg = _("Unknown compression type: {compression}")
                msg = msg.format(compression=compression)
                raise OTPmeException(msg)

            # Compress value.
            value = stuff.compress(data=value, compression=_compression, level=level)
            # Encode value.
            value = stuff.encode(data=value, encoding="base64")
            # Add header.
            value = f'{compression}{{{value}}}'
            # Update value in object config.
            compressed_config[p] = value
        return compressed_config

    def decompress_object_config(self, object_config):
        """ Decompress object config. """
        decompressed_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            compression, \
            value = self.get_compression_type(val)
            # Skip not encrypted values.
            if status is not True:
                continue
            if compression.startswith("GZIP"):
                _compression = "gzip"
            elif compression.startswith("BZIP2"):
                _compression = "bzip"
            elif compression.startswith("ZLIB"):
                _compression = "zlib"
            else:
                msg = _("Unknown compression type: {compression}")
                msg = msg.format(compression=compression)
                raise Exception(msg)

            # Decode value.
            value = stuff.decode(value, "base64")
            # Decompress value.
            value = stuff.decompress(value, _compression)
            # Add header.
            value = f'{compression}[{value}]'
            # Update value in object config.
            decompressed_config[p] = value
        return decompressed_config

    def encode_object_config(self, object_config):
        """ Encode object config. """
        encoded_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            encoding, \
            value = self.get_encoding_type(val)
            # Skip already encoded values.
            if status is not False:
                continue
            if encoding == "BASE64":
                value = stuff.encode(value, "base64")
            if encoding == "HEX":
                value = stuff.encode(value, "hex")

            value = f'{encoding}{{{value}}}'

            encoded_config[p] = value

        return encoded_config

    def decode_object_config(self, object_config):
        """ Decode object config. """
        decoded_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            encoding, \
            value = self.get_encoding_type(val)
            # Skip not encoded values.
            if status is not True:
                continue
            if encoding == "BASE64":
                value = stuff.decode(value, "base64")
            if encoding == "HEX":
                value = stuff.decode(value, "hex")

            if isinstance(value, bytes):
                value = value.decode()

            value = f'{encoding}[{value}]'
            decoded_config[p] = value

        return decoded_config

    def encrypt_object_config(self, object_config, enc_key=None, fake=False):
        """ Encrypt object config. """
        encrypted_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            encryption, \
            value = self.get_encryption_type(val)
            # Skip already encrypted values.
            if status is not False:
                continue
            if fake:
                value = stuff.encode(value, "hex")
            elif not enc_key:
                raise Exception(_("Need 'enc_key' to encrypt."))
            if fake:
                value = f'NEED_ENC{{{encryption}{{{value}}}}}'
            try:
                enc_module = get_module(encryption)
            except Exception as e:
                msg = _("Failed to load encryption module: {error}")
                msg = msg.format(error=e)
                raise OTPmeException(msg) from e

            if not fake:
                value = enc_module.encrypt(enc_key, value)
                value = f'{encryption}{{{value}}}'

            encrypted_config[p] = value

        return encrypted_config

    def decrypt_object_config(self, object_config, check_encrypted=None, enc_key=None):
        """ Decrypt object config. """
        if check_encrypted is None:
            check_encrypted = []
        decrypted_config = dict(object_config)
        for p in dict(object_config):
            val = object_config[p]
            status, \
            encryption, \
            value = self.get_encryption_type(val)
            # Skip not encrypted values.
            if status is not True:
                if p in check_encrypted:
                    msg = _("Found unencrypted parameteer: {p}")
                    msg = msg.format(p=p)
                    raise OTPmeException(msg)
                continue
            if encryption == "NEED_ENC":
                # Get original encryption header.
                status, \
                encryption, \
                value = self.get_encryption_type(value)
                # Decode "fake" (hex) encrypted value.
                try:
                    value = stuff.decode(value, "hex")
                except Exception:
                    pass
            else:
                try:
                    enc_module = get_module(encryption)
                except Exception as e:
                    msg = _("Failed to load encryption module: {error}")
                    msg = msg.format(error=e)
                    raise OTPmeException(msg) from e
                if not enc_key:
                    raise OTPmeException(_("Need 'enc_key' to decrypt."))
                try:
                    value = enc_module.decrypt(enc_key, value)
                except Exception as e:
                    msg = _("Failed to decrypt key: {param}")
                    msg = msg.format(param=p)
                    raise OTPmeException(msg) from e

            value = f'{encryption}[{value}]'

            decrypted_config[p] = value

        return decrypted_config

    def encrypt(self, key=None, fake=False, update_checksums=True):
        if self.encrypted_config:
            if not self.modified:
                return self.encrypted_config
        if update_checksums:
            self.update_checksums()
        if self.encrypted:
            # If the object config was encrypted on init we just have to add
            # the modified (plaintext) attributes to be encrypted below.
            for x in self.modified_attributes:
                self.encrypted_config[x] = self.decrypted_config[x]
            object_config = stuff.copy_object(self.encrypted_config)
        else:
            object_config = stuff.copy_object(self.decrypted_config)
        # Add modifified objects to be used on write.
        if self.modified_attributes:
            self.modified_attributes.append("SALT")
            self.modified_attributes.append("CHECKSUM")
            self.modified_attributes.append("SYNC_CHECKSUM")
            modified_attributes = self.modified_attributes
            object_config['MODIFIED_ATTRIBUTES'] = modified_attributes
            self.modified_attributes = []
            deleted_attributes = self.deleted_attributes
            object_config['DELETED_ATTRIBUTES'] = deleted_attributes
            self.deleted_attributes = []
        # Compress object config.
        try:
            compressed_oc = self.compress_object_config(object_config)
        except Exception as e:
            msg = _("Failed to compress object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        # Encode object config.
        try:
            encoded_oc = self.encode_object_config(compressed_oc)
        except Exception as e:
            msg = _("Failed to encode object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        # Encrypt object config.
        try:
            encrypted_oc = self.encrypt_object_config(object_config=encoded_oc,
                                                        enc_key=key, fake=fake)
        except Exception as e:
            msg = _("Failed to encrypt object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        self.encrypted_config = encrypted_oc
        return self.encrypted_config

    def decrypt(self, key=None, check_encrypted=None):
        if check_encrypted is None:
            check_encrypted = []
        encrypted_oc = dict(self.encrypted_config)
        # Decrypt config.
        try:
            decrypted_oc = self.decrypt_object_config(object_config=encrypted_oc,
                                                    check_encrypted=check_encrypted,
                                                    enc_key=key)
        except Exception as e:
            msg = _("Failed to decrypt object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        # Decode config.
        try:
            decodec_oc = self.decode_object_config(decrypted_oc)
        except Exception as e:
            msg = _("Failed to decode object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        # Decompress config.
        try:
            decompressed_oc = self.decompress_object_config(decodec_oc)
        except Exception as e:
            msg = _("Failed to decompress object config: {error}")
            msg = msg.format(error=e)
            raise OTPmeException(msg) from e
        self.decrypted_config = decompressed_oc
        return self.decrypted_config

    def reduce(self, encrypted=False):
        if encrypted:
            try:
                modified_attributes = self.encrypted_config['MODIFIED_ATTRIBUTES']
            except KeyError:
                modified_attributes = []
            reduced_config = self.encrypted_config
        else:
            try:
                modified_attributes = self.decrypted_config['MODIFIED_ATTRIBUTES']
            except KeyError:
                modified_attributes = []
            reduced_config = self.decrypted_config

            keep_attribues = [
                                "SALT",
                                "UUID",
                                #"LDIF",
                                #"ACLS",
                                #"INDEX",
                                "TEMPLATE",
                                "CHECKSUM",
                                "SYNC_CHECKSUM",
                                "ACL_JOURNAL",
                                "LDIF_JOURNAL",
                                "INDEX_JOURNAL",
                                "LAST_MODIFIED",
                                "INCREMENT_IDS",
                                "DICT_ATTRIBUTES",
                                "LIST_ATTRIBUTES",
                                "MODIFIED_ATTRIBUTES",
                                "DELETED_ATTRIBUTES",
                                "INCREMENTAL_UPDATES",
                            ]

        for x in dict(reduced_config):
            if x in self.modified_attributes:
                continue
            if x in modified_attributes:
                continue
            if x in keep_attribues:
                continue
            reduced_config.pop(x)
        try:
            incremental_updates = self.decrypted_config['INCREMENTAL_UPDATES']
        except KeyError:
            incremental_updates = []
        for x in incremental_updates:
            attr = x[1]
            if attr in keep_attribues:
                continue
            try:
                reduced_config.pop(attr)
            except KeyError:
                pass
        return reduced_config
