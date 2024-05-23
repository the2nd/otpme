# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import glob
import ujson
import shutil

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import json
from otpme.lib import config
from otpme.lib import filetools
from otpme.lib.classes.object_config import ObjectConfig

from otpme.lib.exceptions import *

class SyncCache(dict):
    """ Handle sync cache files. """
    def __init__(self, realm, site, protocol=None, mem_cache=True):
        self.realm = realm
        self.site = site
        self.object_ids = {}
        self._cache = {}
        self.mem_cache = mem_cache
        # Get logger.
        self.logger = config.logger
        # Temp directory we will use to spool sync objects.
        self.cache_dir = "%s/tmp/%s/%s" % (config.sync_dir, realm, site)
        self.ensure_cache_dir()
        # File to save sync protocol version to.
        self.protocol_file = "%s/sync.protocol" % self.cache_dir
        # The sync protocol (handler) that created this sync cache.
        if protocol is not None:
            self.protocol = protocol
        self.sync_params_file = os.path.join(self.cache_dir, "sync_parameters.json")
        # Files to save sync lists to.
        self.local_sync_list_file = os.path.join(self.cache_dir, "local_sync_list.json")
        self.remote_sync_list_file = os.path.join(self.cache_dir, "remote_sync_list.json")
        self.sync_list_files = {
                    'local'     : self.remote_sync_list_file,
                    'remote'    : self.local_sync_list_file,
                    }

    def __setitem__(self, key, item):
        self.add(key, item)

    def __getitem__(self, key):
        return self.get(key)

    #def __repr__(self):
    #    return repr(self.__dict__)

    def __len__(self):
        # Get cache data.
        return len(self.object_ids)

    def __delitem__(self, key):
        self.delete(key)

    #def copy(self):
    #    return self.__dict__.copy()

    def has_key(self, k):
        return k in self

    #def update(self, *args, **kwargs):
    #    return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.object_ids.keys()

    def values(self):
        return self.object_ids.values()

    def items(self):
        return self.object_ids.items()

    def pop(self, *args):
        return self.delete(*args)

    def __contains__(self, item):
        return item in self.object_ids

    def __iter__(self):
        return iter(self.object_ids)

    def clear(self):
        """ Clear sync cache. """
        self.object_ids = {}
        if not os.path.exists(self.cache_dir):
            return True
        self.logger.info("Clearing sync cache directory...")
        try:
            shutil.rmtree(self.cache_dir)
        except Exception as e:
            msg = "Failed to sync cache dir: %s" % e
            self.logger.critical(msg)

    def get_cache_file(self, object_id):
        """ Get cache file path. """
        cache_file = "%s/%s.sqlite" % (self.cache_dir, object_id.replace("/", ":"))
        return cache_file

    @property
    def protocol(self):
        """ Read sync protocol version from file. """
        if not os.path.exists(self.protocol_file):
            return
        try:
            protocol = filetools.read_file(self.protocol_file)
        except Exception as e:
            msg = ("Error reading protocol version from file: %s" % e)
            self.logger.warning(msg)
            return
        return protocol

    @protocol.setter
    def protocol(self, protocol):
        """ Write sync protocol version to file. """
        try:
            filetools.create_file(path=self.protocol_file,
                                content=protocol)
        except Exception as e:
            msg = ("Error writing sync protocol version to file: %s" % e)
            self.logger.warning(msg)
            return

    @property
    def sync_parameters(self):
        """ Read remote sync list from file. """
        if not os.path.exists(self.sync_params_file):
            return
        try:
            content = filetools.read_file(self.sync_params_file)
        except Exception as e:
            msg = ("Error reading sync parameters from file: %s" % e)
            self.logger.warning(msg)
            return
        # Decode sync parameters.
        try:
            sync_parameters = json.decode(content, encoding="base64")
        except Exception as e:
            msg = ("Error decoding sync parameters: %s" % e)
            self.logger.warning(msg)
            return
        return sync_parameters

    @sync_parameters.setter
    def sync_parameters(self, sync_parameters):
        """ Write sync parameters to file. """
        try:
            encoded_sync_params = json.encode(sync_parameters,
                                            encoding="base64",
                                            compress=True)
        except Exception as e:
            msg = ("Error encoding sync parameters: %s" % e)
            self.logger.warning(msg)
            return
        try:
            filetools.create_file(path=self.sync_params_file,
                                content=encoded_sync_params)
        except Exception as e:
            msg = ("Error writing sync parameters to file: %s" % e)
            self.logger.warning(msg)
            return

    @property
    def local_sync_list(self):
        """ Read local sync list from file. """
        local_sync_list = self.read_sync_list("local")
        return local_sync_list

    @local_sync_list.setter
    def local_sync_list(self, local_sync_list):
        """ Write local sync list to file. """
        self.write_sync_list("local", local_sync_list)

    @property
    def remote_sync_list(self):
        """ Read remote sync list from file. """
        remote_sync_list = self.read_sync_list("remote")
        return remote_sync_list

    @remote_sync_list.setter
    def remote_sync_list(self, remote_sync_list):
        """ Write remote sync list to file. """
        self.write_sync_list("remote", remote_sync_list)

    def read_sync_list(self, list_type):
        """ Read sync list from file. """
        try:
            sync_list_file = self.sync_list_files[list_type]
        except:
            msg = "Invalid sync list type: %s" % list_type
            self.logger.warning(msg)
            return
        if not os.path.exists(sync_list_file):
            return
        try:
            content = filetools.read_file(sync_list_file)
        except Exception as e:
            msg = ("Error reading %s sync list from file: %s" % (list_type, e))
            self.logger.warning(msg)
            return
        # Decode sync list.
        try:
            sync_list = json.decode(content, encoding="base64")
        except Exception as e:
            msg = ("Error decoding %s sync list: %s" % (list_type, e))
            self.logger.warning(msg)
            return
        return sync_list

    def write_sync_list(self, list_type, sync_list):
        """ Write sync list to file. """
        try:
            sync_list_file = self.sync_list_files[list_type]
        except:
            msg = "Invalid sync list type: %s" % list_type
            self.logger.warning(msg)
            return
        try:
            encoded_sync_list = json.encode(sync_list,
                                            encoding="base64",
                                            compress=True)
        except Exception as e:
            msg = ("Error encoding %s sync list: %s" % (list_type, e))
            self.logger.warning(msg)
            return
        try:
            filetools.create_file(path=sync_list_file,
                                content=encoded_sync_list)
        except Exception as e:
            msg = ("Error writing %s sync list to file: %s" % (list_type, e))
            self.logger.warning(msg)
            return

    def add(self, object_id, data):
        """ Add object to job cache. """
        cache_file = self.get_cache_file(object_id)
        # Add object ID.
        self.object_ids[object_id] = cache_file
        # Write data.
        self.write_object(object_id, data)
        # Cache object.
        if self.mem_cache:
            self._cache[object_id] = data

    def get(self, object_id):
        """ Get job cache. """
        if not object_id in self.object_ids:
            return
        # Get object from cache.
        if self.mem_cache:
            try:
                data = self._cache[object_id]
            except:
                data = None
            if data is not None:
                return data
        data = self.read_object(object_id)
        # Cache object.
        if self.mem_cache:
            self._cache[object_id] = data
        return data

    def delete(self, object_id):
        """ Del object from job cache. """
        # Try to remove object.
        try:
            cache_file = self.object_ids.pop(object_id)
        except:
            return
        if not os.path.exists(cache_file):
            return
        try:
            filetools.delete(cache_file)
        except Exception as e:
            msg = "Failed to remove cache file: %s" % e
            self.logger.critical(msg)

    def ensure_cache_dir(self):
        """ Make sure we have a cache dir. """
        if os.path.exists(self.cache_dir):
            return
        try:
            filetools.create_dir(path=self.cache_dir,
                                user=config.user,
                                group=config.group,
                                mode=0o770)
        except Exception as e:
            msg = (_("Error creating cache directory: %s") % e)
            raise OTPmeException(msg)

    def load(self):
        """ Read all object IDs from sync dir into sync cache dict. """
        if not os.path.exists(self.cache_dir):
            return
        # Get cache file list.
        cache_files = glob.glob("%s/*.sqlite" % self.cache_dir)
        if not cache_files:
            return
        self.logger.info("Reading sync cache from directory: %s" % self.cache_dir)
        for cache_file in cache_files:
            cache_file_name = os.path.basename(cache_file)
            object_id = cache_file_name.replace(":", "/")
            object_id = re.sub('.sqlite$', '', object_id)
            self.object_ids[object_id] = cache_file

    def read_object(self, object_id):
        """ Read object from sync dir. """
        if not os.path.exists(self.cache_dir):
            return
        # Get cache file path.
        cache_file = self.get_cache_file(object_id)
        # Read sync object from disk.
        try:
            file_content = filetools.read_file(cache_file)
        except Exception:
            os.remove(cache_file)
            return
        # Load object config.
        object_config = ujson.loads(file_content)
        # Decrypt config.
        try:
            object_config = ObjectConfig(object_id, object_config)
            object_config = object_config.decrypt(config.master_key)
        except Exception as e:
            msg = ("Failed to decrypt object config: %s: %s"
                    % (object_id, e))
            self.logger.critical(msg, exc_info=True)
            return
        return object_config

    def write_object(self, object_id, object_config):
        """ Write sync cache to disk. """
        # Encrypt object config.
        object_config = ObjectConfig(object_id=object_id,
                                object_config=object_config,
                                encrypted=False)
        object_config = object_config.encrypt(config.master_key)
        file_content = ujson.dumps(object_config)
        # Get cache file path.
        cache_file = self.get_cache_file(object_id)
        # Write object config to disk.
        try:
            return filetools.create_file(cache_file,
                                        file_content,
                                        user=config.user,
                                        group=config.group,
                                        mode=0o660)
        except Exception as e:
            msg = (_("Error writing cache file: %s") % e)
            raise OTPmeException(msg)
