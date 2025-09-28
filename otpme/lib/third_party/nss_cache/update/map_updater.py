# Copyright 2007 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""Update class, used for manipulating source and cache data.

These classes contains all the business logic for updating cache objects.
They also contain the code for reading, writing, and updating timestamps.

FileMapUpdater:  Class used for all single map caches.
AutomountMapUpdater:  Class used for updating automount map caches.
"""

__author__ = ('vasilios@google.com (V Hoffman)',
              'jaq@google.com (Jamie Wilkinson)')

from nss_cache import error
from nss_cache.caches import cache_factory
from nss_cache.update import updater


class MapUpdater(updater.Updater):
    """Updates simple maps like passwd, group, shadow, and netgroup."""

    def UpdateCacheFromSource(self,
                              cache,
                              source,
                              incremental=False,
                              force_write=False,
                              location=None):
        """Update a single cache, from a given source.

        Args:
          cache: A nss_cache.caches.Cache object.
          source: A nss_cache.sources.Source object.
          incremental: A boolean flag indicating that an incremental update
            should be performed if True.
          force_write: A boolean flag forcing empty map updates if True.
          location: The optional location in the source of this map used by
            automount to specify which automount map to get, defaults to None.

        Returns:
          An int indicating the success of an update (0 == good, fail otherwise).
        """
        return_val = 0
        incremental = incremental and self.can_do_incremental

        timestamp = self.GetModifyTimestamp()
        if timestamp is None and incremental is True:
            self.log.info(
                'Missing previous timestamp, defaulting to a full sync.')
            incremental = False

        if incremental:
            source_map = source.GetMap(self.map_name,
                                       since=timestamp,
                                       location=location)
            try:
                return_val += self._IncrementalUpdateFromMap(cache, source_map)
            except (error.CacheNotFound, error.EmptyMap):
                self.log.warning(
                    'Local cache is invalid, faulting to a full sync.')
                incremental = False

        # We don't use an if/else, because we give the incremental a chance to
        # fail through to a full sync.
        if not incremental:
            source_map = source.GetMap(self.map_name, location=location)
            return_val += self.FullUpdateFromMap(cache, source_map, force_write)

        return return_val

    def _IncrementalUpdateFromMap(self, cache, new_map):
        """Merge a given map into the provided cache.

        Args:
          cache: A nss_cache.caches.Cache object.
          new_map: A nss_cache.maps.Map object.

        Returns:
          An int indicating the success of an update (0 == good, fail otherwise).

        Raises:
          EmptyMap: We're trying to merge into cache with an emtpy map.
        """
        return_val = 0

        if len(new_map) == 0:
            self.log.info('Empty map on incremental update, skipping')
            return 0

        self.log.debug('loading cache map, may be slow for large maps.')
        cache_map = cache.GetMap()

        if len(cache_map) == 0:
            raise error.EmptyMap

        if cache_map.Merge(new_map):
            return_val += cache.WriteMap(map_data=cache_map)
            if return_val == 0:
                self.WriteModifyTimestamp(new_map.GetModifyTimestamp())
        else:
            self.WriteModifyTimestamp(new_map.GetModifyTimestamp())
            self.log.info('Nothing new merged, returning')

        # We did an update, even if nothing was written, so write our
        # update timestamp unless there is an error.
        if return_val == 0:
            self.WriteUpdateTimestamp()

        return return_val

    def FullUpdateFromMap(self, cache, new_map, force_write=False):
        """Write a new map into the provided cache (overwrites).

        Args:
          cache: A nss_cache.caches.Cache object.
          new_map: A nss_cache.maps.Map object.
          force_write: A boolean indicating empty maps are okay to write, defaults
            to False which means do not write them.

        Returns:
          0 if succesful, non-zero indicating number of failures otherwise.

        Raises:
          EmptyMap: Update is an empty map, not raised if force_write=True.
        """
        return_val = 0

        if len(new_map) == 0 and not force_write:
            raise error.EmptyMap(
                'Source map empty during full update, aborting. '
                'Use --force-write to override.')

        return_val = cache.WriteMap(map_data=new_map)

        # We did an update, write our timestamps unless there is an error.
        if return_val == 0:
            self.WriteModifyTimestamp(new_map.GetModifyTimestamp())
            self.WriteUpdateTimestamp()

        return return_val
