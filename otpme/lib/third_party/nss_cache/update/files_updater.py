# Copyright 2010 Google Inc.
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

These update classes are based around file synchronization rather than
map synchronization.

These classes contains all the business logic for updating cache objects.
They also contain the code for reading, writing, and updating timestamps.
"""

__author__ = (
    'jaq@google.com (Jamie Wilkinson)',
    'vasilios@google.com (V Hoffman)',
    'blaedd@google.com (David MacKinnon)',
)

import errno
import os
import tempfile
import time

from nss_cache import error
from nss_cache.caches import cache_factory
from nss_cache.update import updater


class FileMapUpdater(updater.Updater):
    """Updates simple map files like passwd, group, shadow, and netgroup."""

    def UpdateCacheFromSource(self,
                              cache,
                              source,
                              incremental=False,
                              force_write=False,
                              location=None):
        """Update a single cache file, from a given source.

        Args:
          cache: A nss_cache.caches.Cache object.
          source: A nss_cache.sources.Source object.
          incremental: We ignore this.
          force_write: A boolean flag forcing empty map updates when False,
            defaults to False.
          location: The optional location in the source of this map used by
            automount to specify which automount map to get, defaults to None.

        Returns:
          An int indicating the success of an update (0 == good, fail otherwise).
        """
        return_val = 0

        cache_filename = cache.GetCacheFilename()
        if cache_filename is not None:
            new_file_fd, new_file = tempfile.mkstemp(
                dir=os.path.dirname(cache_filename),
                prefix=os.path.basename(cache_filename),
                suffix='.nsscache.tmp')
        else:
            raise error.CacheInvalid('Cache has no filename.')

        self.log.debug('temp source filename: %s', new_file)
        try:
            # Writes the source to new_file.
            # Current file is passed in to allow the source to do partial diffs.
            # TODO(jaq): refactor this to pass in the whole cache, so that the source
            # can decide how to reduce downloads, c.f. last-modify-timestamp for ldap.
            source.GetFile(self.map_name,
                           new_file,
                           current_file=cache.GetCacheFilename(),
                           location=location)
            os.lseek(new_file_fd, 0, os.SEEK_SET)
            # TODO(jaq): this sucks.
            source_cache = cache_factory.Create(self.cache_options,
                                                self.map_name)
            source_map = source_cache.GetMap(new_file)

            # Update the cache from the new file.
            return_val += self._FullUpdateFromFile(cache, source_map,
                                                   force_write)
        finally:
            try:
                os.unlink(new_file)
            except OSError as e:
                # If we're using zsync source, it already renames the file for us.
                if e.errno != errno.ENOENT:
                    raise

        return return_val

    def _FullUpdateFromFile(self, cache, source_map, force_write=False):
        """Write a new map into the provided cache (overwrites).

        Args:
          cache: A nss_cache.caches.Cache object.
          source_map: The map whose contents we're replacing the cache with, that is
            used for verification.
          force_write: A boolean flag forcing empty map updates when False,
            defaults to False.

        Returns:
          0 if succesful, non-zero indicating number of failures otherwise.

        Raises:
          EmptyMap: Update is an empty map, not raised if force_write=True.
          InvalidMap:
        """
        return_val = 0

        for entry in source_map:
            if not entry.Verify():
                raise error.InvalidMap('Map is not valid. Aborting')

        if len(source_map) == 0 and not force_write:
            raise error.EmptyMap(
                'Source map empty during full update, aborting. '
                'Use --force-write to override.')

        return_val += cache.WriteMap(map_data=source_map)

        # We did an update, write our timestamps unless there is an error.
        if return_val == 0:
            mtime = os.stat(cache.GetCacheFilename()).st_mtime
            self.log.debug('Cache filename %s has mtime %d',
                           cache.GetCacheFilename(), mtime)
            self.WriteModifyTimestamp(mtime)
            self.WriteUpdateTimestamp()

        return return_val
