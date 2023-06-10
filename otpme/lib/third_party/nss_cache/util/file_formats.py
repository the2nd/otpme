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
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
"""Parsing methods for file cache types."""

__author__ = ('jaq@google.com (Jamie Wilkinson)',
              'vasilios@google.com (Vasilios Hoffman)')

import logging

from ..maps import group
from ..maps import passwd
from ..maps import shadow

try:
    SetType = set
except NameError:
    import sets
    SetType = sets.Set


class FilesMapParser(object):
    """A base class for parsing nss_files module cache."""

    def __init__(self):
        self.log = logging.getLogger(__name__)

    def GetMap(self, cache_info, data):
        """Returns a map from a cache.

        Args:
          cache_info: file like object containing the cache.
          data: a Map to populate.
        Returns:
          A child of Map containing the cache data.
        """
        for line in cache_info:
            line = line.rstrip('\n')
            if not line or line[0] == '#':
                continue
            entry = self._ReadEntry(line)
            if entry is None:
                self.log.warning(
                    'Could not create entry from line %r in cache, skipping',
                    line)
                continue
            if not data.Add(entry):
                self.log.warning(
                    'Could not add entry %r read from line %r in cache', entry,
                    line)
        return data


class FilesPasswdMapParser(FilesMapParser):
    """Class for parsing nss_files module passwd cache."""

    def _ReadEntry(self, entry):
        """Return a PasswdMapEntry from a record in the target cache."""
        entry = entry.split(':')
        map_entry = passwd.PasswdMapEntry()
        # maps expect strict typing, so convert to int as appropriate.
        map_entry.name = entry[0]
        map_entry.passwd = entry[1]
        map_entry.uid = int(entry[2])
        map_entry.gid = int(entry[3])
        map_entry.gecos = entry[4]
        map_entry.dir = entry[5]
        map_entry.shell = entry[6]
        return map_entry


class FilesGroupMapParser(FilesMapParser):
    """Class for parsing a nss_files module group cache."""

    def _ReadEntry(self, line):
        """Return a GroupMapEntry from a record in the target cache."""
        line = line.split(':')
        map_entry = group.GroupMapEntry()
        # map entries expect strict typing, so convert as appropriate
        map_entry.name = line[0]
        map_entry.passwd = line[1]
        map_entry.gid = int(line[2])
        map_entry.members = line[3].split(',')
        return map_entry


class FilesShadowMapParser(FilesMapParser):
    """Class for parsing a nss_files module shadow cache."""

    def _ReadEntry(self, line):
        """Return a ShadowMapEntry from a record in the target cache."""
        line = line.split(':')
        map_entry = shadow.ShadowMapEntry()
        # map entries expect strict typing, so convert as appropriate
        map_entry.name = line[0]
        map_entry.passwd = line[1]
        if line[2]:
            map_entry.lstchg = int(line[2])
        if line[3]:
            map_entry.min = int(line[3])
        if line[4]:
            map_entry.max = int(line[4])
        if line[5]:
            map_entry.warn = int(line[5])
        if line[6]:
            map_entry.inact = int(line[6])
        if line[7]:
            map_entry.expire = int(line[7])
        if line[8]:
            map_entry.flag = int(line[8])
        return map_entry
