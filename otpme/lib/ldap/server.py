# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
#import errno
import signal
import setproctitle

#from twisted.internet import selectreactor
#selectreactor.install()
from twisted.internet import pollreactor
pollreactor.install()

import logging
from twisted.python import log
from twisted.internet import defer
#from twisted.internet import error
#from twisted.python import failure
from zope.interface import implementer
from twisted.python import components
from twisted.internet import protocol

from ldaptor import entry
from ldaptor import interfaces
from ldaptor import attributeset

#from ldaptor import entryhelpers
from ldaptor.protocols.ldap import ldapserver
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap import ldifprotocol
from ldaptor.protocols.ldap import distinguishedname
from twisted.protocols.tls import TLSMemoryBIOFactory

#from twisted.mail.maildir import _generateMaildirName as tempName
from ldaptor.protocols import pureber
from ldaptor.protocols import pureldap

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import auth_cache
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.cache import ldap_search_cache
from otpme.lib.classes.otpme_object import get_ldif
from otpme.lib.classes.otpme_object import get_ldif_whitelist_id
from otpme.lib.classes.otpme_object import get_ldif_whitelist_attributes
from otpme.lib.backends.file.file import get_oid_from_path
from otpme.lib.backends.file.file import get_config_paths
from otpme.lib.backends.file.file import OBJECTS_DIR

from otpme.lib.exceptions import *

# The tokens we read from the backend, with the time we read them.
# Value and time belong together: with the token kept on the entry and
# only the time shared, the first holder to refresh stamps the time for
# everyone else, and every other holder then keeps its old token for
# good. Shared by UUID also means one read per token and interval for
# the whole process, however many connections bound with it.
auth_token_cache = {}
AUTH_TOKEN_READ_TIMEOUT = 30

ldap_cache = {}
ldap_query_cache = {}

uuid_to_oid = {}
user_ldif_cache = {}
global_ldif_cache = {}
ldif_settings_cache = {}

# The state of the shared outdated objects dict we acted on. See
# sync_outdated_objects().
outdated_counter = None
outdated_time = None

# Search bases we resolved. See LDIFTreeEntry.lookup().
lookup_cache = {}

# How well our caches do. See count_cache() and log_cache_stats().
cache_stats = {}
cache_stats_time = 0
# Seconds between two lines of cache statistics.
CACHE_STATS_INTERVAL = 30

# Resolving the LDIF settings of a token means loading the token and our
# site, and update_ldif_settings() runs for every entry a search builds. So
# cache them for a moment. A changed config parameter takes effect with
# a delay of up to this many seconds.
LDIF_SETTINGS_CACHE_TIME = 30

# How long we trust cached LDIF data without asking the backend for the
# objects current checksum. Verifying it is one index query per object,
# which is way too much for a search that returns thousands of them.
LDIF_CACHE_TIME = 300

# How long a search result stays in the cache the ldapd processes share.
# Also the expiry of the redis keys, so nobody has to clean up after a
# process that went away.
#
# The resolved search bases get the same span, locally and shared: an
# entry we take over from a sibling would otherwise be too old for us
# right away and we would fetch it again on every request. What keeps
# this correct is not the time but outdate_ldap_object(), which drops
# the entry of an object that moved.
#
# Set from the "ldap_shared_cache_time" config parameter when ldapd
# starts, before it forks its workers, see LdapDaemon._run().
SHARED_QUERY_CACHE_TIME = 3600
shared_query_cache_time = SHARED_QUERY_CACHE_TIME

def set_shared_cache_time(cache_time):
    """ Set how long the ldapd processes trust a cached search. """
    global shared_query_cache_time
    shared_query_cache_time = int(cache_time)

# Whether the processes share anything at all: their search results and
# the search bases they resolved. Set from the "ldap_shared_cache" config
# parameter when ldapd starts, before it forks its workers, see
# LdapDaemon._run().
shared_cache_enabled = True

def set_shared_cache(enabled):
    """ Turn the caches the ldapd processes share on or off. """
    global shared_cache_enabled
    shared_cache_enabled = bool(enabled)

LDAP_CLIENT_NAME = "LDAP"
LDAP_ACCESSGROUP = "LDAP"

# Encoded search results we keep per entry. The key is the attribute
# list of the request, so it is the client that decides how many there
# are. A handful covers what an application asks for; past that we
# encode again rather than let one entry grow without an end.
MAX_ENTRY_PAYLOADS = 8

# Connections the kernel queues for us until we accept them.
LISTEN_BACKLOG = 128

# Default value of the "ldap_on_request_attributes" config parameter.
ON_REQUEST_ATTRIBUTES = [
                    'jpegPhoto',
                    ]

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.client",
                "otpme.lib.classes.accessgroup",
                ]

def register():
    register_config()
    register_config_parameters()

def register_config():
    """ Register config stuff. """
    # Register LDAP base client.
    config.register_config_var("ldap_client_name", str, LDAP_CLIENT_NAME)
    config.register_config_var("ldap_access_group", str, LDAP_ACCESSGROUP)
    config.register_base_object("accessgroup",  LDAP_ACCESSGROUP)
    client_attrs = {'access_group':LDAP_ACCESSGROUP}
    config.register_base_object(object_type="client",
                            name=config.ldap_client_name,
                            attributes=client_attrs)

def register_config_parameters():
    """ Register config parameters. """
    # Whether ldapd verifies the ACLs of the objects it hands out to a
    # token (see LDIFTreeEntry.ldap_verify_acls()). Resolved through the
    # tokens inheritance chain (token -> user -> unit -> site), so it can
    # be turned off for a single service token without opening up the
    # whole site. admin_only: switching it off gives the token every
    # attribute of every object it can find, which is nothing an ACL on
    # the token itself should be able to decide.
    config.register_config_parameter(name="ldap_verify_acls",
                                    ctype=bool,
                                    default_value=True,
                                    admin_only=True,
                                    object_types=[
                                                'site',
                                                'unit',
                                                'user',
                                                'token',
                                                ])
    # Attributes we only hand out when the search asked for them by
    # name. A client that requests all attributes (SOGo does that on
    # every address book search) would otherwise pull the photos of
    # every hit over the wire and into our caches. RFC 4522 allows
    # holding back attributes on a wildcard request.
    def on_request_attributes_setter(attributes, **kwargs):
        if isinstance(attributes, str):
            attributes = attributes.split(",")
        _attributes = []
        for x_attr in attributes:
            x_attr = x_attr.strip()
            if not x_attr:
                continue
            if x_attr in _attributes:
                continue
            _attributes.append(x_attr)
        return _attributes
    config.register_config_parameter(name="ldap_on_request_attributes",
                                    ctype=list,
                                    setter=on_request_attributes_setter,
                                    default_value=ON_REQUEST_ATTRIBUTES,
                                    object_types=[
                                                'site',
                                                'unit',
                                                'user',
                                                'token',
                                                ])

def install_reactor():
    """ Get a reactor of our own.

    The reactor is built when this module gets imported, so it already
    exists when ldapd forks its workers and they would all share it --
    above all its wakeup pipe. callFromThread() puts the work into a
    queue and writes a byte into that pipe to get the reactor out of
    poll(). A sibling that reads the byte first leaves the process the
    work belongs to asleep, with the work still sitting in its queue,
    until something else happens to wake it -- and poll() without a
    pending timer waits forever. Every search takes that path, it runs
    through deferToThread().

    Twisted refuses to install a second reactor, so we drop the one we
    inherited first. Call this before anything imports the reactor in
    this process, or that one would go on using the old one.
    """
    import sys
    try:
        del sys.modules['twisted.internet.reactor']
    except KeyError:
        pass
    pollreactor.install()

def create_listen_socket(address, port, reuse_port=True):
    """ Get a socket to listen on.

    We build it ourselves instead of leaving that to twisted because of
    SO_REUSEPORT: it lets several processes bind the same address and
    port, and the kernel spreads the connections over them. That is how
    ldapd runs on more than one core, see LdapDaemon.

    Made outside of LDAPServer on purpose: creating one of those
    registers an adapter and builds the root entry, and whoever binds
    the socket (the parent, while it still has the privileges) is not
    the one who serves it.
    """
    import socket
    addr_info = socket.getaddrinfo(address, port,
                                type=socket.SOCK_STREAM,
                                flags=socket.AI_PASSIVE)
    if not addr_info:
        msg = _("Cannot listen on address: {address}")
        msg = msg.format(address=address)
        raise OTPmeException(msg)
    family, socket_type, proto, _canonname, sockaddr = addr_info[0]
    listen_socket = socket.socket(family, socket_type, proto)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if reuse_port:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    listen_socket.bind(sockaddr)
    listen_socket.listen(LISTEN_BACKLOG)
    # adoptStreamPort() wants a non blocking socket.
    listen_socket.setblocking(False)
    return listen_socket

def update_auth_token_cache(token_uuid, auth_token):
    """ Remember a token, with the time and the OID of its object. """
    global auth_token_cache
    read_oid = None
    if auth_token is not None:
        try:
            read_oid = auth_token.oid.read_oid
        except Exception:
            read_oid = None
    auth_token_cache[token_uuid] = {
                                    'token'     : auth_token,
                                    'time'      : time.time(),
                                    'read_oid'  : read_oid,
                                    }

def clear_caches():
    global ldap_cache
    global uuid_to_oid
    global lookup_cache
    global user_ldif_cache
    global ldap_query_cache
    global auth_token_cache
    global global_ldif_cache
    global ldif_settings_cache
    ldap_cache.clear()
    uuid_to_oid.clear()
    lookup_cache.clear()
    user_ldif_cache.clear()
    ldap_query_cache.clear()
    auth_token_cache.clear()
    global_ldif_cache.clear()
    ldif_settings_cache.clear()
    ldap_search_cache.invalidate()

def drop_cached_objects(read_oids):
    """ Remove the given objects from our entry caches. """
    global ldap_cache
    global uuid_to_oid
    global lookup_cache
    global user_ldif_cache
    global global_ldif_cache
    for x_oid in read_oids:
        global_ldif_cache.pop(x_oid, None)
        for x_token_id in list(user_ldif_cache):
            user_ldif_cache[x_token_id].pop(x_oid, None)
        for x_token_id in list(ldap_cache):
            for x_client in list(ldap_cache[x_token_id]):
                ldap_cache[x_token_id][x_client].pop(x_oid, None)
    # A renamed object keeps its UUID but gets a new OID, so a stale
    # entry here would send get_object() looking for something that does
    # not exist anymore.
    for x_uuid in list(uuid_to_oid):
        if uuid_to_oid[x_uuid] not in read_oids:
            continue
        uuid_to_oid.pop(x_uuid, None)
    # Same for a search base that moved: its DN would still point at the
    # directory it used to live in.
    for x_dn in list(lookup_cache):
        if lookup_cache[x_dn]['read_oid'] not in read_oids:
            continue
        lookup_cache.pop(x_dn, None)
    # A token we hold may have been disabled or had its ACLs changed, and
    # we must not go on verifying against the one we read before. Without
    # this it would stay in effect for AUTH_TOKEN_READ_TIMEOUT.
    for x_uuid in list(auth_token_cache):
        if auth_token_cache[x_uuid]['read_oid'] not in read_oids:
            continue
        auth_token_cache.pop(x_uuid, None)

def sync_outdated_objects():
    """ Drop the objects that changed in the meantime from our caches.

    Runs once per request, not per object: asking for the counter is a
    roundtrip to the shared dict, and only a change makes us read the
    objects themselves. See backend.outdate_ldap_object().
    """
    global outdated_counter
    global outdated_time
    global ldap_query_cache
    global ldif_settings_cache
    # Runs once per request, so this is where we get around to it.
    #log_cache_stats()
    # Before the counter: an object that changes while we read must not
    # look older than the point we say we are up to date with.
    now = time.monotonic()
    counter = backend.get_ldap_outdated_counter()
    if counter is None:
        return
    if counter == outdated_counter:
        return
    try:
        outdated_objects, pruned = backend.get_ldap_outdated_objects()
    except Exception as e:
        log_msg = _("Failed to get outdated LDAP objects: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)
        return

    if outdated_time is None:
        # Our first look. Our caches are empty, so there is nothing to
        # drop and everything up to now does not concern us.
        pass
    elif pruned is not None and outdated_time < pruned:
        # We fell behind further than the dict reaches back, so we
        # cannot know what we missed.
        log_msg = _("Missed LDAP cache updates, clearing all caches.", log=True)[1]
        config.logger.warning(log_msg)
        clear_caches()
    else:
        read_oids = set()
        for x_oid in outdated_objects:
            x_time = outdated_objects[x_oid]
            if x_time is None:
                continue
            if x_time <= outdated_time:
                continue
            read_oids.add(x_oid)
        if read_oids:
            drop_cached_objects(read_oids)
            # These are keyed by the search, not by object, so we cannot
            # tell which of them the changed objects belong to.
            ldap_query_cache.clear()
            ldif_settings_cache.clear()

    outdated_counter = counter
    outdated_time = now

def get_ldif_settings(auth_token_uuid):
    """ Get the LDIF settings that apply to the given token.

    Takes the UUID, not the token: without a cache hit we do not even
    have to load the token object.
    """
    global ldif_settings_cache
    now = time.time()
    try:
        cache_entry = ldif_settings_cache[auth_token_uuid]
    except KeyError:
        cache_entry = None
    if cache_entry is not None:
        cache_age = now - cache_entry['time']
        if cache_age < LDIF_SETTINGS_CACHE_TIME:
            return cache_entry
    auth_token = None
    if auth_token_uuid:
        auth_token = backend.get_object(uuid=auth_token_uuid)
    whitelist_attributes = get_ldif_whitelist_attributes(auth_token=auth_token)
    cache_entry = {
        'time'                  : now,
        'whitelist_attributes'  : whitelist_attributes,
        'whitelist_id'          : get_ldif_whitelist_id(whitelist=whitelist_attributes),
        'on_request_attributes' : get_on_request_attributes(auth_token=auth_token),
        }
    ldif_settings_cache[auth_token_uuid] = cache_entry
    return cache_entry

def get_on_request_attributes(auth_token=None):
    """ Get the attributes that are only handed out when asked for.

    Comes from the "ldap_on_request_attributes" config parameter of the
    requesting token (token -> user -> unit -> site), so a client that
    really wants the photos with every search can be exempted. Without a
    token we ask our own site. Returned lowercase: LDAP attribute names
    are case insensitive.
    """
    attributes = None
    if auth_token:
        try:
            attributes = auth_token.get_config_parameter("ldap_on_request_attributes")
        except Exception:
            attributes = None
    if attributes is None:
        my_site = None
        if config.site_uuid:
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
        if my_site:
            try:
                attributes = my_site.get_config_parameter("ldap_on_request_attributes")
            except Exception:
                attributes = None
    if attributes is None:
        attributes = ON_REQUEST_ATTRIBUTES
    return {x.lower() for x in attributes}

def get_ldif_attributes(attributes):
    """ Get the attributes an LDAP search asked for.

    Returns None if the client wants them all, else the attributes to
    build. "dn" and "objectClass" are always included: get_ldif() only
    renders the DN line when objectClass is asked for, and the search
    reads the DN back out of the rendered LDIF.

    ldaptor hands us the list from the search request as bytes (see
    RFC 4511: no attributes means all user attributes, "*" all user
    attributes, "+" the operational ones, "1.1" none).
    """
    if not attributes:
        return None
    _attributes = []
    for x_attr in attributes:
        if isinstance(x_attr, bytes):
            x_attr = x_attr.decode()
        if x_attr == "*":
            return None
        if x_attr == "+":
            continue
        if x_attr == "1.1":
            continue
        _attributes.append(x_attr)
    if not _attributes:
        return None
    _attributes.append("dn")
    _attributes.append("objectClass")
    return tuple(sorted(set(_attributes)))

def get_ldif_attributes_id(attributes):
    """ Get a stable ID of the requested attributes, for cache keys. """
    if attributes is None:
        return "all"
    return ",".join(attributes)

def count_cache(cache_name, hit):
    """ Note down whether one of our caches had what we wanted.

    The calls to this are commented out. Uncomment them (and the
    log_cache_stats() call in sync_outdated_objects()) to get the hit
    rates of every cache into the log again.
    """
    global cache_stats
    try:
        counters = cache_stats[cache_name]
    except KeyError:
        counters = {'hit':0, 'miss':0}
        cache_stats[cache_name] = counters
    if hit:
        counters['hit'] += 1
    else:
        counters['miss'] += 1

def log_cache_stats():
    """ Log how well our caches did since we last said so.

    Counting is cheap, and without it there is no way to tell a cache
    that does not help from one that is not asked. With several ldapd
    processes every one of them keeps its own caches, so every one of
    them writes its own line.
    """
    global cache_stats
    global cache_stats_time
    now = time.time()
    if not cache_stats_time:
        cache_stats_time = now
        return
    if now - cache_stats_time < CACHE_STATS_INTERVAL:
        return
    cache_stats_time = now
    if not cache_stats:
        return
    stats = []
    for x_name in sorted(cache_stats):
        x_hit = cache_stats[x_name]['hit']
        x_miss = cache_stats[x_name]['miss']
        x_total = x_hit + x_miss
        if not x_total:
            continue
        x_rate = x_hit / x_total * 100
        stats.append(f"{x_name}={x_rate:.0f}% ({x_hit}/{x_total})")
    cache_stats.clear()
    if not stats:
        return
    log_msg = _("LDAP cache hits: {stats}", log=True)[1]
    log_msg = log_msg.format(stats=" ".join(stats))
    config.logger.info(log_msg)

def split_client_dn(object_dn):
    """ Get the OTPme client out of a DN, and the DN without it.

    A client picks its accessgroup by putting a "dc=" of its own left of
    the realm, which is what get_ldif() inserts as the fake DC. Which
    object a DN means does not depend on that part, so everything we
    cache by DN is cached under the DN without it -- otherwise the same
    object would sit in the cache once per client, and invalidating it
    would mean knowing every client there is.

    Returns the client, the DN without it and the realm.
    """
    realm = None
    client = None
    dn_parts = object_dn.split(",")
    realm_parts = []
    for x_part in reversed(dn_parts):
        if not x_part.startswith("dc="):
            continue
        if realm:
            # Left of the realm, so this one names a client.
            client = x_part.split("=")[1]
            continue
        realm_parts.insert(0, re.sub('^dc=', '', x_part))
        x_realm = ".".join(realm_parts)
        if x_realm == config.realm:
            realm = x_realm
    real_dn = object_dn
    if client:
        real_dn = ",".join(x for x in dn_parts if x != f"dc={client}")
    return client, real_dn, realm

def get_lookup_cache(object_dn):
    """ Get what we know about a search base we resolved before.

    ldaptor resolves the base of every request, and doing that means an
    "ldif:dn" search over all object types plus get_oid() plus
    get_config_paths(). Three backend queries to answer the same
    question every time, because the base of a client hardly ever
    changes.
    """
    global lookup_cache
    try:
        cache_entry = lookup_cache[object_dn]
    except KeyError:
        cache_entry = None
    if cache_entry is not None:
        age = time.time() - cache_entry['time']
        if age < shared_query_cache_time:
            #count_cache("base", True)
            return cache_entry
    # Nothing of ours, so ask what our siblings resolved.
    cache_entry = get_shared_lookup_cache(object_dn)
    if cache_entry is None:
        #count_cache("base", False)
        return
    # Keep it here as well, so next time we do not have to ask.
    lookup_cache[object_dn] = cache_entry
    #count_cache("base", True)
    return cache_entry

def update_lookup_cache(object_dn, config_dir, object_id):
    """ Remember a DN we resolved.

    Keyed by the DN without the client part, see split_client_dn(). No
    client in here either: it belongs to the request, and our caller
    reads it from the DN it was asked for.
    """
    global lookup_cache
    cache_entry = {
                'time'          : time.time(),
                'config_dir'    : config_dir,
                'read_oid'      : object_id.read_oid,
                }
    lookup_cache[object_dn] = cache_entry
    update_shared_lookup_cache(object_dn, cache_entry)

def get_shared_lookup_key(object_dn):
    """ Get the key a resolved DN is stored under.

    From the backend, so what we write and what outdate_ldap_lookup()
    drops cannot drift apart.
    """
    return backend.get_ldap_lookup_key(object_dn)

def get_shared_lookup_cache(object_dn):
    """ Get a search base another ldapd process resolved. """
    if not shared_cache_enabled:
        return
    try:
        cache_entry = multiprocessing.ldap_shared_lookups[get_shared_lookup_key(object_dn)]
    except KeyError:
        return
    except Exception as e:
        log_msg = _("Failed to read shared LDAP lookups: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)
        return
    if not cache_entry:
        return
    age = time.time() - cache_entry['time']
    if age >= shared_query_cache_time:
        return
    return cache_entry

def update_shared_lookup_cache(object_dn, cache_entry):
    """ Hand a resolved search base to the other ldapd processes. """
    if not shared_cache_enabled:
        return
    try:
        multiprocessing.ldap_shared_lookups.add(get_shared_lookup_key(object_dn),
                                            cache_entry,
                                            expire=shared_query_cache_time)
    except Exception as e:
        log_msg = _("Failed to write shared LDAP lookups: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)

def get_cache_token_id(auth_token, whitelist_id, attributes_id, verify_acls):
    """ Get the token part of our cache keys.

    The LDIF we cache is filtered by the tokens ACLs, by the LDIF
    whitelist in effect for it and by the attributes the search asked
    for, so all of it belongs into the key: after a change of
    "ldif_whitelist_attributes" the entries built with the old list must
    not be found anymore, and a search for a few attributes must not be
    answered from an entry built for another set.

    verify_acls is part of it as well. We cache what a search would
    build, and that is not the same thing with the ACL check on as it is
    with it off, so turning "ldap_verify_acls" back on must not find the
    entries we built without it.

    Without a token they all share one key. That happens for the search
    base of every request: ldaptor looks it up before it knows the bind,
    so it gets built without one (see LDIFTreeEntry.lookup() and
    OTPmeLDAPServer._cbSearchGotBase()). There are no ACLs to filter by
    then, so what we build is the same for everyone.
    """
    if auth_token is None:
        token_uuid = "no-token"
    else:
        token_uuid = auth_token.uuid
    return f"{token_uuid}|{whitelist_id}|{attributes_id}|{verify_acls}"

def copy_ldif_data(object_data):
    """ Get a private copy of cached object data.

    Our callers only modify the LDIF: get_object() drops the attributes
    the search must not see and get_ldif() sorts the objectClass values
    in place. So copying the LDIF (and its value lists) is enough, and
    way cheaper than a copy.deepcopy() of the whole thing for every
    object of a search that returns thousands of them.
    """
    object_data = dict(object_data)
    object_ldif = object_data['ldif']
    if isinstance(object_ldif, dict):
        object_ldif = {x:list(object_ldif[x]) for x in object_ldif}
    else:
        object_ldif = list(object_ldif)
    object_data['ldif'] = object_ldif
    return object_data

def get_ldap_cache(auth_token, whitelist_id, attributes_id, verify_acls,
    client, object_id):
    """ Get cached entry. """
    global ldap_cache
    token_id = get_cache_token_id(auth_token, whitelist_id, attributes_id,
                                verify_acls)
    read_oid = object_id.read_oid
    try:
        cache_time = ldap_cache[token_id][client][read_oid]['TIME']
    except KeyError:
        #count_cache("entry", False)
        return
    cache_age = time.time() - cache_time
    if cache_age >= 300:
        try:
            cached_object_checksum = ldap_cache[token_id][client][read_oid]['CHECKSUM']
        except KeyError:
            #count_cache("entry", False)
            return
        try:
            object_checksum = backend.get_checksum(object_id)
        except Exception:
            object_checksum = None
        # Each of these is a backend query of its own, so count how many
        # of them we make and how often they tell us anything new.
        #count_cache("csum", object_checksum == cached_object_checksum)
        if object_checksum != cached_object_checksum:
            #count_cache("entry", False)
            return
    ldap_cache[token_id][client][read_oid]['TIME'] = time.time()
    cache_entry = ldap_cache[token_id][client][read_oid]['ENTRY']
    #count_cache("entry", True)
    return cache_entry

def update_ldap_cache(auth_token, whitelist_id, attributes_id, verify_acls,
    client, object_id, ldap_entry, checksum):
    """ Add cache entry. """
    global ldap_cache
    token_id = get_cache_token_id(auth_token, whitelist_id, attributes_id,
                                verify_acls)
    read_oid = object_id.read_oid
    if token_id not in ldap_cache:
        ldap_cache[token_id] = {}
    if client not in ldap_cache[token_id]:
        ldap_cache[token_id][client] = {}
    if read_oid not in ldap_cache[token_id][client]:
        ldap_cache[token_id][client][read_oid] = {}
    ldap_cache[token_id][client][read_oid]['TIME'] = time.time()
    ldap_cache[token_id][client][read_oid]['ENTRY'] = ldap_entry
    ldap_cache[token_id][client][read_oid]['CHECKSUM'] = checksum

def get_ldap_search_cache(auth_token, whitelist_id, attributes_id, verify_acls,
    client, cache_key):
    """ Get cached entry. """
    global ldap_query_cache
    token_id = get_cache_token_id(auth_token, whitelist_id, attributes_id,
                                verify_acls)
    try:
        cache_time = ldap_query_cache[token_id][client][cache_key]['time']
        cache_entry = ldap_query_cache[token_id][client][cache_key]['entries']
    except KeyError:
        #count_cache("query", False)
        return
    cache_age = time.time() - cache_time
    if cache_age >= 300:
        #count_cache("query", False)
        return
    #cache_entry = copy.deepcopy(cache_entry)
    #count_cache("query", True)
    return cache_entry

def update_ldap_search_cache(auth_token, whitelist_id, attributes_id,
    verify_acls, client, cache_key, entries):
    """ Add cache entry. """
    global ldap_query_cache
    token_id = get_cache_token_id(auth_token, whitelist_id, attributes_id,
                                verify_acls)
    if not token_id in ldap_query_cache:
        ldap_query_cache[token_id] = {}
    if client not in ldap_query_cache[token_id]:
        ldap_query_cache[token_id][client] = {}
    if cache_key not in ldap_query_cache[token_id][client]:
        ldap_query_cache[token_id][client][cache_key] = {}
    ldap_query_cache[token_id][client][cache_key]['entries'] = entries
    ldap_query_cache[token_id][client][cache_key]['time'] = time.time()

def get_shared_query_key(auth_token, whitelist_id, attributes_id, verify_acls,
    client, cache_key):
    """ Get the key a search is stored under for all ldapd processes.

    Hashed, because the readable form is the base DN plus the whole
    search filter. That gets long, and memcached refuses a key over 250
    bytes or one with a space in it -- and a filter can easily have
    both.
    """
    token_id = get_cache_token_id(auth_token, whitelist_id, attributes_id,
                                verify_acls)
    return stuff.gen_sha256(f"{token_id}|{client}|{cache_key}")

def get_shared_search_cache(auth_token, whitelist_id, attributes_id,
    verify_acls, client, cache_key):
    """ Get a search another ldapd process already did.

    Returns the UUIDs it found, or None. The entries themselves are not
    in there: they carry ldaptor objects, and those do not survive
    serialization -- an LDAPAttributeSet comes back empty without
    saying so. What we do share is the data a search brings along
    anyway, so whoever gets a hit here can build the entries without
    touching the backend at all.
    """
    global uuid_to_oid
    global global_ldif_cache
    if not shared_cache_enabled:
        return
    shared_key = get_shared_query_key(auth_token, whitelist_id, attributes_id,
                                    verify_acls, client, cache_key)
    try:
        cache_entry = multiprocessing.ldap_shared_queries[shared_key]
    except KeyError:
        return
    except Exception as e:
        log_msg = _("Failed to read shared LDAP queries: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)
        return
    if not cache_entry:
        return
    cache_age = time.time() - cache_entry['time']
    if cache_age >= shared_query_cache_time:
        return

    # Take the object data over. Without it get_object() would go and
    # ask the backend for every single object of the result, which is
    # worse than the one search we just saved.
    now = time.time()
    objects = cache_entry['objects']
    for x_oid in objects:
        x_data = objects[x_oid]
        global_ldif_cache[x_oid] = {'time':now, 'data':x_data}
        uuid_to_oid[x_data['uuid']] = x_oid
    return cache_entry['uuids']

def update_shared_search_cache(auth_token, whitelist_id, attributes_id,
    verify_acls, client, cache_key, uuids):
    """ Hand our search over to the other ldapd processes. """
    global uuid_to_oid
    global global_ldif_cache
    if not shared_cache_enabled:
        return
    objects = {}
    for x_uuid in uuids:
        try:
            x_oid = uuid_to_oid[x_uuid]
            objects[x_oid] = global_ldif_cache[x_oid]['data']
        except KeyError:
            # Whatever we cannot hand over completely we leave out, so
            # nobody gets a result with holes in it.
            return
    cache_entry = {
                'time'      : time.time(),
                'uuids'     : list(uuids),
                'objects'   : objects,
                }
    shared_key = get_shared_query_key(auth_token, whitelist_id, attributes_id,
                                    verify_acls, client, cache_key)
    try:
        # With an expiry, so a process that goes away leaves nothing
        # behind that anyone has to clean up.
        multiprocessing.ldap_shared_queries.add(shared_key, cache_entry,
                                            expire=shared_query_cache_time)
    except Exception as e:
        log_msg = _("Failed to write shared LDAP queries: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        config.logger.warning(log_msg)

class CachedSearchResultEntry(pureber.BERBase):
    """ A search result entry we encoded before.

    ldaptor wraps whatever we hand to reply() into an LDAPMessage and
    calls toWire() on it, and that message is a BER sequence of the
    request ID and us. So returning the bytes we kept gives byte for
    byte what encoding the entry again would, without us having to know
    the request ID to build the envelope ourselves.
    """
    def __init__(self, wire):
        self.wire = wire

    def toWire(self):
        return self.wire

    def __repr__(self):
        return f"{self.__class__.__name__}(<{len(self.wire)} bytes>)"

class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""

class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""

class StoreParsedLDIF(ldifprotocol.LDIF):
    # Allow bigger jpgPhoto.
    MAX_LENGTH = 1024000000
    def __init__(self):
        self.done = False
        self.seen = []

    def gotEntry(self, obj):
        self.seen.append(obj)

    def connectionLost(self, reason):
        self.done = True

@implementer(interfaces.IConnectedLDAPEntry)
class LDIFTreeEntry(entry.BaseLDAPEntry,
                    #entry.EditableLDAPEntry,
                    #entryhelpers.DiffTreeMixin,
                    #entryhelpers.SubtreeFromChildrenMixin,
                    #entryhelpers.MatchMixin,
                    #entryhelpers.SearchByTreeWalkingMixin,
    ):
    """ Class that adds LDAP support to OTPme using twisted ldaptor. """

    def __init__(self, path, dn=None, auth_token=None, client=None,
        attributes=None, object_data=None, verify_acls=None,
        object_id=None, *a, **kw):
        if dn is None:
            dn = ''

        self.logger = config.logger
        self.auth_token_uuid = None
        # Without a path we resolve it from the OID when we need it.
        self._path = None
        self._path_oid = object_id
        # The encoded search result we hand to the client, keyed by the
        # attributes the request asked for. Encoding one costs more than
        # everything else a cached search does, and what comes out only
        # depends on our DN and our attributes, so it is good for as long
        # as we are. Riding along on the entry also means it goes away
        # with us when the object changes, see drop_cached_objects().
        self.ldap_payloads = {}

        if auth_token:
            self.auth_token = auth_token
        else:
            try:
                self.auth_token
            except Exception:
                self.auth_token = None

        if client:
            self.client = client
        else:
            try:
                self.client
            except Exception:
                self.client = None

        entry.BaseLDAPEntry.__init__(self, dn, *a, **kw)

        # Must be set before _load(): it reads the object through
        # get_object(), which filters by both and keys its caches on
        # them (see get_cache_token_id()).
        self.update_ldif_settings()
        # The attributes the search asked for, None for all of them.
        self.attributes = get_ldif_attributes(attributes)
        self.attributes_id = get_ldif_attributes_id(self.attributes)

        self.path = path
        if dn != '':
            self._load(object_data=object_data, verify_acls=verify_acls)

    @property
    def path(self):
        """ Get the fs path of our object.

        Resolving it from the OID is an index query, and a search that
        returns thousands of objects would run one for each of them. So
        the search hands us the OID and we resolve the path if anyone
        really wants it.
        """
        if self._path is None:
            if self._path_oid is None:
                return None
            config_paths = get_config_paths(object_id=self._path_oid)
            self._path = re.sub('[/]$', '', config_paths['config_dir'])
        return self._path

    @path.setter
    def path(self, path):
        if path is None:
            self._path = None
        else:
            self._path = re.sub('[/]$', '', path)

    def ldap_verify_acls(self, auth_token=None):
        if auth_token is None:
            auth_token = self.auth_token
        if not auth_token:
            return False
        ldap_verify_acls = auth_token.get_config_parameter("ldap_verify_acls")
        if ldap_verify_acls is False:
            return False
        if auth_token.is_admin():
            return False
        return True

    def update_ldif_settings(self):
        """ Take over the LDIF settings of our auth token.

        Must run again whenever the token changes: the entry a search
        runs on is created without one (ldaptor looks it up before the
        bind is known) and gets its token assigned afterwards, on every
        search (see OTPmeLDAPServer._cbSearchGotBase()). Resolving only
        in __init__ would leave the search entry on the whitelist of our
        site, and a change of the tokens "ldif_whitelist_attributes"
        would never reach the cache keys built from it.

        Runs for every entry a search builds, so the values themselves
        come from get_ldif_settings(), which caches them.
        """
        ldif_settings = get_ldif_settings(self.auth_token_uuid)
        self.whitelist_attributes = ldif_settings['whitelist_attributes']
        self.whitelist_id = ldif_settings['whitelist_id']
        self.on_request_attributes = ldif_settings['on_request_attributes']

    def _load(self, object_data=None, verify_acls=None):
        """ Load LDIF of self.dn.

        A search that builds an entry has read the object already, so it
        hands us its data and we do not read it a second time.
        """
        # Handle subschmema requests.
        if self.dn.getText() == "cn=Subschema":
            ldif = f"dn: {self.dn}\ncn: Subschema\nobjectClass: subschema\n"
            oc_ldif = ""
            attr_ldif = ""
            #attr_syntax_ldif = ""

            for i in config.ldap_object_classes:
                oc_ldif = f"{oc_ldif}objectClasses: {config.ldap_object_classes[i]}\n"

            for i in config.ldap_attribute_types:
                attr_ldif = f"{attr_ldif}attributeTypes: {config.ldap_attribute_types[i]}"
                #attr_desc = config.ldap_attribute_types[i].desc
                #attr_syntax = config.ldap_attribute_types[i].syntax
                #if attr_syntax != None and attr_desc != None:
                #    attr_syntax_ldif = f"{attr_syntax_ldif}ldapSyntaxes: ( {attr_syntax_ldif} DESC '{attr_desc}' )\n"
                #print(config.ldap_attribute_types[i].oid, config.ldap_attribute_types[i].equality, config.ldap_attribute_types[i].syntax)

            # FIXME: how to implement ldapSyntaxes, matchingRules, and matchingRuleUse like returned in schema search of openldap?
            # ldapsearch -H ldap://127.0.0.1 -b cn=Subschema -D "uid=testuser1,ou=Users,ou=site,dc=realm,dc=tld" -w otp -s base -x '(objectClass=subschema)' attributeTypes dITStructureRules objectClasses nameForms dITContentRules matchingRules ldapSyntaxes matchingRuleUse
            # ldaptor-fetchschema --base="dc=domain,dc=tld"  --service-location="dc=domain,dc=tld:127.0.0.1:389"

            #ldif = f"{ldif}{attr_syntax_ldif}"
            ldif = f"{ldif}{oc_ldif}"
            ldif = f"{ldif}{attr_ldif}"
            ldif = f"{ldif}\n"

        else:
            #r = []
            #realm = None
            #for i in reversed(self.dn.getText().split(",")):
            #    if not i.startswith("dc="):
            #        break
            #    if realm:
            #        # Get OTPme client from DN.
            #        self.client = i.split("=")[1]
            #        #msg = f"Using client from DN: {self.client}"
            #        #log.msg(msg, logLevel=logging.DEBUG)
            #    r.insert(0, i.replace("dc=", ""))
            #    x = ".".join(r)
            #    if x == config.realm:
            #        realm = x

            # Handle OTPme object requests.
            if object_data is None:
                if not self.otpme_oid:
                    msg = _("Not an OTPme file backend path: {path}")
                    msg = msg.format(path=self.path)
                    raise OTPmeException(msg)

                if verify_acls is None:
                    verify_acls = self.ldap_verify_acls()

                # Get object data from cache.
                object_data = self.get_object(self.otpme_oid,
                                            fake_dc=self.client,
                                            verify_acls=verify_acls,
                                            attributes=self.attributes)
            object_name = object_data['name']
            object_type = object_data['type']
            ldif = object_data['ldif']

            if object_type == "realm":
                dc_parts = object_name.split(".")
                full_dn = f"dc={',dc='.join(dc_parts)}"
                dc_parts.reverse()
                dn = ""
                for p in dc_parts:
                    if dn == "":
                        dn = f"dc={p}"
                    else:
                        dn = f"dc={p},{dn}"
                    if dn == self.dn:
                        dc = p
                        break

                if dn == full_dn:
                    ldif = f"{chr(10).join(ldif)}\n\n"
                else:
                    ldif = f"dn: {dn}\nobjectClass: dcObject\ndc: {dc}\n\n"
            else:
                ldif = f"{chr(10).join(ldif)}\n\n"

        ldif = ldif.encode("utf-8")
        try:
            parser = StoreParsedLDIF()
            parser.dataReceived(ldif)
        except Exception as e:
            log_msg = _("Failed to load LDIF: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        entries = parser.seen

        if len(entries) == 0:
            raise LDIFTreeEntryContainsNoEntries
        elif len(entries) > 1:
            raise (LDIFTreeEntryContainsMultipleEntries, entries)
        else:
            # TODO ugliness and all of its friends
            for k,v in entries[0].items():
                self._attributes[k] = attributeset.LDAPAttributeSet(k, v)

    def bind(self, password):
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        return defer.maybeDeferred(self._bind, password)

    def _bind(self, password):
        """ Authenticate user against OTPme. """
        if self.client is None:
            log_msg = _("Missing client DC: {dn_text}", log=True)[1]
            log_msg = log_msg.format(dn_text=self.dn.getText())
            self.logger.warning(log_msg)
            raise ldaperrors.LDAPInvalidCredentials

        # Get username from DN.
        username = self.dn.getText().split(",")[0].split("=")[1]

        result = backend.search(object_type="client",
                                attribute="name",
                                value=self.client,
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")

        if not result:
            log_msg = _("Unknown client: {client}", log=True)[1]
            log_msg = log_msg.format(client=self.client)
            self.logger.warning(log_msg)
            raise ldaperrors.LDAPInvalidCredentials

        do_auth = True
        cache_auth = False
        auth_client = result[0]
        if auth_client.auth_cache_enabled:
            cache_auth = True
            try:
                auth_cache_timeout = auth_client.auth_cache_timeout
                self.auth_token_uuid = auth_cache.verify(self.client,
                                                        username,
                                                        password,
                                                        auth_cache_timeout)
                self.update_ldif_settings()
                # Get audit logger.
                audit_logger = config.audit_logger
                log_msg = _("User authenticated to ldapd by cache: {username}", log=True)[1]
                log_msg = log_msg.format(username=username)
                self.logger.info(log_msg)
                if audit_logger:
                    audit_msg = f"{config.daemon_name}: {log_msg}"
                    audit_logger.info(audit_msg)
                do_auth = False
            except AuthFailed:
                do_auth = True
            except Exception as e:
                do_auth = True
                log_msg = _("Auth cache failed: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

        if do_auth:
            # Get authd connection.
            try:
                authd_conn = connections.get("authd",
                                            realm=config.realm,
                                            site=config.site,
                                            auto_auth=False,
                                            do_preauth=False,
                                            auto_preauth=False,
                                            interactive=False,
                                            handle_response=True,
                                            socket_uri=config.authd_socket_path,
                                            local_socket=True,
                                            use_ssl=False,
                                            handle_host_auth=False,
                                            handle_user_auth=False,
                                            encrypt_session=False)
            except Exception as e:
                log_msg = _("Failed to get authd connection: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
                raise

            # Build command args.
            command_args = {
                            'username'  : username,
                            'password'  : password,
                            'client'    : self.client,
                            }

            # Send verify request.
            try:
                status, \
                status_code, \
                auth_response, \
                binary_data = authd_conn.send(command="verify",
                                    command_args=command_args)
            except Exception as e:
                log_msg = _("Failed to authenticate user: {username}: {error}", log=True)[1]
                log_msg = log_msg.format(username=username, error=e)
                self.logger.warning(log_msg)
                raise ldaperrors.LDAPInvalidCredentials from e
            finally:
                authd_conn.close()

            if status is False:
                log_msg = _("Failed to authenticate user: {username}: {response}", log=True)[1]
                log_msg = log_msg.format(username=username, response=auth_response)
                self.logger.warning(log_msg)
                raise ldaperrors.LDAPInvalidCredentials

            # Set auth token.
            self.auth_token_uuid = auth_response[0]['login_token_uuid']
            self.update_ldif_settings()
            # Cache authentication.
            if cache_auth:
                try:
                    session_uuid= auth_response[0]['session']
                except KeyError:
                    session_uuid = None
                auth_cache.add(self.client, username, password, session_uuid, self.auth_token_uuid)

        return self

    @property
    def otpme_oid(self):
        otpme_oid = get_oid_from_path(self.path)
        return otpme_oid

    @property
    def auth_token(self):
        """ Get our token.

        Reading it is a backend query, and a search asks for it more
        than once, so we keep it for AUTH_TOKEN_READ_TIMEOUT seconds.
        That long is also how long a token that got disabled or had its
        ACLs changed stays in effect here.
        """
        if not self.auth_token_uuid:
            return
        now = time.time()
        cache_entry = auth_token_cache.get(self.auth_token_uuid)
        if cache_entry is not None:
            if now - cache_entry['time'] < AUTH_TOKEN_READ_TIMEOUT:
                return cache_entry['token']
        auth_token = backend.get_object(uuid=self.auth_token_uuid)
        update_auth_token_cache(self.auth_token_uuid, auth_token)
        return auth_token

    @auth_token.setter
    def auth_token(self, auth_token):
        if auth_token is None:
            self.auth_token_uuid = None
        else:
            self.auth_token_uuid = auth_token.uuid
            # Handed to us, so it is as good as one we just read.
            update_auth_token_cache(self.auth_token_uuid, auth_token)
        # The whitelist comes from the token, see update_ldif_settings().
        self.update_ldif_settings()

    def parent(self):
        if self.dn == '':
            # root
            return None
        parentPath, _ = os.path.split(self.path)
        return self.__class__(parentPath, self.dn.up())

    #def _sync_children(self):
    #    child_objects = {}
    #    children = []
    #    get_childs = True

    #    if self.dn != "":
    #        if self.o.type == "realm":
    #            dc_parts = self.o.name.split(".")
    #            full_dn = "dc=" + ",dc=".join(dc_parts)
    #            if self.dn != full_dn:
    #                dc_parts.reverse()
    #                object_dn = ""
    #                match = False
    #                for p in dc_parts:
    #                    if object_dn == "":
    #                        object_dn = "dc=" + p
    #                    else:
    #                        object_dn = "dc=" + p + "," + object_dn
    #                    if match:
    #                        break
    #                    if object_dn == self.dn:
    #                        match = True

    #                get_childs = False
    #                object_base = object_dn.split(",")[0]
    #                child_objects[object_dn] = [self.path, object_base]


    #    if get_childs:
    #        try:
    #            filenames = os.listdir(self.path)
    #        except OSError, e:
    #            if e.errno == e.errno.ENOENT:
    #                pass
    #            else:
    #                raise

    #        for fn in filenames:
    #            ext = fn.split(".")[-1:][0]

    #            if ext not in config.object_types:
    #                continue

    #            object_path = os.path.join(self.path, fn)
    #            object_id = get_oid_from_path(object_path)
    #            object_dn = False

    #            result = backend.search(attributes="read_oid",
    #                                    value=object_id.read_oid,
    #                                    return_attributes=['ldif:dn'])
    #            if result:
    #                object_dn = result[0]
    #            else:
    #                o = backend.get_object(object_id=object_id)
    #                if o:
    #                    if o.type == "realm":
    #                        object_dn = "dc=" + o.name.split(".")[-1]
    #                    else:
    #                        for a in o.ldif:
    #                            if a.startswith('dn: '):
    #                                object_dn = re.sub('^dn: ', '', a)
    #                                break
    #        if object_dn:
    #            object_base = object_dn.split(",")[0]
    #            child_objects[object_dn] = [object_path, object_base]

    #    for object_dn in child_objects:
    #        object_path = child_objects[object_dn][0]
    #        object_base = child_objects[object_dn][1]

    #        dn = distinguishedname.DistinguishedName(
    #            listOfRDNs=((distinguishedname.RelativeDistinguishedName(object_base),)
    #                        + self.dn.split()))
    #        e = self.__class__(os.path.join(object_path), dn)
    #        children.append(e)
    #    return children

    #def _children(self, callback=None):
    #    children = self._sync_children()
    #    if callback is None:
    #        return children
    #    else:
    #        for c in children:
    #            callback(c)
    #        return None

    #def children(self, callback=None):
    #    return defer.maybeDeferred(self._children, callback=callback)

    def lookup(self, dn):
        """
        Lookup the given object (dn) and return it as
        distinguishedname.DistinguishedName.
        """
        # Runs for the base of every request, so this is where a bind
        # gets its caches up to date.
        sync_outdated_objects()
        object_dn = dn.getText()

        cache_entry = None
        if object_dn != "cn=Subschema":
            # The client belongs to the request, not to the object, so
            # take it from the DN we were asked for -- every time, and
            # also when there is none. Reading it back out of the cache
            # would hand one client the client of another, and leaving
            # it alone would carry the one of the request before along.
            client, real_dn, realm = split_client_dn(object_dn)
            self.client = client
            cache_entry = get_lookup_cache(real_dn)

        if object_dn == "cn=Subschema":
            config_dir = self.path
        elif cache_entry is not None:
            config_dir = cache_entry['config_dir']
        else:
            # Get object UUID from backend via 'dn' search.
            result = backend.search(attribute="ldif:dn",
                                    value=real_dn,
                                    realm=realm)
                                    # No need to add site because DN includes site (dc=...).
                                    #site=site)
            if len(result) == 0:
                return defer.fail(ldaperrors.LDAPNoSuchObject(dn))

            uuid = result[0]
            # Get object config dir.
            object_id = backend.get_oid(uuid, instance=True)
            config_dir = get_config_paths(object_id=object_id)['config_dir']
            update_lookup_cache(real_dn, config_dir, object_id)

        if not os.path.isdir(config_dir):
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn))

        dn = distinguishedname.DistinguishedName(object_dn)

        # Create object instance and return it.
        e = self.__class__(config_dir, dn, self.auth_token, self.client)
        return defer.succeed(e)

    def __repr__(self):
        return f'{self.__class__.__name__}({self.path!r}, {self.dn.getText()!r})'

    def gen_cache_key(self, filterObject, sizeLimit=0, timeLimit=0, scope=None):
        """ Generate cache key for ldap search cache.

        The scope belongs in it: the same filter under the same base
        returns something else with "base" than it does with "sub", and
        a shared cache would carry that mix over to every process.
        """
        value =  None
        cache_key = self.dn.getText()

        if isinstance(filterObject, pureldap.LDAPFilter_and):
            cache_key += "+and"
            for f in filterObject:
                cache_key += self.gen_cache_key(f)

        elif isinstance(filterObject, pureldap.LDAPFilter_or):
            cache_key += "+or"
            for f in filterObject:
                cache_key += self.gen_cache_key(f)
        else:
            if isinstance(filterObject, pureldap.LDAPFilter_present):
                cache_key += "+present="
                cache_key += filterObject.value.decode()
            elif isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
                cache_key += "+equalityMatch="
                cache_key += filterObject.attributeDesc.value.decode()
                cache_key += filterObject.assertionValue.value.decode()
            elif isinstance(filterObject, pureldap.LDAPFilter_substrings):
                cache_key += "+substrings="
                cache_key += filterObject.type.decode()
                sub_count = 0
                for s in filterObject.substrings:
                    s_value = s.value
                    if isinstance(s_value, bytes):
                        s_value = s_value.decode("utf-8")
                        cache_key += s_value
                    if isinstance(filterObject.substrings[sub_count],
                                pureldap.LDAPFilter_substrings_initial):
                        if not value:
                            value = f"{s_value}*"
                        else:
                            value = f"{value}{value}{s_value}*"
                        cache_key += value
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_any):
                        if not value:
                            value = f"*{s_value}*"
                        else:
                            if value.endswith("*"):
                                value = f"{value}{s_value}*"
                            else:
                                value = f"{value}*{s_value}*"
                        cache_key += value
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_final):
                        if not value:
                            value = f"*{s_value}"
                        else:
                            if value.endswith("*"):
                                value = f"{value}{s_value}"
                            else:
                                value = f"{value}*{s_value}"
                        cache_key += value
                    sub_count += 1

            elif isinstance(filterObject, pureldap.LDAPFilter_greaterOrEqual):
                cache_key += "+greaterOrEqual="
                cache_key += filterObject.attributeDesc.value.decode()
                cache_key += str(int(filterObject.assertionValue.value) - 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_lessOrEqual):
                cache_key += "+lessOrEqual="
                cache_key += filterObject.attributeDesc.value.decode()
                cache_key += str(int(filterObject.assertionValue.value) + 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_not):
                if isinstance(filterObject.value, pureldap.LDAPFilter_present):
                    msg = _("Invalid search filter: not filter with '*'")
                    raise ldapsyntax.MatchNotImplemented(msg)
                if isinstance(filterObject.value, pureldap.LDAPFilter_substrings):
                    cache_key += self.gen_cache_key(filterObject.value)
                elif isinstance(filterObject.value, pureldap.LDAPFilter_equalityMatch):
                    cache_key += "+not="
                    cache_key += f'!{filterObject.value.assertionValue.value.decode()}'
                else:
                    msg = _("Invalid search filter: unsupported inner filter type in NOT: {t}")
                    msg = msg.format(t=type(filterObject.value).__name__)
                    raise ldapsyntax.MatchNotImplemented(msg)

        cache_key += f"{sizeLimit}"
        cache_key += f"{timeLimit}"
        if scope is not None:
            cache_key += f"+scope={scope}"

        return cache_key

    def get_ldif_attribute(self, attribute):
        x = attribute.lower()
        try:
            try:
                ldif_attribute = config.ldap_object_class_mappings[x]
            except Exception:
                ldif_attribute = config.ldap_attribute_type_mappings[x]
        except Exception as e:
            msg = _("Invalid attribute: {attribute}")
            msg = msg.format(attribute=attribute)
            raise ldapsyntax.MatchNotImplemented(msg) from e
        ldif_attribute = f"ldif:{ldif_attribute}"
        return ldif_attribute

    def decode_and_filter(self, filterObject, search_attributes=None):
        if search_attributes is None:
            search_attributes = {}
        for f in filterObject:
            if isinstance(f, pureldap.LDAPFilter_and):
                search_attributes = self.decode_and_filter(f, search_attributes)
                continue
            if isinstance(f, pureldap.LDAPFilter_or):
                search_attributes = self.decode_or_filter(f, search_attributes)
                continue
            attribute, \
            value, \
            greater_than, \
            less_than = self.decode_ldap_filter(f)
            ldif_attribute = self.get_ldif_attribute(attribute)
            try:
                attr_data = search_attributes[ldif_attribute]
            except KeyError:
                attr_data = {}
                search_attributes[ldif_attribute] = attr_data
            try:
                and_values = attr_data['values']
            except KeyError:
                and_values = []
                attr_data['values'] = and_values
            if less_than is not None or greater_than is not None:
                if less_than is not None:
                    and_values.append({'less_than':less_than})
                if greater_than is not None:
                    and_values.append({'greater_than':greater_than})
            else:
                and_values.append(value)
        return search_attributes

    def decode_or_filter(self, filterObject, search_attributes=None):
        if search_attributes is None:
            search_attributes = {}
        for f in filterObject:
            if isinstance(f, pureldap.LDAPFilter_or):
                search_attributes = self.decode_or_filter(f, search_attributes)
                continue
            if isinstance(f, pureldap.LDAPFilter_and):
                search_attributes = self.decode_and_filter(f, search_attributes)
                continue
            attribute, \
            value, \
            greater_than, \
            less_than = self.decode_ldap_filter(f)
            ldif_attribute = self.get_ldif_attribute(attribute)
            # Set attribute.
            try:
                attr_data = search_attributes[ldif_attribute]
            except Exception:
                attr_data = {}
                search_attributes[ldif_attribute] = attr_data
            try:
                or_values = attr_data['or_values']
            except KeyError:
                or_values = []
                attr_data['or_values'] = or_values
            if less_than is not None or greater_than is not None:
                if less_than is not None:
                    or_values.append({'less_than':less_than})
                if greater_than is not None:
                    or_values.append({'greater_than':greater_than})
            else:
                or_values.append(value)
        return search_attributes

    def decode_ldap_filter(self, filterObject):
        """ Decode ldap filter object. """
        value = None
        less_than = None
        attribute = None
        greater_than = None
        if isinstance(filterObject, pureldap.LDAPFilter_present):
            attribute = filterObject.value.decode()
            value = "*"
        elif isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
            attribute = filterObject.attributeDesc.value.decode()
            value = filterObject.assertionValue.value.decode()
            value = stuff.string_to_type(value)
        elif isinstance(filterObject, pureldap.LDAPFilter_substrings):
            value = None
            sub_count = 0
            attribute = filterObject.type.decode()
            for f in filterObject.substrings:
                s_value = f.value
                if isinstance(s_value, bytes):
                    s_value = s_value.decode("utf-8")
                if isinstance(filterObject.substrings[sub_count],
                            pureldap.LDAPFilter_substrings_initial):
                    if not value:
                        value = f"{s_value}*"
                    else:
                        value = f"{value}{value}{s_value}*"
                elif isinstance(filterObject.substrings[sub_count],
                                pureldap.LDAPFilter_substrings_any):
                    if not value:
                        value = f"*{s_value}*"
                    else:
                        if value.endswith("*"):
                            value = f"{value}{s_value}*"
                        else:
                            value = f"{value}*{s_value}*"
                elif isinstance(filterObject.substrings[sub_count],
                                pureldap.LDAPFilter_substrings_final):
                    if not value:
                        value = f"*{s_value}"
                    else:
                        if value.endswith("*"):
                            value = f"{value}{s_value}"
                        else:
                            value = f"{value}*{s_value}"
                sub_count += 1
        elif isinstance(filterObject, pureldap.LDAPFilter_greaterOrEqual):
            attribute = filterObject.attributeDesc.value.decode()
            greater_than = int(filterObject.assertionValue.value) - 1
        elif isinstance(filterObject, pureldap.LDAPFilter_lessOrEqual):
            attribute = filterObject.attributeDesc.value.decode()
            less_than = int(filterObject.assertionValue.value) + 1
        elif isinstance(filterObject, pureldap.LDAPFilter_not):
            if isinstance(filterObject.value, pureldap.LDAPFilter_present):
                msg = _("Invalid search filter: not filter with '*'")
                raise ldapsyntax.MatchNotImplemented(msg)
            if isinstance(filterObject.value, pureldap.LDAPFilter_substrings):
                attribute, \
                value, \
                greater_than, \
                less_than = self.decode_ldap_filter(filterObject.value)
                value = f"!{value}"
            elif isinstance(filterObject.value, pureldap.LDAPFilter_equalityMatch):
                attribute = filterObject.value.attributeDesc.value.decode()
                value = f'!{filterObject.value.assertionValue.value.decode()}'
            else:
                msg = _("Invalid search filter: unsupported inner filter type in NOT: {t}")
                msg = msg.format(t=type(filterObject.value).__name__)
                raise ldapsyntax.MatchNotImplemented(msg)
        else:
            msg = "Invalid ldap filter: {filterObject}"
            msg = msg.format(filterObject=type(filterObject))
            raise OTPmeException(msg)
        return attribute, value, greater_than, less_than

    def search_otpme(self, filterText=None, filterObject=None,
        attributes=(), sizeLimit=0, timeLimit=0, typesOnly=0, **kwargs):
        """ Search OTPme backend. """
        #if filterObject is None and filterText is None:
        #    filterObject = pureldap.LDAPFilterMatchAll

        ## Whats ldapfilter?????
        ##elif filterObject is None and filterText is not None:
        ##    filterObject = ldapfilter.parseFilter(filterText)

        ##elif filterObject is not None and filterText is not None:
        ##    f = ldapfilter.parseFilter(filterText)
        ##    filterObject=pureldap.LDAPFilter_and((f, filterObject))

        #elif filterObject is not None and filterText is None:
        #    pass

        if isinstance(filterObject, pureldap.LDAPFilter_and):
            search_attributes = {}
            search_attributes = self.decode_and_filter(filterObject, search_attributes)
            result_uuids = self._search_otpme(attributes=search_attributes,
                                            size_limit=sizeLimit,
                                            **kwargs)
        elif isinstance(filterObject, pureldap.LDAPFilter_or):
            search_attributes = {}
            search_attributes = self.decode_or_filter(filterObject, search_attributes)
            result_uuids = self._search_otpme(attributes=search_attributes,
                                            size_limit=sizeLimit,
                                            **kwargs)
        else:
            attribute, \
            value, \
            greater_than, \
            less_than = self.decode_ldap_filter(filterObject)
            ldif_attribute = self.get_ldif_attribute(attribute)
            result_uuids = self._search_otpme(attribute=ldif_attribute,
                                            value=value,
                                            less_than=less_than,
                                            greater_than=greater_than,
                                            size_limit=sizeLimit,
                                            **kwargs)
        if sizeLimit > 0:
            result_uuids = result_uuids[:sizeLimit]

        return result_uuids

    def get_object(self, object_id, verify_acls=None, fake_dc=None,
        attributes=None, auth_token=None):
        global user_ldif_cache
        global global_ldif_cache
        attributes_id = get_ldif_attributes_id(attributes)
        read_oid = object_id.read_oid
        object_type = object_id.object_type

        # Loading our token means a backend query, so a search that runs
        # us for each of its objects resolves it once and hands it over.
        if auth_token is None:
            auth_token = self.auth_token

        if verify_acls is None:
            verify_acls = True
            if auth_token:
                if auth_token.is_admin():
                    verify_acls = False

        if verify_acls and not auth_token:
            msg = _("Unable to verify ACLs without token.")
            raise OTPmeException(msg)

        # Try to get the object data from the LDIF cache. Also without a
        # token: the search base of every request is built before the
        # bind is known, so it comes without one and would otherwise be
        # rendered again for every single request.
        cache_token_id = get_cache_token_id(auth_token, self.whitelist_id,
                                        attributes_id, verify_acls)
        try:
            object_data = user_ldif_cache[cache_token_id][read_oid]['data']
            object_data = copy_ldif_data(object_data)
            cache_time = user_ldif_cache[cache_token_id][read_oid]['time']
        except Exception:
            object_data = None
        if object_data:
            check_cache_time = True
            object_client = object_data['client']
            if object_client:
                if object_client != self.client:
                    check_cache_time = False
            if check_cache_time:
                now = time.time()
                age = now - cache_time
                if age < LDIF_CACHE_TIME:
                    #count_cache("ldif", True)
                    return object_data
                object_checksum = object_data['checksum']
                x_checksum = backend.get_checksum(object_id)
                #count_cache("csum", object_checksum == x_checksum)
                if object_checksum == x_checksum:
                    user_ldif_cache[cache_token_id][read_oid]['time'] = time.time()
                    #count_cache("ldif", True)
                    return object_data
        #count_cache("ldif", False)

        # Try to get object data from global cache.
        try:
            cache_entry = global_ldif_cache[read_oid]
        except KeyError:
            cache_entry = None
        do_search = True
        if cache_entry is not None:
            object_data = copy_ldif_data(cache_entry['data'])
            do_search = False
            # This cache is shared by every token, and a search that
            # verifies no ACLs does not fetch any. Taking its entry for
            # one that does would filter every attribute away, so read
            # the object again to get them.
            if verify_acls and object_data['acls'] is None:
                do_search = True
            # The searches we run fill the global cache from the backend,
            # so an entry that young was verified a moment ago. Asking the
            # backend for the checksum again is one index query per object.
            age = time.time() - cache_entry['time']
            if age >= LDIF_CACHE_TIME:
                object_checksum = object_data['checksum']
                x_checksum = backend.get_checksum(object_id)
                #count_cache("csum", object_checksum == x_checksum)
                if object_checksum != x_checksum:
                    do_search = True
        # Whether the raw LDIF of the object was there. A miss here means
        # we have to ask the backend for it.
        #count_cache("raw", not do_search)

        if do_search:
            # Try to get object data from backend.
            result = self._search_otpme(object_type=object_type,
                                        attribute="read_oid",
                                        value=read_oid)
            if len(result) > 1:
                msg = _("Found more than one object for: {oid}")
                msg = msg.format(oid=read_oid)
                raise OTPmeException(msg)

            try:
                object_data = copy_ldif_data(global_ldif_cache[read_oid]['data'])
            except Exception:
                msg = _("Unknown object: {oid}")
                msg = msg.format(oid=read_oid)
                raise UnknownObject(msg) from None

        object_ldif = object_data['ldif']
        if not object_ldif:
            msg = _("Object without ldif: {oid}")
            msg = msg.format(oid=read_oid)
            raise UnknownObject(msg)

        object_uuid = object_data['uuid']
        object_name = object_data['name']
        object_type = object_data['type']
        object_acls = object_data['acls']
        object_checksum = object_data['checksum']
        if attributes is None:
            # Wildcard search: hold back the attributes that are only
            # handed out when asked for by name.
            for x_attr in dict(object_ldif):
                if x_attr.lower() not in self.on_request_attributes:
                    continue
                object_ldif.pop(x_attr)
        else:
            # Drop what the search did not ask for before we verify any
            # ACL for it. LDAP attribute names are case insensitive.
            requested_attributes = {x.lower() for x in attributes}
            for x_attr in dict(object_ldif):
                if x_attr.lower() in requested_attributes:
                    continue
                object_ldif.pop(x_attr)
        if verify_acls:
            for x_attr in dict(object_ldif):
                if x_attr in self.whitelist_attributes:
                    continue
                x_acl = f"view:attribute:{x_attr}"
                result = otpme_acl.verify(uuid=object_uuid,
                                        acl_list=object_acls,
                                        acl=x_acl,
                                        check_admin_role=True,
                                        check_admin_user=True,
                                        need_exact_acl=False,
                                        auth_token=auth_token)
                if result:
                    continue
                object_ldif.pop(x_attr)

        # We filtered above, so let get_ldif() render what is left: its
        # own filter is case sensitive and would drop attributes whose
        # spelling differs from the search request.
        object_ldif = get_ldif(object_ldif, text=False, fake_dc=fake_dc)
        object_data['ldif'] = object_ldif

        # Caching this does not depend on whether we verified any ACLs.
        # The key covers the token, the LDIF whitelist, the attributes
        # the search asked for and the ACL check itself (see
        # get_cache_token_id()), so what we put in matches what we would
        # build again. Tying it to the ACL check left a token with
        # "ldap_verify_acls" turned off -- the fast path -- without any
        # cache at all.
        if cache_token_id not in user_ldif_cache:
            user_ldif_cache[cache_token_id] = {}
        user_ldif_cache[cache_token_id][read_oid] = {}
        user_ldif_cache[cache_token_id][read_oid]['time'] = time.time()
        user_ldif_cache[cache_token_id][read_oid]['data'] = {
                                            'uuid'      : object_uuid,
                                            'read_oid'  : read_oid,
                                            'name'      : object_name,
                                            'type'      : object_type,
                                            'ldif'      : object_ldif,
                                            'acls'      : object_acls,
                                            'checksum'  : object_checksum,
                                            'client'    : self.client,
                                            }
        return object_data

    @ldap_search_cache.cache_method()
    def _search_otpme(self, attribute=None, value=None, attributes=None,
        object_type=None, less_than=None, greater_than=None,
        size_limit=1024, scope="one", verify_acls=True):
        """ Search OTPme objects. """
        global global_ldif_cache
        global uuid_to_oid
        search_attributes = {
                                #'l'     : {'value':"Sitename",},
                                'template'  : {'value':False,},
                            }
        if verify_acls:
            search_attributes['acl'] = {
                                        'values' : [
                                                    "*:edit",
                                                    "*:edit:*",
                                                    "*:view",
                                                    "*:view:*",
                                                    "*:view_all",
                                                    "*:view_all:*",
                                                    "*:view_public",
                                                    "*:view_public:*",
                                                    "*:view:attribute",
                                                    "*:view:attribute:*",
                                                    "*:view_all:attribute",
                                                    "*:view_all:attribute:*",
                                                    "*:view_public:attribute",
                                                    "*:view_public:attribute:*",
                                                    ],
                                    }

        # Add attribute and values.
        if attribute and value is not None:
            search_attributes[attribute] = {'value':value}
        if attribute and less_than is not None:
            search_attributes[attribute] = {'less_than':less_than}
        if attribute and greater_than is not None:
            search_attributes[attribute] = {'greater_than':greater_than}

        # Add attributes and values.
        if attributes:
            for attr in attributes:
                vals = attributes[attr]
                search_attributes[attr] = vals

        ldap_settings = config.get_ldap_settings(self.otpme_oid.object_type)
        if ldap_settings:
            object_scopes = ldap_settings['scopes']
            default_scope = ldap_settings['default_scope']
            if scope not in object_scopes:
                scope = default_scope
        if scope == "one":
            object_type = self.otpme_oid.object_type
            search_attributes['name'] = {'value':self.otpme_oid.name}
        if scope == "sub":
            path = f"{self.otpme_oid.path}/*"
            search_attributes['path'] = {'value':path}

        return_attributes = ['read_oid', 'name', 'object_type', 'ldif', 'checksum']

        # Without an object type the backend queries every one of them,
        # and OTPme has 31 while only the ones registered as LDAP objects
        # can ever carry an LDIF. The rest cannot match, but each of them
        # still costs a query the database has to plan.
        object_types = None
        if object_type is None:
            object_types = list(config.ldap_object_types)

        result = backend.search(object_type=object_type,
                                object_types=object_types,
                                attributes=search_attributes,
                                case_sensitive=False,
                                return_raw_acls=verify_acls,
                                less_than=less_than,
                                greater_than=greater_than,
                                return_attributes=return_attributes,
                                max_results=size_limit)

        # Asked for the ACLs we get them next to the objects, otherwise
        # the objects are all there is.
        if verify_acls:
            acls = result['acls']
            objects = result['objects']
        else:
            acls = None
            objects = result

        for x_uuid in objects:
            object_name = objects[x_uuid]['name']
            object_id = objects[x_uuid]['read_oid']
            object_type = objects[x_uuid]['object_type']
            object_checksum = objects[x_uuid]['checksum']
            object_ldif = objects[x_uuid]['ldif']
            # None, not an empty list: we did not ask for them, and
            # whoever finds this in the cache has to tell "this object
            # has no ACLs" from "nobody looked".
            object_acls = None
            if verify_acls:
                object_acls = acls[x_uuid]

            uuid_to_oid[x_uuid] = object_id

            try:
                cache_entry = global_ldif_cache[object_id]
            except KeyError:
                cache_entry = None

            if cache_entry is not None:
                if cache_entry['data']['checksum'] == object_checksum:
                    # Data is unchanged. But we just got the checksum from
                    # the backend, so mark the entry as verified: it saves
                    # get_object() one index query per object.
                    cache_entry['time'] = time.time()
                    continue

            global_ldif_cache[object_id] = {}
            global_ldif_cache[object_id]['time'] = time.time()
            global_ldif_cache[object_id]['data'] = {
                                                'uuid'      : x_uuid,
                                                'read_oid'  : object_id,
                                                'name'      : object_name,
                                                'type'      : object_type,
                                                'ldif'      : object_ldif,
                                                'acls'      : object_acls,
                                                'checksum'  : object_checksum,
                                                }

        return list(objects.keys())

    def search(self, filterText=None, filterObject=None, attributes=(),
        scope=None, derefAliases=None, sizeLimit=0,
        timeLimit=0, typesOnly=0, callback=None):
        """ Start search as thread. """
        from twisted.internet import threads
        if sizeLimit == 0:
            sizeLimit = 1024
        # Run search as thread.
        # http://www.ianbicking.org/twisted-and-threads.html
        search_defer = threads.deferToThread(self._search,
                                    filterText=filterText,
                                    filterObject=filterObject,
                                    attributes=attributes,
                                    scope=scope,
                                    derefAliases=derefAliases,
                                    sizeLimit=sizeLimit,
                                    timeLimit=timeLimit,
                                    typesOnly=typesOnly)
        if callback is None:
            return search_defer

        def send_entries(entries):
            """ Hand the entries to our caller.

            It writes them to the client, and a twisted transport must
            only be written to from the reactor thread. So this must not
            happen in our search thread: it corrupts the TLS state of the
            connection (bio_read() of a connection that is gone).
            """
            for x_entry in entries:
                callback(x_entry)
            return []

        search_defer.addCallback(send_entries)
        return search_defer

    def _search(self, filterText=None, filterObject=None, attributes=(),
        scope=None, derefAliases=None, sizeLimit=0,
        timeLimit=0, typesOnly=0):
        """ Search LDAP object.

        Returns the entries we found. Sending them to the client is the
        job of our caller, see search().
        """
        from ldaptor.protocols import pureldap
        results = []
        schema_search = False

        # Get rid of what changed since our last search before we answer
        # anything from cache.
        sync_outdated_objects()

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        if scope == pureldap.LDAP_SCOPE_wholeSubtree:
            scope = "sub"
        elif scope == pureldap.LDAP_SCOPE_singleLevel:
            scope = "one"
        elif scope == pureldap.LDAP_SCOPE_baseObject:
            scope = "base"
        else:
            msg = _("Unknown search scope: {scope!r}")
            msg = msg.format(scope=scope)
            raise ldaperrors.LDAPProtocolError(msg)

        # Handle schema search requests.
        if isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
            attribute = filterObject.attributeDesc.value
            value = filterObject.assertionValue.value.lower()
            if attribute.lower() == "objectclass" and value.lower() == "subschema":
                schema_search = True
                dn = distinguishedname.DistinguishedName('cn=Subschema')
                e = self.__class__(self.path, dn)
                results.append(e)

        if not schema_search:
            # The attributes the client asked for. We only build those,
            # so they are part of our cache keys as well.
            search_attributes = get_ldif_attributes(attributes)
            attributes_id = get_ldif_attributes_id(search_attributes)
            # Our token is a property that loads it from the backend on
            # every access. Resolve it once, we need it for each object.
            auth_token = self.auth_token
            # Part of our cache keys, so we need it before we look
            # anything up, not just for building the entries.
            verify_acls = self.ldap_verify_acls(auth_token=auth_token)
            cached_entry = None
            shared_uuids = None
            if auth_token:
                cache_key = self.gen_cache_key(filterObject, sizeLimit,
                                            timeLimit, scope)
                cached_entry = get_ldap_search_cache(auth_token, self.whitelist_id,
                                                    attributes_id, verify_acls,
                                                    self.client, cache_key)
                if cached_entry is None:
                    # Nothing of ours, but maybe one of our siblings ran
                    # this very search already.
                    shared_uuids = get_shared_search_cache(auth_token,
                                                    self.whitelist_id,
                                                    attributes_id, verify_acls,
                                                    self.client, cache_key)
            if cached_entry is not None:
                result_objects = cached_entry
            else:
                if shared_uuids is not None:
                    # It brought the object data along, so building the
                    # entries below needs no backend at all.
                    result_uuids = shared_uuids
                else:
                    # Handle OTPme object search requests.
                    try:
                        result_uuids = self.search_otpme(filterText=filterText,
                                                        filterObject=filterObject,
                                                        attributes=(),
                                                        sizeLimit=sizeLimit,
                                                        timeLimit=timeLimit,
                                                        typesOnly=typesOnly,
                                                        scope=scope,
                                                        verify_acls=verify_acls)
                    except SizeLimitExceeded as e:
                        log.msg(str(e), logLevel=logging.WARNING)
                        raise ldaperrors.LDAPSizeLimitExceeded() from e

                result_objects = {}
                for x_uuid in result_uuids:
                    object_dn = None
                    scope_match = False
                    try:
                        object_id = uuid_to_oid[x_uuid]
                        object_id = oid.get(object_id)
                    except Exception as e:
                        object_id = backend.get_oid(uuid=x_uuid, instance=True)

                    # Skip orphan objects.
                    if not object_id:
                        continue

                    # Try to get entry from cache.
                    if auth_token:
                        entry = get_ldap_cache(auth_token, self.whitelist_id,
                                                attributes_id, verify_acls,
                                                self.client, object_id)
                        if entry:
                            object_dn = entry.dn.getText()

                    if not object_dn:
                        if object_id:
                            object_data = self.get_object(object_id,
                                                        fake_dc=self.client,
                                                        verify_acls=verify_acls,
                                                        attributes=search_attributes,
                                                        auth_token=auth_token)
                            object_dn = object_data['ldif'][0][4:]
                            object_id = object_data['read_oid']
                            object_id = oid.get(object_id)
                            object_checksum = object_data['checksum']

                            dn = distinguishedname.DistinguishedName(object_dn)

                            # Create new entry and pass on auth token and
                            # client. It gets the object data we just read,
                            # so it does not read the object again, and
                            # only the OID of the object: resolving its fs
                            # path is an index query we do not need here.
                            entry = self.__class__(None, dn, auth_token,
                                                    self.client, attributes,
                                                    object_data=object_data,
                                                    verify_acls=verify_acls,
                                                    object_id=object_id)
                            # Update cache.
                            if auth_token:
                                update_ldap_cache(auth_token, self.whitelist_id,
                                                attributes_id, verify_acls,
                                                self.client, object_id, entry,
                                                object_checksum)

                    if scope == "base":
                        if self.dn.getText() == object_dn:
                            scope_match = True
                    elif scope == "one":
                        if len(object_dn.split(",")) == (len(self.dn.getText().split(",")) + 1):
                            scope_match = True
                    elif scope == "sub":
                        if self.dn.getText() in object_dn:
                            scope_match = True

                    if scope_match:
                        # A tuple, not a string: with the depth printed
                        # into one, "10 ..." sorts before "3 ..." and a
                        # deep unit tree comes out in the wrong order.
                        dn_path_len = len(object_dn.split(","))
                        result_objects[(dn_path_len, object_dn)] = entry

            # Update ldap search cache.
            if auth_token:
                update_ldap_search_cache(auth_token, self.whitelist_id,
                                        attributes_id, verify_acls, self.client,
                                        cache_key, result_objects)
                if cached_entry is None and shared_uuids is None:
                    # We are the one who did the search, so hand it over.
                    # Coming from one of the two caches there is nothing
                    # to hand over that is not in there already.
                    update_shared_search_cache(auth_token, self.whitelist_id,
                                            attributes_id, verify_acls,
                                            self.client, cache_key,
                                            result_uuids)

            for key in sorted(result_objects):
                results.append(result_objects[key])

        return results

def otpme_log_translate(conf):
    logger = config.logger
    try:
        debug_message = conf['debug']
    except Exception:
        debug_message = False
    try:
        message = conf['message']
    except Exception:
        message = False
    try:
        loglevel = logging.getLevelName(conf['logLevel'])
    except Exception:
        loglevel = config.loglevel

    if message:
        log_msg = message
        if debug_message:
            pass
            #if config.loglevel == "DEBUG" or config.debug_enabled:
            #    self.logger.debug(log_msg)
        else:
            if loglevel == "CRITICAL":
                logger.critical(log_msg)
            if loglevel == "ERROR":
                logger.error(log_msg)
            if loglevel == "WARNING":
                logger.warning(log_msg)
            if loglevel == "INFO":
                logger.info(log_msg)
            if loglevel == "DEBUG":
                logger.debug(log_msg)

class LDAPServerFactory(protocol.ServerFactory):
    def __init__(self, root):
        self.root = root

class OTPmeLDAPServer(ldapserver.LDAPServer):
    if config.loglevel == "DEBUG" or config.debug_enabled:
        debug = True
    else:
        debug = False

    def connectionMade(self):
        # Get peer.
        self.peer = self.transport.getPeer()

    def handle_LDAPBindRequest(self, request, controls, response):
        if request.version != 3:
            msg = _("Version {version} not supported")
            msg = msg.format(version=request.version)
            raise ldaperrors.LDAPProtocolError(msg)

        self.checkControls(controls)

        if request.dn == '':
            # anonymous bind
            self.boundUser = None
            return pureldap.LDAPBindResponse(resultCode=0)

        dn = distinguishedname.DistinguishedName(request.dn)
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)

        def _noEntry(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            return None
        d.addErrback(_noEntry)

        def _gotEntry(entry, auth):
            if entry is None:
                raise ldaperrors.LDAPInvalidCredentials

            # Pass on peer to bind entry.
            entry.peer = self.peer

            d = entry.bind(auth)
            def _cb(entry):
                self.boundUser = entry
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    matchedDN=entry.dn.getText())
                return msg
            d.addCallback(_cb)
            return d
        d.addCallback(_gotEntry, request.auth)

        return d

    def handle_LDAPSearchRequest(self, request, controls, response):
        if self.boundUser is None:
            raise ldaperrors.LDAPStrongAuthRequired()
        return ldapserver.LDAPServer.handle_LDAPSearchRequest(self, request, controls, response)

    def _cbSearchGotBase(self, base, dn, request, response):
        """ Answer a search.

        Same as the one we inherit, except that an entry we already
        encoded is not encoded again. Building the BER tree of a result
        entry costs an object per attribute name and per attribute
        value, which for a search returning a few dozen entries is more
        work than everything else it does put together.

        Clone instead of a call to super() because ldaptor defines the
        method that sends a single entry inside _cbSearchGotBase(), so
        there is nothing to override on its own.
        """
        # Pass on auth token.
        base.auth_token = self.boundUser.auth_token

        requested_attributes = request.attributes
        # What we cache are the bytes for this attribute selection, and
        # the request order is the order they go out in, so the whole
        # list belongs in the key.
        payload_key = tuple(requested_attributes)
        send_all = True
        if requested_attributes:
            if b"*" not in requested_attributes:
                send_all = False

        def send_entry(entry):
            payloads = getattr(entry, "ldap_payloads", None)
            if payloads is None:
                payload = None
            else:
                payload = payloads.get(payload_key)
            if payload is None:
                if send_all:
                    entry_attributes = entry.items()
                else:
                    entry_attributes = [(x, entry.get(x))
                                        for x in requested_attributes
                                        if x in entry]
                result_entry = pureldap.LDAPSearchResultEntry(
                                            objectName=entry.dn.getText(),
                                            attributes=entry_attributes)
                payload = result_entry.toWire()
                if payloads is not None:
                    if len(payloads) < MAX_ENTRY_PAYLOADS:
                        payloads[payload_key] = payload
            response(CachedSearchResultEntry(payload))

        search_defer = base.search(filterObject=request.filter,
                                attributes=request.attributes,
                                scope=request.scope,
                                derefAliases=request.derefAliases,
                                sizeLimit=request.sizeLimit,
                                timeLimit=request.timeLimit,
                                typesOnly=request.typesOnly,
                                callback=send_entry)

        def search_done(_):
            return pureldap.LDAPSearchResultDone(
                            resultCode=ldaperrors.Success.resultCode)

        search_defer.addCallback(search_done)
        return search_defer

class LDAPServer(object):
    """ Class to start an LDAP server as OTPme daemon using ldaptor. """
    def __init__(self, address, port):
        self.address = address
        self.port = int(port)
        # save proctitle
        self.proctitle = setproctitle.getproctitle()
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        log.addObserver(otpme_log_translate)
        #log.startLogging(sys.stderr)

        path = OBJECTS_DIR
        db = LDIFTreeEntry(path)

        # FIXME: not needed anymore?
        #sys.setrecursionlimit(1000000000)

        components.registerAdapter(lambda x: x.root,
                                   LDAPServerFactory,
                                   interfaces.IConnectedLDAPEntry)
        self.reactor = None
        self.factory = LDAPServerFactory(db)
        self.factory.protocol = OTPmeLDAPServer

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        log_msg = _("Received SIGTERM.", log=True)[1]
        self.logger.info(log_msg)
        if config.print_timing_results:
            from otpme.lib import debug
            debug.print_timing_result(print_status=True)
        os._exit(0)

    def listen(self, use_ssl=False, cert=None, key=None,
        ssl_context=None, listen_socket=None):
        """ Start listening.

        With more than one ldapd process both the socket and the SSL
        context are made before they are forked: the socket because
        binding a port below 1024 needs privileges the workers do not
        have anymore, the context so the private key does not have to
        stay on disk while they start up.
        """
        from twisted.internet import ssl
        from twisted.internet import reactor

        # FIXME: also implement StartTLS?
        # https://twistedmatrix.com/documents/12.0.0/core/howto/ssl.html
        # https://twistedmatrix.com/documents/14.0.0/core/howto/ssl.html
        if use_ssl and not (cert and key) and not ssl_context:
            msg = _("'use_ssl' requires 'cert' and 'key'.")
            raise OTPmeException(msg)

        from otpme.lib import net
        listen_uri = net.format_socket_uri("tcp", self.address, self.port)
        if use_ssl:
            new_proctitle = f"{self.proctitle} ListenSSL: {listen_uri}"
            if ssl_context is None:
                ssl_context = ssl.DefaultOpenSSLContextFactory(privateKeyFileName=key,
                                                            certificateFileName=cert)
        else:
            new_proctitle = f"{self.proctitle} Listen: {listen_uri}"
            ssl_context = None

        if listen_socket is not None:
            factory = self.factory
            if ssl_context:
                # listenSSL() wraps the factory for us, adoptStreamPort()
                # hands us a plain TCP port and leaves that to us.
                factory = TLSMemoryBIOFactory(ssl_context, False, factory)
            # adoptStreamPort() takes its own copy of the descriptor. We
            # keep ours open: our parent hands us the very same socket
            # again when it has to start us over.
            reactor.adoptStreamPort(listen_socket.fileno(),
                                    listen_socket.family,
                                    factory)
        elif ssl_context:
            reactor.listenSSL(port=self.port,
                            factory=self.factory,
                            interface=self.address,
                            contextFactory=ssl_context)
        else:
            reactor.listenTCP(port=self.port,
                            factory=self.factory,
                            interface=self.address)

        setproctitle.setproctitle(new_proctitle)
        self.reactor = reactor

    def run(self):
        """ Start LDAP server. """
        from otpme.lib import log
        if not self.reactor:
            msg = _("You need to call listen() first.")
            raise OTPmeException(msg)
        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # FIXME: we need this?
        from otpme.lib.extensions import utils
        extensions = utils.load_extensions(config.extensions)
        for _e in extensions:
            _e.preload()
        # Start.
        self.reactor.run()

    def stop(self):
        """ Stop LDAP server. """
        self.reactor.stop()
