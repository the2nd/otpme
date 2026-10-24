# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The passwords a host keeps for offline use.

otpme-agent fetches them for the user it runs for, at login, at an
interval and whenever idled says that one of them changed (see
OTPmeAgent.sync_pass_cache()). mgmtd decides which: the passwords below
a unit or site whose password_offline_cache names this host, that the
user may see the entries of and holds a key for (see
otpme_password.get_pass_cache()).

What is kept is what the client gets to read them anyway: the payload
and the Fernet key encrypted for the user. It is opened here with the
key script, as online (see otpme.lib.pass_crypt), so the private key of
the user is needed -- a user whose key is kept on the server gets
nothing to keep. Kept in the offline dir of the user, next to the
offline tokens, and replaced as a whole by every fetch.

otpme-pass show, list, list_entries and show_password read it when no
node can be reached, and say how old it is. Nothing is changed offline.
"""
import os
import re
import sys
import json
import time
import fnmatch

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import pass_crypt

from otpme.lib.exceptions import *

CACHE_FILE_NAME = "pass.json"

# What otpme-pass answers from the cache when no node can be reached.
OFFLINE_SUBCOMMANDS = [
                    'show',
                    'list',
                    'list_entries',
                    'show_password',
                    ]

# The columns of "otpme-pass show" that the cache can fill.
SHOW_COLUMNS = [
            ('Password', 'name'),
            ('Unit', 'unit'),
            ('Nodes', 'nodes'),
            ('Hosts', 'hosts'),
            ('Devices', 'devices'),
            ('Clients', 'clients'),
            ('Description', 'description'),
            ]

def get_offline_token(username):
    """ The offline token handler of <username>, for its offline dir. """
    from otpme.lib.offline_token import OfflineToken
    offline_token = OfflineToken()
    offline_token.set_user(username)
    return offline_token

def get_cache_file(username):
    """ Where the passwords of <username> are kept. """
    offline_token = get_offline_token(username)
    return os.path.join(offline_token.offline_dir, CACHE_FILE_NAME)

def write_cache(username, cache):
    """ Keep what mgmtd gave, as a whole and at once.

    Written next to the file and moved over it: a reader sees the old
    file or the new one, never half of one.
    """
    offline_token = get_offline_token(username)
    offline_token.init()
    cache_file = os.path.join(offline_token.offline_dir, CACHE_FILE_NAME)
    data = dict(cache)
    data['synced'] = time.time()
    tmp_file = f"{cache_file}.{os.getpid()}.tmp"
    fd = os.open(tmp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, cache_file)
    except Exception:
        try:
            os.remove(tmp_file)
        except OSError:
            pass
        raise
    return cache_file

def read_cache(username):
    """ What is kept for <username>. """
    cache_file = get_cache_file(username)
    if not os.path.exists(cache_file):
        msg = _("No passwords are kept on this host for offline use.")
        raise OTPmeException(msg)
    with open(cache_file, "r") as f:
        return json.load(f)

def offline_notice(cache):
    """ That this is not what the nodes hold, and how old it is. """
    synced = time.strftime("%Y-%m-%d %H:%M:%S",
                        time.localtime(cache['synced']))
    msg = _("Passwords kept on this host, as of {time}.")
    return msg.format(time=synced)

def find_objects(cache, name):
    """ The kept password of the given name or path. """
    for x_object in cache['objects']:
        if name in (x_object['name'], x_object['rel_path']):
            return [x_object]
    msg = _("Unknown password: {name}")
    msg = msg.format(name=name)
    raise OTPmeException(msg)

def search_objects(cache, search):
    """ The kept passwords "otpme-pass show" would show for <search>.

    As online: a path that ends with a slash asks for the passwords of
    that unit (not of its sub units), "*" and "?" match parts of the
    name, and anything else is one password by name or path.
    """
    if search.endswith("/"):
        unit_path = search.strip("/")
        found = [x for x in cache['objects'] if x['unit'] == unit_path]
    elif any(x in search for x in "*?["):
        found = [x for x in cache['objects']
                if fnmatch.fnmatchcase(x['name'], search)]
    else:
        return find_objects(cache, search)
    if not found:
        msg = _("Unknown password: {name}")
        msg = msg.format(name=search)
        raise OTPmeException(msg)
    return found

def list_names(cache, search_regex=None):
    """ The names of the kept passwords, as "otpme-pass list" has them. """
    names = sorted(x['name'] for x in cache['objects'])
    if search_regex:
        x_re = re.compile(search_regex)
        names = [x for x in names if x_re.search(x)]
    return "\n".join(names)

def show_table(objects):
    """ What the cache knows of "otpme-pass show", as a table. """
    rows = []
    for x_object in sorted(objects, key=lambda x: x['name']):
        x_row = []
        for _header, x_key in SHOW_COLUMNS:
            x_value = x_object.get(x_key)
            if isinstance(x_value, list):
                x_value = ",".join(x_value)
            if x_value is None:
                x_value = ""
            x_row.append(str(x_value))
        rows.append(x_row)
    headers = [x[0] for x in SHOW_COLUMNS]
    widths = [len(x) for x in headers]
    for x_row in rows:
        for x_pos, x_value in enumerate(x_row):
            widths[x_pos] = max(widths[x_pos], len(x_value))
    def format_row(x_row):
        x_cells = [x.ljust(widths[x_pos]) for x_pos, x in enumerate(x_row)]
        return " " + "  ".join(x_cells).rstrip()
    lines = [format_row(headers)]
    lines.append("-" * (sum(widths) + 2 * len(widths)))
    for x_row in rows:
        lines.append(format_row(x_row))
    return "\n".join(lines)

def handle_offline(subcommand, cache, unwrap_key, object_name=None,
    command_args=None):
    """ Answer an otpme-pass command from <cache>.

    <unwrap_key> opens the encrypted Fernet key of the user, the way
    the key script does online. Returns what is to be shown; that it
    is the kept state and how old goes to stderr, so whatever reads
    the output gets the same as online.
    """
    if command_args is None:
        command_args = {}
    if subcommand not in OFFLINE_SUBCOMMANDS:
        msg = _("No node reachable, and this cannot be done offline: {subcommand}")
        msg = msg.format(subcommand=subcommand)
        raise OTPmeException(msg)
    print(offline_notice(cache), file=sys.stderr)
    if subcommand == "list":
        return list_names(cache, command_args.get('search_regex'))
    if subcommand == "show":
        objects = cache['objects']
        if object_name:
            objects = search_objects(cache, object_name)
        return show_table(objects)
    if not object_name:
        msg = _("Error: Please give {command}")
        msg = msg.format(command="pass")
        raise OTPmeException(msg)
    objects = find_objects(cache, object_name)
    action = "list"
    if subcommand == "show_password":
        action = "show"
    entry_name = command_args.get('entry_name')
    _response, output = pass_crypt.read_entries(action, objects,
                                                entry_name, unwrap_key)
    return output
