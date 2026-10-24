# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The client side of the password objects (otpme-pass).

The server never sees a password. It holds a Fernet token with all the
entries of a password object and, per user, the Fernet key encrypted
with the encrypt public key of that user. The rest happens here, in the
client the user runs:

  * The entry a command is about -- its name, username, URL, notes and
    the password itself -- is taken off the command line before the
    command goes to mgmtd, and kept in local_request.

  * mgmtd answers with a PASS_CRYPT callback that carries what it holds:
    the payload, the encrypted key of the caller and the public keys of
    the members. handle_request() decrypts, changes, encrypts and hands
    back ciphertext only. What is to be shown is shown here.
"""
import os
import json
import base64

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.encryption import fernet

from otpme.lib.exceptions import *

# Arguments of the command line that stay on the client.
LOCAL_ARGS = [
            'entry_name',
            'username',
            'url',
            'notes',
            'new_password',
            ]

# The fields of an entry besides its password.
ENTRY_FIELDS = [
            'username',
            'url',
            'notes',
            ]

# Actions that write a new payload.
WRITE_ACTIONS = [
            'add_entry',
            'change_entry',
            'del_entry',
            'update_keys',
            ]

# What the command handler took off the command line, for
# handle_request(). One command per process, so one of these.
local_request = {}

# The config parameter of a unit or site that names the members. It
# holds their signatures as well.
MEMBERS_PARAMETER = "password_store_members"

def members_tag(object_uuid):
    """ The tag of a members signature: which unit or site it is for. """
    return f"{MEMBERS_PARAMETER}:{object_uuid}"

def members_sign_data(object_uuid, member_uuids, user_uuids):
    """ What a members signature covers.

    The members as they are configured and the users they stand for:
    a role that gets a new token holder changes the users and so needs
    a new signature, which is the point. Sorted, so the same lists make
    the same data.
    """
    data = {
            'parameter'     : MEMBERS_PARAMETER,
            'object_uuid'   : object_uuid,
            'members'       : sorted(member_uuids),
            'users'         : sorted(user_uuids),
            }
    return json.dumps(data, sort_keys=True)

def verify_members(request, signers=None):
    """ The users a valid signature of a password signer names.

    The signers are the ones configured on this host (signer type
    "password"), never anything mgmtd sends: whoever runs mgmtd must not
    be able to add themselves. A signature that does not verify counts for
    nothing, and without one valid signature nothing is encrypted.
    """
    members = request.get('members')
    if not members:
        msg = _("No password_store_members configured.")
        raise OTPmeException(msg)
    if signers is None:
        from otpme.lib.classes import signing
        signers = signing.get_signers(signer_type="password")
    if not signers:
        msg = _("No password signer configured on this host, see otpme-tool add_signer --signer-type password.")
        raise OTPmeException(msg)
    from otpme.lib.classes import signing
    object_uuid = members['object_uuid']
    allowed_users = set()
    errors = []
    for x_entry in members['signatures'].values():
        sign_data = members_sign_data(object_uuid,
                                    x_entry['members'],
                                    x_entry['users'])
        x_signature = x_entry['signature']
        try:
            sig = signing.OTPmeSignature(signature=x_signature)
            signatures = {
                        sig.signer_uuid : {
                            sig.sign_id : {
                                'signature' : x_signature,
                                },
                            },
                        }
            signing.verify_signatures(signer_type="password",
                                    signers=signers,
                                    signatures=signatures,
                                    sign_data=sign_data,
                                    tags=[members_tag(object_uuid)])
        except Exception as e:
            errors.append(str(e))
            continue
        allowed_users.update(x_entry['users'])
    if not allowed_users:
        msg = _("No valid signature of password_store_members.")
        if errors:
            msg = f"{msg} {' '.join(errors)}"
        raise OTPmeException(msg)
    return allowed_users

def split_local_args(command_args):
    """ Split command args into the ones we keep and the ones we send. """
    local_args = {}
    remote_args = {}
    for x in command_args:
        if x in LOCAL_ARGS:
            local_args[x] = command_args[x]
            continue
        remote_args[x] = command_args[x]
    return local_args, remote_args

def set_local_request(local_args):
    """ Keep what the command line said about the entry. """
    local_request.clear()
    local_request.update(local_args)

def decrypt_entries(fernet_key, payload):
    """ The entries of a password object. """
    if not payload:
        return {}
    data = fernet.decrypt(fernet_key, payload)
    try:
        data = json.loads(data)
    except Exception as e:
        msg = _("Unable to read password data: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e
    return data['entries']

def encrypt_entries(fernet_key, entries):
    """ The payload for the given entries. """
    data = json.dumps({'entries': entries}, sort_keys=True)
    return fernet.encrypt(fernet_key, data)

def wrap_key(fernet_key, public_key):
    """ Encrypt the Fernet key with the encrypt public key of a user.

    The public key is the one the user object holds, a base64 encoded
    PEM. RSA-OAEP-SHA256 for an RSA key and HPKE for an X25519 key, both
    base64 encoded: what "pkey_encrypt" of the key script writes, so
    "pkey_decrypt" opens it whichever way the user holds the private key
    (file, server, smartcard).
    """
    from otpme.lib import encryption
    if isinstance(fernet_key, str):
        fernet_key = fernet_key.encode()
    pem = base64.b64decode(public_key)
    key = encryption.load_public_key(pem)
    ciphertext = key.encrypt(fernet_key)
    return base64.b64encode(ciphertext).decode()

def apply_change(entries, action, entry_name, fields=None, password=None):
    """ Add, change or delete an entry. """
    if fields is None:
        fields = {}
    if not entry_name:
        msg = _("Missing entry name.")
        raise OTPmeException(msg)
    if action == "add_entry":
        if entry_name in entries:
            msg = _("Entry already exists: {entry_name}")
            msg = msg.format(entry_name=entry_name)
            raise OTPmeException(msg)
        entry = {'password': password}
        for x in ENTRY_FIELDS:
            entry[x] = fields.get(x) or ""
        entries[entry_name] = entry
        return entries
    if entry_name not in entries:
        msg = _("Unknown entry: {entry_name}")
        msg = msg.format(entry_name=entry_name)
        raise OTPmeException(msg)
    if action == "del_entry":
        entries.pop(entry_name)
        return entries
    if action == "change_entry":
        entry = entries[entry_name]
        for x in ENTRY_FIELDS:
            if fields.get(x) is None:
                continue
            entry[x] = fields[x]
        if password is not None:
            entry['password'] = password
        return entries
    msg = _("Unknown action: {action}")
    msg = msg.format(action=action)
    raise OTPmeException(msg)

def format_entry(object_name, entry_name, entry, show_password=True):
    """ One entry for the terminal. """
    lines = [f"{object_name}/{entry_name}"]
    for x in ['username', 'password', 'url', 'notes']:
        if x == "password" and not show_password:
            continue
        value = entry.get(x) or ""
        lines.append(f"    {x}: {value}")
    return "\n".join(lines)

def ask_password(get_password):
    """ Ask for the password of an entry, twice. """
    while True:
        password1 = get_password(_("Password: "))
        password2 = get_password(_("Repeat password: "))
        if password1 == password2:
            return password1
        print(_("Sorry, passwords do not match."))

def handle_request(request, unwrap_key, get_password, local_args=None,
    check_members=verify_members, check_keys=None):
    """ Handle a PASS_CRYPT request of mgmtd.

    <unwrap_key> decrypts an encrypted Fernet key (the key script),
    <get_password> asks the user, <check_members> answers which users
    a valid signature names (verify_members()). <check_keys> holds the
    keys mgmtd sends to the ones written down on this host, see
    user_key_pins.check_keys(); without it the keys are taken as they
    come (PIN_USER_KEYS off). Returns the answer for mgmtd and what is
    to be shown here.
    """
    if local_args is None:
        local_args = local_request
    action = request['action']
    objects = request['objects']
    entry_name = local_args.get('entry_name')
    fields = {}
    for x in ENTRY_FIELDS:
        fields[x] = local_args.get(x)

    if action not in WRITE_ACTIONS:
        return read_entries(action, objects, entry_name, unwrap_key)

    x_object = objects[0]
    # Only the users a signature names, and of those only the ones that
    # are still members: a change of the members can take a key away
    # without a new signature, but never give one.
    allowed_users = check_members(request)
    recipients = {}
    unsigned = []
    for x_uuid, x_recipient in request['recipients'].items():
        if x_uuid in allowed_users:
            recipients[x_uuid] = x_recipient
            continue
        unsigned.append(x_recipient['name'])
    lines = []
    if unsigned:
        x_line = _("Not signed, no key: {users}")
        lines.append(x_line.format(users=", ".join(sorted(unsigned))))
    # Only keys that are the ones written down on this host.
    if check_keys is not None:
        recipients, not_pinned, changed = check_keys(recipients)
        if not_pinned:
            x_line = _("Key not pinned on this host, no key: {users}")
            lines.append(x_line.format(users=", ".join(sorted(not_pinned))))
        if changed:
            x_line = _("Key changed, no key until otpme-tool update_user_keys: {users}")
            lines.append(x_line.format(users=", ".join(sorted(changed))))
    output = None
    if lines:
        output = "\n".join(lines)
    key_users = set(x_object['key_users'])
    rotate = False
    if x_object['fernet_key']:
        fernet_key = unwrap_key(x_object['fernet_key'])
        entries = decrypt_entries(fernet_key, x_object['payload'])
    elif key_users:
        msg = _("You hold no key for this password: {object_name}")
        msg = msg.format(object_name=x_object['name'])
        raise OTPmeException(msg)
    else:
        fernet_key = None
        entries = {}
        rotate = True

    if action == "update_keys":
        # Users that left can still hold the key, from an earlier read.
        # A new key keeps them out of what is written from now on.
        if key_users - set(recipients):
            rotate = True
    else:
        password = None
        if action == "add_entry" \
        or (action == "change_entry" and local_args.get('new_password')):
            password = ask_password(get_password)
        entries = apply_change(entries, action, entry_name,
                                fields=fields, password=password)

    if rotate:
        if not recipients:
            msg = _("Nobody to encrypt the password for, see password_store_members.")
            raise OTPmeException(msg)
        fernet_key = fernet.gen_key()
        wrap_users = list(recipients)
    else:
        wrap_users = [x for x in recipients if x not in key_users]

    fernet_keys = {}
    for x_uuid in wrap_users:
        x_public_key = recipients[x_uuid]['public_key']
        fernet_keys[x_uuid] = wrap_key(fernet_key, x_public_key)

    response = {
            'payload'       : encrypt_entries(fernet_key, entries),
            'fernet_keys'   : fernet_keys,
            'rotated'       : rotate,
            }
    return response, output

def read_entries(action, objects, entry_name, unwrap_key):
    """ Show or list the entries of the given objects. """
    found = []
    unreadable = []
    for x_object in objects:
        if not x_object['fernet_key']:
            # Empty, or not for us.
            if x_object['key_users']:
                unreadable.append(x_object['name'])
            continue
        fernet_key = unwrap_key(x_object['fernet_key'])
        entries = decrypt_entries(fernet_key, x_object['payload'])
        for x_name in sorted(entries):
            if entry_name and x_name != entry_name:
                continue
            found.append((x_object['name'], x_name, entries[x_name]))

    if unreadable and not found:
        msg = _("You hold no key for this password: {object_name}")
        msg = msg.format(object_name=", ".join(sorted(unreadable)))
        raise OTPmeException(msg)

    if entry_name:
        if not found:
            msg = _("Unknown entry: {entry_name}")
            msg = msg.format(entry_name=entry_name)
            raise OTPmeException(msg)
        if len(found) > 1:
            x_names = ", ".join(sorted(x[0] for x in found))
            msg = _("Entry found in more than one password: {entry_name}: {objects}")
            msg = msg.format(entry_name=entry_name, objects=x_names)
            raise OTPmeException(msg)

    show_password = action == "show"
    output = []
    for x_object_name, x_name, x_entry in found:
        output.append(format_entry(x_object_name, x_name, x_entry,
                                    show_password=show_password))
    # Only that it was done goes back.
    return {'shown': True}, "\n".join(output)
