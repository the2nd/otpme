# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

def auth_ldap(username, password):
    import ldap
    import ldap.dn
    import ldap.filter
    ldap_server="ldap.domain.intern"
    safe_uid_dn = ldap.dn.escape_dn_chars(username)
    safe_uid_filter = ldap.filter.escape_filter_chars(username)
    user_dn = f"uid={safe_uid_dn},ou=users,dc=domain,dc=intern"
    base_dn = "dc=domain,dc=intern"
    connect = ldap.initialize(f'ldaps://{ldap_server}')
    search_filter = f"(uid={safe_uid_filter})"
    try:
        # If authentication successful, get the full user data
        connect.bind_s(user_dn,password)
        connect.search_s(base_dn,ldap.SCOPE_SUBTREE,search_filter)
        # Return all user data results
        connect.unbind_s()
        return True
    except ldap.LDAPError:
        connect.unbind_s()
        raise

# Python 3
def auth_ldap3(bind_dn, username, password):
    from ldap3 import Server
    from ldap3 import Connection
    from ldap3.utils.conv import escape_filter_chars
    ldap_server="ldap.domain.intern"
    base_dn = "dc=domain,dc=intern"
    attributes = ['uid']
    search_filter = f"(uid={escape_filter_chars(username)})"
    server = Server(ldap_server)
    conn = Connection(server, bind_dn, password, auto_bind=True)
    conn.search(base_dn, search_filter, attributes=attributes)
    #print(conn.response[0]['attributes']['uid'][0])
    conn.unbind()
