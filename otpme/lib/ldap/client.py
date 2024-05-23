# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def auth_ldap(username, password):
    import ldap
    ldap_server="ldap.domain.intern"
    user_dn = "uid=%s,ou=users,dc=domain,dc=intern" % username
    base_dn = "dc=domain,dc=intern"
    connect = ldap.initialize('ldaps://%s' % ldap_server)
    search_filter = "uid=%s" % username
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
    ldap_server="ldap.domain.intern"
    base_dn = "dc=domain,dc=intern"
    attributes = ['uid']
    search_filter = "uid=%s" % username
    server = Server(ldap_server)
    conn = Connection(server, bind_dn, password, auto_bind=True)
    conn.search(base_dn, search_filter, attributes=attributes)
    #print(conn.response[0]['attributes']['uid'][0])
    conn.unbind()
