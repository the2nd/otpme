# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import copy
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

#from twisted.mail.maildir import _generateMaildirName as tempName
from ldaptor.protocols import pureldap

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.cache import ldap_search_cache
from otpme.lib.classes.otpme_object import get_ldif
from otpme.lib.backends.file.file import get_oid_from_path
from otpme.lib.backends.file.file import get_config_paths
from otpme.lib.backends.file.file import OBJECTS_DIR

from otpme.lib.exceptions import *

ldap_cache = {}
ldap_query_cache = {}

uuid_to_oid = {}
user_ldif_cache = {}
global_ldif_cache = {}

LDAP_CLIENT_NAME = "LDAP"
LDAP_ACCESSGROUP = "LDAP"

REGISTER_BEFORE = []
REGISTER_AFTER = [
                "otpme.lib.classes.client",
                "otpme.lib.classes.accessgroup",
                ]

logger = config.logger

def register():
    register_config()

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

def get_ldap_cache(auth_token, client, object_id):
    """ Get cached entry. """
    global ldap_cache
    read_oid = object_id.read_oid
    try:
        cache_time = ldap_cache[auth_token.uuid][client][read_oid]['TIME']
    except KeyError:
        return
    cache_age = time.time() - cache_time
    if cache_age >= 300:
        try:
            cached_object_checksum = ldap_cache[auth_token.uuid][client][read_oid]['CHECKSUM']
        except KeyError:
            return
        try:
            object_checksum = backend.get_checksum(object_id)
        except:
            object_checksum = None
        if object_checksum != cached_object_checksum:
            return
    ldap_cache[auth_token.uuid][client][read_oid]['TIME'] = time.time()
    cache_entry = ldap_cache[auth_token.uuid][client][read_oid]['ENTRY']
    return cache_entry

def update_ldap_cache(auth_token, client, object_id, ldap_entry, checksum):
    """ Add cache entry. """
    global ldap_cache
    read_oid = object_id.read_oid
    if auth_token.uuid not in ldap_cache:
        ldap_cache[auth_token.uuid] = {}
    if client not in ldap_cache[auth_token.uuid]:
        ldap_cache[auth_token.uuid][client] = {}
    if read_oid not in ldap_cache[auth_token.uuid][client]:
        ldap_cache[auth_token.uuid][client][read_oid] = {}
    ldap_cache[auth_token.uuid][client][read_oid]['TIME'] = time.time()
    ldap_cache[auth_token.uuid][client][read_oid]['ENTRY'] = ldap_entry
    ldap_cache[auth_token.uuid][client][read_oid]['CHECKSUM'] = checksum

def get_ldap_search_cache(auth_token, client, cache_key):
    """ Get cached entry. """
    global ldap_cache
    global ldap_query_cache
    if config.ldap_cache_clear:
        ldap_cache.clear()
        ldap_query_cache.clear()
        config.ldap_cache_clear = False
        return
    try:
        cache_time = ldap_query_cache[auth_token.uuid][client][cache_key]['time']
        cache_entry = ldap_query_cache[auth_token.uuid][client][cache_key]['entries']
    except KeyError:
        return
    cache_age = time.time() - cache_time
    if cache_age >= 300:
        if config.ldap_object_changed:
            ldap_query_cache.clear()
            config.ldap_object_changed = False
        return
    #cache_entry = copy.deepcopy(cache_entry)
    return cache_entry

def update_ldap_search_cache(auth_token, client, cache_key, entries):
    """ Add cache entry. """
    global ldap_query_cache
    if not auth_token.uuid in ldap_query_cache:
        ldap_query_cache[auth_token.uuid] = {}
    if client not in ldap_query_cache[auth_token.uuid]:
        ldap_query_cache[auth_token.uuid][client] = {}
    if cache_key not in ldap_query_cache[auth_token.uuid][client]:
        ldap_query_cache[auth_token.uuid][client][cache_key] = {}
    ldap_query_cache[auth_token.uuid][client][cache_key]['entries'] = entries
    ldap_query_cache[auth_token.uuid][client][cache_key]['time'] = time.time()

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

    def __init__(self, path, dn=None, auth_token=None, client=None, *a, **kw):
        if dn is None:
            dn = ''

        self.auth_token_uuid = None

        if auth_token:
            self.auth_token = auth_token
        else:
            try:
                self.auth_token
            except:
                self.auth_token = None

        if client:
            self.client = client
        else:
            try:
                self.client
            except:
                self.client = None

        entry.BaseLDAPEntry.__init__(self, dn, *a, **kw)

        self.path = re.sub('[/]$', '', path)
        if dn != '':
            self._load()

    def _load(self):
        """ Load LDIF of self.dn. """
        # Handle subschmema requests.
        if self.dn.getText() == "cn=Subschema":
            ldif = "dn: %s\ncn: Subschema\nobjectClass: subschema\n" % self.dn
            oc_ldif = ""
            attr_ldif = ""
            #attr_syntax_ldif = ""

            for i in config.ldap_object_classes:
                oc_ldif = ("%sobjectClasses: %s\n"
                        % (oc_ldif, config.ldap_object_classes[i]))

            for i in config.ldap_attribute_types:
                attr_ldif = "%sattributeTypes: %s" % (attr_ldif,
                                                config.ldap_attribute_types[i])
                #attr_desc = config.ldap_attribute_types[i].desc
                #attr_syntax = config.ldap_attribute_types[i].syntax
                #if attr_syntax != None and attr_desc != None:
                #    attr_syntax_ldif = "%sldapSyntaxes: ( %s DESC '%s' )\n"
                #                    % (attr_syntax_ldif, attr_syntax, attr_desc)
                #print(config.ldap_attribute_types[i].oid, config.ldap_attribute_types[i].equality, config.ldap_attribute_types[i].syntax)

            # FIXME: how to implement ldapSyntaxes, matchingRules, and matchingRuleUse like returned in schema search of openldap?
            # ldapsearch -H ldap://127.0.0.1 -b cn=Subschema -D "uid=testuser1,ou=Users,ou=site,dc=realm,dc=tld" -w otp -s base -x '(objectClass=subschema)' attributeTypes dITStructureRules objectClasses nameForms dITContentRules matchingRules ldapSyntaxes matchingRuleUse
            # ldaptor-fetchschema --base="dc=domain,dc=tld"  --service-location="dc=domain,dc=tld:127.0.0.1:389"

            #ldif = "%s%s" % (ldif, attr_syntax_ldif)
            ldif = "%s%s" % (ldif, oc_ldif)
            ldif = "%s%s" % (ldif, attr_ldif)
            ldif = "%s\n" % ldif

        else:
            #r = []
            #realm = None
            #for i in reversed(self.dn.getText().split(",")):
            #    if not i.startswith("dc="):
            #        break
            #    if realm:
            #        # Get OTPme client from DN.
            #        self.client = i.split("=")[1]
            #        #msg = "Using client from DN: %s" % self.client
            #        #log.msg(msg, logLevel=logging.DEBUG)
            #    r.insert(0, i.replace("dc=", ""))
            #    x = ".".join(r)
            #    if x == config.realm:
            #        realm = x

            # Handle OTPme object requests.
            if not self.otpme_oid:
                msg = (_("Not an OTPme file backend path: %s") % self.path)
                raise OTPmeException(msg)

            # Get object data from cache.
            object_data = self.get_object(self.otpme_oid, fake_dc=self.client)
            object_name = object_data['name']
            object_type = object_data['type']
            ldif = object_data['ldif']

            if object_type == "realm":
                dc_parts = object_name.split(".")
                full_dn = "dc=%s" % ",dc=".join(dc_parts)
                dc_parts.reverse()
                dn = ""
                for p in dc_parts:
                    if dn == "":
                        dn = "dc=%s" % p
                    else:
                        dn = "dc=%s,%s" % (p, dn)
                    if dn == self.dn:
                        dc = p
                        break

                if dn == full_dn:
                    ldif = "%s\n\n" % "\n".join(ldif)
                else:
                    ldif = ("dn: %s\nobjectClass: dcObject\ndc: %s\n\n"
                            % (dn, dc))
            else:
                ldif = "%s\n\n" % "\n".join(ldif)

        ldif = ldif.encode("utf-8")
        try:
            parser = StoreParsedLDIF()
            parser.dataReceived(ldif)
        except Exception as e:
            msg = "Failed to load LDIF: %s" % e
            logger.critical(msg)

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
            msg = "Missing client DC: %s" % self.dn.getText()
            logger.warning(msg)
            raise ldaperrors.LDAPInvalidCredentials

        # Get username from DN.
        username = self.dn.getText().split(",")[0].split("=")[1]

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
            msg = "Failed to get authd connection: %s" % e
            logger.critical(msg)
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
            auth_reply, \
            binary_data = authd_conn.send(command="verify",
                                command_args=command_args)
        except Exception as e:
            msg = "Failed to authenticate user: %s" % e
            logger.warning(msg)
            raise ldaperrors.LDAPInvalidCredentials
        finally:
            authd_conn.close()

        if status is False:
            msg = "Failed to authenticate user: %s" % auth_reply
            logger.warning(msg)
            raise ldaperrors.LDAPInvalidCredentials

        # Set auth token.
        self.auth_token_uuid = auth_reply[0]['login_token_uuid']

        return self

    @property
    def otpme_oid(self):
        otpme_oid = get_oid_from_path(self.path)
        return otpme_oid

    @property
    def auth_token(self):
        if not self.auth_token_uuid:
            return
        auth_token = backend.get_object(uuid=self.auth_token_uuid)
        return auth_token

    @auth_token.setter
    def auth_token(self, auth_token):
        self.auth_token_uuid = auth_token.uuid

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
        object_dn = dn.getText()

        if object_dn == "cn=Subschema":
            dn_parts = [object_dn]
            config_dir = self.path
        else:
            realm = None
            site = None
            # Get realm and site from DN.
            dn_parts = object_dn.split(",")
            dn_parts.reverse()
            r = []
            for i in dn_parts:
                if i.startswith("dc="):
                    if realm:
                        # Get OTPme client from DN.
                        self.client = i.split("=")[1]
                        #msg = "Using client from DN: %s" % self.client
                        #log.msg(msg, logLevel=logging.DEBUG)
                    r.insert(0, re.sub('^dc=', '', i))
                    x = ".".join(r)
                    if x == config.realm:
                        realm = x
                if i.startswith("ou="):
                    site = re.sub('^ou=', '', i)
                    break

            # Make sure we do not add <site> parameter when searching for a
            # site object.
            if realm and site:
                x_realm = []
                for x in realm.split("."):
                    x_realm.append("dc=%s" % x)
                x_realm = ",".join(x_realm)
                test_dn = "ou=%s,%s" % (site, x_realm)
                if test_dn == object_dn:
                    site = None

            if self.client:
                x = list(dn_parts)
                x.reverse()
                # Remove fake DC used to pass on OTPme client within LDAP
                # requests.
                client_dc = "dc=%s" % self.client
                if client_dc in x:
                    x.remove(client_dc)
                real_dn = ",".join(x)
            else:
                real_dn = object_dn
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

        if not os.path.isdir(config_dir):
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn))

        dn = distinguishedname.DistinguishedName(object_dn)

        # Create object instance and return it.
        e = self.__class__(config_dir, dn, self.auth_token, self.client)
        return defer.succeed(e)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.path, self.dn.getText())

    def gen_cache_key(self, filterObject, sizeLimit=0, timeLimit=0):
        """ Generate cache key for ldap search cache. """
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
                            value = "%s*" % s_value
                        else:
                            value = "%s%s%s*" % (value, value, s_value)
                        cache_key += value
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_any):
                        if not value:
                            value = "*%s*" % s_value
                        else:
                            if value.endswith("*"):
                                value = "%s%s*" % (value, s_value)
                            else:
                                value = "%s*%s*" % (value, s_value)
                        cache_key += value
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_final):
                        if not value:
                            value = "*%s" % s_value
                        else:
                            if value.endswith("*"):
                                value = "%s%s" % (value, s_value)
                            else:
                                value = "%s*%s" % (value, s_value)
                        cache_key += value
                    sub_count += 1

            elif isinstance(filterObject, pureldap.LDAPFilter_greaterOrEqual):
                cache_key += "+greaterOrEqual="
                cache_key += filterObject.attributeDesc.value
                cache_key += str(int(filterObject.assertionValue.value) - 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_lessOrEqual):
                cache_key += "+lessOrEqual="
                cache_key += filterObject.attributeDesc.value
                cache_key += str(int(filterObject.assertionValue.value) + 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_not):
                cache_key += "+not="
                cache_key += filterObject.value.attributeDesc.value
                cache_key += '[^%s]' % filterObject.value.assertionValue.value

        cache_key += "%s" % sizeLimit
        cache_key += "%s" % timeLimit

        return cache_key

    def search_otpme(self, filterText=None, filterObject=None,
        attributes=(), sizeLimit=0, timeLimit=0, typesOnly=0, **kwargs):
        """ Search OTPme backend. """
        result_uuids = []
        value = None
        less_than = False
        greater_than = False
        attribute = None

        if filterObject is None and filterText is None:
            filterObject = pureldap.LDAPFilterMatchAll

        # Whats ldapfilter?????
        #elif filterObject is None and filterText is not None:
        #    filterObject = ldapfilter.parseFilter(filterText)

        #elif filterObject is not None and filterText is not None:
        #    f = ldapfilter.parseFilter(filterText)
        #    filterObject=pureldap.LDAPFilter_and((f, filterObject))

        elif filterObject is not None and filterText is None:
            pass

        if isinstance(filterObject, pureldap.LDAPFilter_and):
            counter = 0
            for f in filterObject:
                search_result = self.search_otpme(filterText=None,
                                                filterObject=f,
                                                attributes=(),
                                                #sizeLimit=sizeLimit,
                                                #timeLimit=timeLimit,
                                                typesOnly=typesOnly,
                                                **kwargs)
                if counter == 0:
                    result_uuids = search_result
                else:
                    for o in list(result_uuids):
                        if o not in search_result:
                            result_uuids.remove(o)
                counter += 1

        elif isinstance(filterObject, pureldap.LDAPFilter_or):
            for f in filterObject:
                result_uuids += self.search_otpme(filterText=None,
                                                filterObject=f,
                                                attributes=(),
                                                #sizeLimit=sizeLimit,
                                                #timeLimit=timeLimit,
                                                typesOnly=typesOnly,
                                                **kwargs)
        else:
            if isinstance(filterObject, pureldap.LDAPFilter_present):
                attribute = filterObject.value.decode()
                value = "*"
            elif isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
                attribute = filterObject.attributeDesc.value.decode()
                value = filterObject.assertionValue.value.decode().lower()
            elif isinstance(filterObject, pureldap.LDAPFilter_substrings):

                attribute = filterObject.type.decode()
                sub_count = 0
                for s in filterObject.substrings:
                    s_value = s.value
                    if isinstance(s_value, bytes):
                        s_value = s_value.decode("utf-8")
                    if isinstance(filterObject.substrings[sub_count],
                                pureldap.LDAPFilter_substrings_initial):
                        if not value:
                            value = "%s*" % s_value
                        else:
                            value = "%s%s%s*" % (value, value, s_value)
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_any):
                        if not value:
                            value = "*%s*" % s_value
                        else:
                            if value.endswith("*"):
                                value = "%s%s*" % (value, s_value)
                            else:
                                value = "%s*%s*" % (value, s_value)
                    elif isinstance(filterObject.substrings[sub_count],
                                    pureldap.LDAPFilter_substrings_final):
                        if not value:
                            value = "*%s" % s_value
                        else:
                            if value.endswith("*"):
                                value = "%s%s" % (value, s_value)
                            else:
                                value = "%s*%s" % (value, s_value)
                    sub_count += 1

            elif isinstance(filterObject, pureldap.LDAPFilter_greaterOrEqual):
                attribute = filterObject.attributeDesc.value
                greater_than = str(int(filterObject.assertionValue.value) - 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_lessOrEqual):
                attribute = filterObject.attributeDesc.value
                less_than = str(int(filterObject.assertionValue.value) + 1)
            elif isinstance(filterObject, pureldap.LDAPFilter_not):
                attribute = filterObject.value.attributeDesc.value
                value = '[^%s]' % filterObject.value.assertionValue.value
            else:
                raise (ldapsyntax.MatchNotImplemented, filterObject)

            if isinstance(attribute, bytes):
                attribute = attribute.decode("utf-8")
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            if attribute and (value is not None
                            or less_than is not None
                            or greater_than is not None
                            or value is not None):

                # Try to get case sensitive attribute name.
                x = attribute.lower()
                try:
                    ldif_attribute = config.ldap_object_class_mappings[x]
                except:
                    try:
                        ldif_attribute = config.ldap_attribute_type_mappings[x]
                    except:
                        return result_uuids
                ldif_attribute = "ldif:%s" % ldif_attribute

                # Search objects.
                result_uuids = self._search_otpme(attribute=ldif_attribute,
                                            value=value,
                                            less_than=less_than,
                                            greater_than=greater_than,
                                            size_limit=sizeLimit,
                                            **kwargs)
        if sizeLimit > 0:
            result_uuids = result_uuids[:sizeLimit]
        return result_uuids

    def get_object(self, object_id, verify_acls=None, fake_dc=None):
        global user_ldif_cache
        global global_ldif_cache
        read_oid = object_id.read_oid
        object_type = object_id.object_type

        if verify_acls is None:
            verify_acls = False
            if self.auth_token:
                if not self.auth_token.is_admin():
                    verify_acls = True

        if not config.ldap_verify_acls:
            verify_acls = False

        if verify_acls and not self.auth_token:
            msg = "Unable to verify ACLs without token."
            raise OTPmeException(msg)

        # Try to get object data from user cache.
        if self.auth_token:
            auth_token = self.auth_token.uuid
            try:
                object_data = user_ldif_cache[auth_token][read_oid]['data']
                object_data = copy.deepcopy(object_data)
                cache_time = user_ldif_cache[auth_token][read_oid]['time']
            except:
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
                    if age < 10:
                        return object_data
                    object_checksum = object_data['checksum']
                    x_checksum = backend.get_checksum(object_id)
                    if object_checksum == x_checksum:
                        user_ldif_cache[auth_token][read_oid]['time'] = time.time()
                        return object_data

        # Try to get object data from global cache.
        try:
            object_data = global_ldif_cache[read_oid]['data']
            object_data = copy.deepcopy(object_data)
            cache_time = global_ldif_cache[read_oid]['time']
            do_search = False
        except:
            do_search = True
        if not do_search:
            object_checksum = object_data['checksum']
            x_checksum = backend.get_checksum(object_id)
            if object_checksum != x_checksum:
                do_search = True

        if do_search:
            # Try to get object data from backend.
            result = self._search_otpme(object_type=object_type,
                                        attribute="read_oid",
                                        value=read_oid)
            if len(result) > 1:
                msg = "Found more than one object for: %s" % read_oid
                raise OTPmeException(msg)

        try:
            object_data = global_ldif_cache[read_oid]['data']
            object_data = copy.deepcopy(object_data)
        except:
            msg = "Unknown object: %s" % read_oid
            raise UnknownObject(msg)

        object_ldif = object_data['ldif']
        if not object_ldif:
            msg = "Object without ldif: %s" % read_oid
            raise UnknownObject(msg)

        update_user_cache = False
        object_uuid = object_data['uuid']
        object_name = object_data['name']
        object_type = object_data['type']
        object_acls = object_data['acls']
        object_checksum = object_data['checksum']
        if verify_acls:
            update_user_cache = True
            for x_attr in dict(object_ldif):
                if x_attr in config.ldif_whitelist_attributes:
                    continue
                x_acl = "view:attribute:%s" % x_attr
                result = otpme_acl.verify(uuid=object_uuid,
                                        acl_list=object_acls,
                                        acl=x_acl,
                                        check_admin_role=True,
                                        check_admin_user=True,
                                        need_exact_acl=False,
                                        auth_token=self.auth_token)
                if result:
                    continue
                object_ldif.pop(x_attr)
        object_ldif = get_ldif(object_ldif, text=False, fake_dc=fake_dc)
        object_data['ldif'] = object_ldif
        if update_user_cache:
            if auth_token not in user_ldif_cache:
                user_ldif_cache[auth_token] = {}
            user_ldif_cache[auth_token][read_oid] = {}
            user_ldif_cache[auth_token][read_oid]['time'] = time.time()
            user_ldif_cache[auth_token][read_oid]['data'] = {
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
    def _search_otpme(self, attribute, value, object_type=None,
        less_than=None, greater_than=None, size_limit=1024, scope="one"):
        """ Search OTPme objects. """
        global global_ldif_cache
        global uuid_to_oid
        search_attributes = {
                                attribute  : {'value':value,},
                                #'l'     : {'value':"Koblenz",},
                                'acl'  : {
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
                                        },
                                'template'  : {'value':False,},
                            }

        ldap_settings = config.get_ldap_settings(self.otpme_oid.object_type)
        if ldap_settings:
            object_scopes = ldap_settings['scopes']
            default_scope = ldap_settings['default_scope']
            if scope not in object_scopes:
                scope = default_scope
            if scope == "one":
                object_type = self.otpme_oid.object_type
                search_attributes['name'] = {'value':self.otpme_oid.name}

        return_attributes = ['read_oid', 'name', 'object_type', 'ldif', 'checksum']

        result = backend.search(object_type=object_type,
                                attributes=search_attributes,
                                case_sensitive=False,
                                return_raw_acls=True,
                                less_than=less_than,
                                greater_than=greater_than,
                                return_attributes=return_attributes,
                                max_results=size_limit,
                                _debug=True)

        acls = result['acls']
        objects = result['objects']

        for x_uuid in objects:
            object_name = objects[x_uuid]['name']
            object_id = objects[x_uuid]['read_oid']
            object_type = objects[x_uuid]['object_type']
            object_checksum = objects[x_uuid]['checksum']
            object_acls = acls[x_uuid]
            object_ldif = objects[x_uuid]['ldif']

            try:
                cache_checksum = global_ldif_cache[object_id]['data']['checksum']
            except KeyError:
                cache_checksum = None

            if cache_checksum == object_checksum:
                continue

            uuid_to_oid[x_uuid] = object_id
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
        return threads.deferToThread(self._search,
                                    filterText=filterText,
                                    filterObject=filterObject,
                                    attributes=attributes,
                                    scope=scope,
                                    derefAliases=derefAliases,
                                    sizeLimit=sizeLimit,
                                    timeLimit=timeLimit,
                                    typesOnly=typesOnly,
                                    callback=callback)

    def _search(self, filterText=None, filterObject=None, attributes=(),
        scope=None, derefAliases=None, sizeLimit=0,
        timeLimit=0, typesOnly=0, callback=None):
        """ Search LDAP object. """
        from ldaptor.protocols import pureldap
        results = []
        schema_search = False

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
            msg = "Unknown search scope: %r" % scope
            raise ldaperrors.LDAPProtocolError(msg)

        # Handle schema search requests.
        if isinstance(filterObject, pureldap.LDAPFilter_equalityMatch):
            attribute = filterObject.attributeDesc.value
            value = filterObject.assertionValue.value.lower()
            if attribute.lower() == "objectclass" and value.lower() == "subschema":
                schema_search = True
                dn = distinguishedname.DistinguishedName('cn=Subschema')
                e = self.__class__(self.path, dn)
                if callback is None:
                    results.append(e)
                else:
                    callback(e)

        if not schema_search:
            cached_entry = None
            if self.auth_token:
                cache_key = self.gen_cache_key(filterObject, sizeLimit, timeLimit)
                cached_entry = get_ldap_search_cache(self.auth_token, self.client, cache_key)
            if cached_entry is not None:
                result_objects = cached_entry
            else:
                # Handle OTPme object search requests.
                try:
                    result_uuids = self.search_otpme(filterText=filterText,
                                                    filterObject=filterObject,
                                                    attributes=(),
                                                    sizeLimit=sizeLimit,
                                                    timeLimit=timeLimit,
                                                    typesOnly=typesOnly,
                                                    scope=scope)
                except SizeLimitExceeded as e:
                    log.msg(str(e), logLevel=logging.WARNING)
                    raise ldaperrors.LDAPSizeLimitExceeded()

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
                    if self.auth_token:
                        entry = get_ldap_cache(self.auth_token, self.client, object_id)
                        if entry:
                            object_dn = entry.dn.getText()

                    if not object_dn:
                        if object_id:
                            object_data = self.get_object(object_id, fake_dc=self.client)
                            object_dn = object_data['ldif'][0][4:]
                            object_id = object_data['read_oid']
                            object_id = oid.get(object_id)
                            object_checksum = object_data['checksum']

                            object_path = get_config_paths(object_id=object_id)['config_dir']

                            dn = distinguishedname.DistinguishedName(object_dn)

                            # Create new entry and pass on auth token and client.
                            entry = self.__class__(object_path, dn, self.auth_token, self.client)
                            # Update cache.
                            if self.auth_token:
                                update_ldap_cache(self.auth_token, self.client,
                                                object_id, entry, object_checksum)

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
                        dn_path_len = str(len(object_dn.split(",")))
                        result_objects["%s %s" % (dn_path_len, object_dn)] = entry

            # Update ldap search cache.
            if self.auth_token:
                update_ldap_search_cache(self.auth_token, self.client, cache_key, result_objects)

            for key in sorted(result_objects):
                entry = result_objects[key]
                if callback is None:
                    results.append(entry)
                else:
                    callback(entry)

        if callback is None:
            return defer.succeed(results)
        return results

def otpme_log_translate(conf):
    try:
        debug_message = conf['debug']
    except:
        debug_message = False
    try:
        message = conf['message']
    except:
        message = False
    try:
        loglevel = logging.getLevelName(conf['logLevel'])
    except:
        loglevel = config.loglevel

    if message:
        if debug_message:
            pass
            #if config.loglevel == "DEBUG" or config.debug_enabled:
            #    logger.debug(message)
        else:
            if loglevel == "CRITICAL":
                logger.critical(message)
            if loglevel == "ERROR":
                logger.error(message)
            if loglevel == "WARNING":
                logger.warning(message)
            if loglevel == "INFO":
                logger.info(message)
            if loglevel == "DEBUG":
                logger.debug(message)

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

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            msg = "Version %u not supported" % request.version
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

    def handle_LDAPSearchRequest(self, request, controls, reply):
        if self.boundUser is None:
            raise ldaperrors.LDAPStrongAuthRequired()
        return ldapserver.LDAPServer.handle_LDAPSearchRequest(self, request, controls, reply)

    def _cbSearchGotBase(self, base, dn, request, reply):
        # Pass on auth token.
        base.auth_token = self.boundUser.auth_token
        return super(OTPmeLDAPServer, self)._cbSearchGotBase(base, dn, request, reply)

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
        msg = ("Received SIGTERM.")
        logger.info(msg)
        if config.print_timing_results:
            from otpme.lib import debug
            debug.print_timing_result(print_status=True)
        os._exit(0)

    def listen(self, use_ssl=False, cert=None, key=None):
        """ Start listening. """
        from twisted.internet import ssl
        from twisted.internet import reactor

        # FIXME: also implement StartTLS?
        # https://twistedmatrix.com/documents/12.0.0/core/howto/ssl.html
        # https://twistedmatrix.com/documents/14.0.0/core/howto/ssl.html
        if use_ssl and not (cert and key):
            msg = ("'use_ssl' requires 'cert' and 'key'.")
            raise OTPmeException(msg)

        if use_ssl:
            new_proctitle = "%s ListenSSL: tcp://%s:%s" % (self.proctitle,
                                                            self.address,
                                                            self.port)
            ssl_context = ssl.DefaultOpenSSLContextFactory(privateKeyFileName=key,
                                                            certificateFileName=cert)
            reactor.listenSSL(port=self.port,
                            factory=self.factory,
                            interface=self.address,
                            contextFactory=ssl_context)
        else:
            new_proctitle = "%s Listen: tcp://%s:%s" % (self.proctitle,
                                                        self.address,
                                                        self.port)
            reactor.listenTCP(port=self.port,
                            factory=self.factory,
                            interface=self.address)

        setproctitle.setproctitle(new_proctitle)
        self.reactor = reactor

    def run(self):
        """ Start LDAP server. """
        if not self.reactor:
            msg = ("You need to call listen() first.")
            raise OTPmeException(msg)
        # Handle multiprocessing stuff.
        multiprocessing.atfork(quiet=True)
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
