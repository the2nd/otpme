# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock

from otpme.lib.classes.token \
            import get_acls \
            as _get_acls
from otpme.lib.classes.token \
            import get_value_acls \
            as _get_value_acls
from otpme.lib.classes.token \
            import get_default_acls \
            as _get_default_acls
from otpme.lib.classes.token \
            import get_recursive_default_acls \
            as _get_recursive_default_acls

from otpme.lib.exceptions import *

logger = config.logger

default_callback = config.get_callback()

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "auth_script",
                            "destination_token",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "auth_script",
                            ],
                "enable"    : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                "disable"   : [
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
            }

default_acls = []

recursive_default_acls = []

def get_acls(split=False, **kwargs):
    """ Get all supported object ACLs """
    if split:
        otpme_token_read_acls, \
        otpme_token_write_acls = _get_acls(split=split, **kwargs)
        _read_acls = otpme_acl.merge_acls(read_acls, otpme_token_read_acls)
        _write_acls = otpme_acl.merge_acls(write_acls, otpme_token_write_acls)
        return _read_acls, _write_acls
    otpme_token_acls = _get_acls(**kwargs)
    _acls = otpme_acl.merge_acls(read_acls, write_acls)
    _acls = otpme_acl.merge_acls(_acls, otpme_token_acls)
    return _acls

def get_value_acls(split=False, **kwargs):
    """ Get all supported object value ACLs """
    if split:
        otpme_token_read_value_acls, \
        otpme_token_write_value_acls = _get_value_acls(split=split, **kwargs)
        _read_value_acls = otpme_acl.merge_value_acls(read_value_acls,
                                                    otpme_token_read_value_acls)
        _write_value__acls = otpme_acl.merge_value_acls(write_value_acls,
                                                        otpme_token_write_value_acls)
        return _read_value_acls, _write_value__acls
    otpme_token_value_acls = _get_value_acls(**kwargs)
    _acls = otpme_acl.merge_value_acls(read_value_acls, write_value_acls)
    _acls = otpme_acl.merge_value_acls(_acls, otpme_token_value_acls)
    return _acls

def get_default_acls():
    """ Get all supported object default ACLs """
    token_default_acls = _get_default_acls()
    _acls = otpme_acl.merge_acls(default_acls, token_default_acls)
    return _acls

def get_recursive_default_acls():
    """ Get all supported object recursive default ACLs """
    token_recursive_default_acls = _get_recursive_default_acls()
    _acls = otpme_acl.merge_acls(recursive_default_acls,
                                token_recursive_default_acls)
    return _acls

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    """ Register object. """
    register_token_type()

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "link")

class LinkToken(Token):
    """ Class to link a token from one user to another. """
    def __init__(self, object_id=None, user=None, name=None,
        realm=None, site=None, path=None, **kwargs):

        # Call parent class init.
        super(LinkToken, self).__init__(object_id=object_id,
                                        realm=realm,
                                        site=site,
                                        user=user,
                                        name=name,
                                        path=path,
                                        **kwargs)

        self._acls = get_acls()
        self._value_acls = get_value_acls()
        self._default_acls = get_default_acls()
        self._recursive_default_acls = get_recursive_default_acls()

        # Set token type.
        self.token_type = "link"
        # Set password type.
        self.pass_type = "link"

        # If this token supports offline usage depens on the destination token.
        # Our default is not supported (None).
        self.allow_offline = None
        # Set default values.
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'DESTINATION_TOKEN'         : {
                                            'var_name'      : 'destination_token',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def set_variables(self):
        """ Set instance variables """
        # Run parent class method that may override default values with those
        # read from config.
        Token.set_variables(self)

        # Check for destination token attributes we need to inherit.
        dest_token = self.get_destination_token()
        if dest_token:
            # If self.allow_offline was not modified yet, check if our destination
            # token supports offline usage.
            if self.allow_offline == None:
                # If destination token allows offline usage (!= None) set our
                # default to disabled (False).
                if dest_token.allow_offline is not None:
                    self.allow_offline = False

    def get_offline_config(self, second_factor_usage=False):
        """ Get offline config of token. """
        # Make sure our object config is up-to-date.
        self.update_object_config()
        # Get a copy of our object config.
        offline_config = self.object_config.copy()
        # Get offline encryption setting from destination token.
        dest_token = self.get_destination_token()
        dest_token_offline_config = dest_token.get_offline_config()
        need_encryption = dest_token_offline_config['NEED_OFFLINE_ENCRYPTION']
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    def test(self, password=None, callback=default_callback, **kwargs):
        """ Test if destination token can be verified. """
        dst_token = self.get_destination_token()
        return dst_token.test(password=password, callback=callback, **kwargs)

    def get_destination_token(self):
        """ Get destination token instance. """
        if stuff.is_uuid(self.destination_token):
            dst_token = backend.get_object(object_type="token",
                                    uuid=self.destination_token)
            if not dst_token:
                msg = ("Uhhh destination token '%s' of token '%s' does "
                    "not exist!!!" % (self.destination_token, self.rel_path))
                logger.critical(msg)
            return dst_token
        else:
            msg = ("No destination token configured for: %s"
                        % self.rel_path)
            logger.warning(msg)
        return None

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(self, destination_token_uuid, callback=default_callback, **kwargs):
        """ Add a token. """
        # Set link destination.
        self.destination_token = destination_token_uuid
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show token info. """
        if not self.verify_acl("view_public:object"):
            msg = ("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        if self.verify_acl("view:destination_token"):
            destination_token_rel_path = backend.search(object_type="token",
                                                    attribute="uuid",
                                                    value=self.destination_token,
                                                    return_type="rel_path")[0]
        else:
            destination_token_rel_path = ""

        lines = []
        lines.append('DESTINATION_TOKEN="%s"' % destination_token_rel_path)

        return Token.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        """ Show token details """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)
