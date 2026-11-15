# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.otpme_acl import denied_msg
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing
from otpme.lib.protocols.utils import register_commands

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
                            # No offline_status, enable:offline or
                            # disable:offline: a link token leaves
                            # allow_offline at None, and Token refuses
                            # offline use for it.
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            "signatures",
                            ],
            }

write_value_acls = {
                "add"       : [
                            "signature",
                            ],
                "delete"    : [
                            "signature",
                            ],
                "verify"    : [
                            "signature",
                            ],
                "edit"      : [
                            "auth_script",
                            ],
                "enable"    : [
                            "auth_script",
                            "session_keep",
                            ],
                "disable"   : [
                            "auth_script",
                            "session_keep",
                            ],
            }

default_acls = []

recursive_default_acls = []

# A link is signed itself, over the key of its destination (see
# LinkToken.get_sign_data()): the commands of an SSH token.
commands = {
    'sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'sign',
                    'oargs'             : ['tags', 'stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'resign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'resign',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'add_sign',
                    'oargs'             : ['signature', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'del_sign',
                    'oargs'             : ['username', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'verify_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign_data'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_sign_data',
                    'oargs'             : ['tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign'   : {
            'default'    : {
                'exists'    : {
                    'method'            : 'get_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    }

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
    register_commands("token",
                    commands,
                    sub_type="link",
                    sub_type_attribute="token_type")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "link", version=1)
    config.register_ssh_token("link")
    # Followed when a node builds the sync parameters for a host it
    # serves (OTPmeHost.get_sync_parameters()), so a node holding tokens
    # of another site needs it.
    config.register_index_attribute("destination_token",
                                    sync=["node:untrusted"],
                                    object_types=["token"])

@match_class_typing
class LinkToken(Token):
    """ Class to link a token from one user to another. """
    def __init__(
        self,
        object_id: Union[oid.OTPmeOid,None]=None,
        user: Union[str,None]=None,
        name: Union[str,None]=None,
        realm: Union[str,None]=None,
        site: Union[str,None]=None,
        path: Union[str,None]=None,
        **kwargs,
        ):

        # Call parent class init.
        super().__init__(object_id=object_id,
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
        # Holds no secret of its own; it points at the token that does.
        self.count_fails = False

        # Link tokens do not support offline logins.
        self.allow_offline = None
        # Set default values.
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        # Signed itself, over the key of its destination. A host verifies
        # these signatures before it lets the key in (see
        # ssh.update_authorized_keys()), so they go where the ones of an
        # SSH token go.
        self.signatures = {}
        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "SIGNATURES",
                            ]
                        },
                    'node'  : {
                        'untrusted'  : [
                            "SIGNATURES",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'DESTINATION_TOKEN'         : {
                                            'var_name'      : 'destination_token',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },
            'SIGNATURES'                : {
                                            'var_name'  : 'signatures',
                                            'type'      : dict,
                                            'required'  : False,
                                        },
            }

        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. """
        # Make sure our object config is up-to-date.
        self.update_object_config()
        # Get a copy of our object config.
        offline_config = self.object_config.copy()
        # Get offline encryption setting from destination token.
        dest_token_offline_config = self.dst_token.get_offline_config()
        need_encryption = dest_token_offline_config['NEED_OFFLINE_ENCRYPTION']
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    @property
    def dst_token(self):
        dst_token = self.get_destination_token()
        return dst_token

    @property
    def signable(self):
        """ A link is signable when its destination is.

        The signature stays on the link: it is the link that is added to
        a host or a role, by and for the user who owns the link, and
        remove_token() takes the signature off the same token. What is
        signed is the data of the destination (its SSH public key, see
        get_sign_data()), so a new destination or a new key is no longer
        covered by it.
        """
        if not stuff.is_uuid(self.destination_token):
            return False
        dst_token = backend.get_object(object_type="token",
                                    uuid=self.destination_token)
        if not dst_token:
            return False
        return dst_token.signable

    @signable.setter
    def signable(self, value):
        # OTPmeObject.__init__() sets it to False, there is nothing to
        # set: it is the destination that decides.
        pass

    def get_default_sign_tags(self):
        """ Get default sign tags for this token. """
        default_tags = super().get_default_sign_tags()
        # The user who owns the link, the one a host lets in with it.
        user_tag = f"user:{self.owner_uuid}"
        default_tags.append(user_tag)
        return default_tags

    def verify_acl(self, action: str, **kwargs):
        """ Verify ACLs required to allow <action>. """
        # The parent class cannot know the ACLs that allow to verify or
        # read the signatures of a link (see SshToken.verify_acl()).
        if action == "verify_signature":
            if self._verify_acl("verify:signature") \
            or self._verify_acl("view:signatures"):
                return True
        if action == "get_signatures":
            if self._verify_acl("view:signatures"):
                return True
        # The kwargs go only here: the ACLs above are other ones than the
        # action.
        if self._verify_acl(action, **kwargs):
            return True
        return False

    def get_sign_data(self, callback: JobCallback=default_callback, **kwargs):
        """ Return the sign data of the destination token. """
        dst_token = self.dst_token
        if not dst_token:
            msg = _("Destination token does not exist.")
            return callback.error(msg)
        return dst_token.get_sign_data(callback=callback, **kwargs)

    def test(
        self,
        password: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Test if destination token can be verified. """
        return self.dst_token.test(password=password, callback=callback, **kwargs)

    def get_destination_token(self):
        """ Get destination token instance. """
        if stuff.is_uuid(self.destination_token):
            dst_token = backend.get_object(object_type="token",
                                    uuid=self.destination_token)
            if not dst_token:
                log_msg = _("Uhhh destination token '{destination_token}' of token '{rel_path}' does not exist!!!", log=True)[1]
                log_msg = log_msg.format(destination_token=self.destination_token, rel_path=self.rel_path)
                logger.critical(log_msg)
            return dst_token
        else:
            log_msg = _("No destination token configured for: {rel_path}", log=True)[1]
            log_msg = log_msg.format(rel_path=self.rel_path)
            logger.warning(log_msg)
        return None

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(
        self,
        destination_token_uuid: str,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a token. """
        # The invariant, checked where the destination is actually
        # written. User.add_token() says the same thing earlier and
        # with the nicer message, before anything is created -- this
        # one is what a caller reaching add() directly with a uuid runs
        # into. A link whose destination cannot answer for another user
        # is a token that only fails at the first login.
        dst_token = backend.get_object(object_type="token",
                                    uuid=destination_token_uuid)
        if not dst_token:
            msg = _("Destination token does not exist.")
            return callback.error(msg)
        if not dst_token.support_links:
            msg = _("Token type cannot be used as link destination: {token_type}")
            msg = msg.format(token_type=dst_token.token_type)
            return callback.error(msg)
        # Set link destination.
        self.destination_token = destination_token_uuid
        self.update_index('destination_token', self.destination_token)
        return callback.ok()

    def show_config(self, callback=default_callback, **kwargs):
        """ Show token info. """
        if not self.verify_acl("view_public:object"):
            msg = denied_msg(self, "view_public:object")
            return callback.error(msg, exception=PermissionDenied)

        if self.verify_acl("view:destination_token"):
            destination_token_rel_path = backend.search(object_type="token",
                                                    attribute="uuid",
                                                    value=self.destination_token,
                                                    return_type="rel_path")[0]
        else:
            destination_token_rel_path = ""

        lines = []
        lines.append(f'DESTINATION_TOKEN="{destination_token_rel_path}"')

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
