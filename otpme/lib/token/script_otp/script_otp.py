# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import otpme_acl
from otpme.lib.classes.token import Token
from otpme.lib.daemon.scriptd import run_script
from otpme.lib.job.callback import JobCallback
from otpme.lib.typing import match_class_typing

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

default_callback = config.get_callback()

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [ "auth_script" ],
            }

write_value_acls = {
                "edit"      : [ "auth_script" ],
            }

default_acls = []

recursive_default_acls = []

logger = config.logger

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
    token_type = __name__.split(".")[-1]
    config.register_sub_object_type("token", token_type)

@match_class_typing
class ScriptToken(Token):
    """ 'script' token that runs a script to verify user/pass. """
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
        super(ScriptToken, self).__init__(object_id=object_id,
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
        if self.__class__.__name__ == "ScriptotpToken":
            self.token_type = "script_otp"
        elif self.__class__.__name__ == "ScriptstaticToken":
            self.token_type = "script_static"
        # Set password type.
        self.pass_type = self.token_type
        # Token type "script" is itself a script so no need to en- or disable
        # the auth script.
        self.auth_script_enabled = None
        self.allow_offline = None
        self.need_password = True

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {}
        # Use parent class method to merge token configs.
        return Token._get_object_config(self, token_config=token_config)

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Token.set_variables(self)

    def test(
        self,
        password: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """
        Test if the given password/OTP can be verified by this token.
        """
        if self.token_type == "script_otp":
            pass_type = "OTP"
        else:
            pass_type = "Password"

        ok_message = _("Token verified successful.")
        error_message = _("{pass_type} verification failed.")
        error_message = error_message.format(pass_type=pass_type)

        pass_prompt = _("{pass_type}: ")
        pass_prompt = pass_prompt.format(pass_type=pass_type)

        # Get password from user.
        if not password:
            password = callback.askpass(pass_prompt)

        if not password:
            return callback.error(_("Unable to get OTP."))

        auth_otp = None
        auth_pass = None
        if self.token_type == "script_otp":
            auth_otp = password
        else:
            auth_pass = password

        # Verify push password.
        verify_status = self.verify(auth_type="clear-text",
                                    auth_token=self.name,
                                    auth_user=self.owner,
                                    auth_pass=auth_pass,
                                    auth_otp=auth_otp,
                                    **kwargs)
        if not verify_status:
            return callback.error(error_message)

        return callback.ok(ok_message)

    def verify(
        self,
        auth_type: str,
        auth_user: str,
        auth_token: str,
        auth_group: Union[str,None]=None,
        auth_client: Union[str,None]=None,
        auth_client_ip: Union[str,None]=None,
        auth_pass: Union[str,None]=None,
        auth_otp: Union[str,None]=None,
        auth_challenge: Union[str,None]=None,
        auth_response: Union[str,None]=None,
        **kwargs,
        ):
        """ Run auth script for script-token. """
        if not self.auth_script:
            msg = _("No script configured for script-token: {self.rel_path}")
            msg = msg.format(self=self)
            raise OTPmeException(msg)
        # Set auth type idependent values.
        token_script_parms = {
                'options'           : self.auth_script_options,
                'auth_type'         : auth_type,
                'auth_user'         : auth_user,
                'auth_token'        : self.name,
                'auth_group'        : auth_group,
                'auth_client'       : auth_client,
                'auth_client_ip'    : auth_client_ip,
                'auth_pass'         : auth_pass,
                'auth_otp'          : auth_otp,
                'auth_challenge'    : auth_challenge,
                'auth_response'     : auth_response,
                }
        log_msg = _("Starting token script...", log=True)[1]
        logger.debug(log_msg)
        # Run token script.
        try:
            auth_script_result = run_script(script_type="auth_script",
                                        script_uuid=self.auth_script,
                                        script_parms=token_script_parms,
                                        user=auth_user,
                                        group=auth_group)

        except Exception as e:
            log_msg = _("Error running token script: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
            return None

        return auth_script_result

    def enable_auth_script(self, callback: JobCallback=default_callback, **kwargs):
        """ Enable token auth script. """
        msg = _("Authentication script is always enabled for token type '{self.token_type}'.")
        msg = msg.format(self=self)
        return callback.error(msg)

    def disable_auth_script(self, callback: JobCallback=default_callback, **kwargs):
        """ Enable token auth script. """
        msg = _("Disabling authentication script not allowed with token type '{self.token_type}'.")
        msg = msg.format(self=self)
        return callback.error(msg)

    def _add(self, callback: JobCallback=default_callback, **kwargs):
        """ Add a token. """
        msg = _("NOTE: You have to configure an auth script for this token to make it usable.")
        return callback.ok(msg)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []
        return Token.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)
    def show(self, **kwargs):
        """ Show token details. """
        #if not self.verify_acl("view_public:object"):
        #    msg = ("Permission denied.")
        #    return callback.error(msg, exception=PermissionDenied)
        return self.show_config(**kwargs)

# Class aliases.
class ScriptstaticToken(ScriptToken):
    pass

class ScriptotpToken(ScriptToken):
    pass
