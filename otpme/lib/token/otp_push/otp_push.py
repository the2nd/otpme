# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.job.callback import JobCallback
from otpme.lib.daemon.scriptd import run_script
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
                            "push_script",
                            "push_token",
                            "phone_number",
                            "auth_script",
                            ],
            }

write_value_acls = {
                "edit"      : [
                            "password",
                            "push_script",
                            "push_token",
                            "phone_number",
                            "auth_script",
                            ],
                "enable"    : [
                            "auth_script",
                            ],
                "disable"   : [
                            "auth_script",
                            ],
}

default_acls = []

recursive_default_acls = []

commands = {
    'password'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_password',
                    'oargs'             : ['auto_password', 'password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'job_type'          : 'process',
                    },
                },
            },
    'push_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_push_token',
                    'oargs'             : ['push_token'],
                    'job_type'          : 'process',
                    },
                },
            },
    'phone_number'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_phone_number',
                    'oargs'             : ['phone_number'],
                    'job_type'          : 'process',
                    },
                },
            },
    'push_script'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_push_script',
                    'args'              : ['push_script'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_mschap'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_mschap',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_mschap'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_mschap',
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
REGISTER_AFTER = ["otpme.lib.classes.script"]

def register():
    """ Register object. """
    register_hooks()
    register_token_type()
    register_config_params()
    register_commands("token",
                    commands,
                    sub_type="otp_push",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "change_phone_number")
    config.register_auth_on_action_hook("token", "change_push_token")
    config.register_auth_on_action_hook("token", "change_push_script")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "otp_push")

def register_config_params():
    """ Register config params. """
    object_types = [
                    'site',
                    'unit',
                    'user',
                ]
    # Default OTP push password length.
    config.register_config_parameter(name="otp_push_default_pass_len",
                                    ctype=int,
                                    default_value=6,
                                    object_types=object_types)
    # Default push script to add to new users.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                ]
    def script_setter(script_path):
        result = backend.search(object_type="script",
                                attribute="rel_path",
                                value=script_path,
                                return_type="uuid")
        if not result:
            msg = _("Unknown script: {script_path}")
            msg = msg.format(script_path=script_path)
            raise UnknownObject(msg)
        script_uuid = result[0]
        return script_uuid
    def script_getter(script_uuid):
        result = backend.search(object_type="script",
                                attribute="uuid",
                                value=script_uuid,
                                return_type="rel_path")
        if not result:
            msg = _("Unknown script: {script_uuid}")
            msg = msg.format(script_uuid=script_uuid)
            raise UnknownObject(msg)
        script_path = result[0]
        return script_path
    push_script_name = "push_script.sh"
    scripts_unit = config.get_default_unit("script")
    default_push_script = f"{scripts_unit}/{push_script_name}"
    config.register_config_parameter(name="default_otp_push_script",
                                    ctype=str,
                                    getter=script_getter,
                                    setter=script_setter,
                                    default_value=default_push_script,
                                    object_types=object_types)
    # Register push scripot.
    config.register_base_object("script", push_script_name)

@match_class_typing
class OtppushToken(Token):
    """ Class for OTP push tokens (e.g. send OTP via SMS). """
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
        super(OtppushToken, self).__init__(object_id=object_id,
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
        self.token_type = "otp_push"
        # Set password type.
        self.pass_type = "otp_push"
        # Set default values.
        self.phone_number = None
        self.push_script = None
        self.push_script_options = None
        self.push_token = None
        self.allow_offline = None
        self.password_hash = None
        #self.valid_modes = [ 'mode1', 'mode2']
        self.mschap_enabled = False

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'PASSWORD'                  : {
                                            'var_name'      : 'password_hash',
                                            'type'          : str,
                                            'required'      : True,
                                            'encryption'    : config.disk_encryption,
                                        },

            'PASSWORD_HASH_PARAMS'      : {
                                            'var_name'      : 'password_hash_params',
                                            'type'          : list,
                                        },

            'PUSH_SCRIPT'               : {
                                            'var_name'      : 'push_script',
                                            'type'          : 'uuid',
                                            'required'      : True,
                                        },

            'PUSH_SCRIPT_OPTIONS'       : {
                                            'var_name'      : 'push_script_options',
                                            'type'          : list,
                                            'required'      : False,
                                        },

            'PUSH_TOKEN'                : {
                                            'var_name'      : 'push_token',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },

            'PHONE_NUMBER'              : {
                                            'var_name'      : 'phone_number',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'MSCHAP_ENABLED'            : {
                                            'var_name'      : 'mschap_enabled',
                                            'type'          : bool,
                                            'required'      : False,
                                        },
            }

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
        Test if the given password/OTP can be verified by this token
        and send OTP via SMS.
        """
        ok_message = _("Token verified successful.")
        error_message = _("Password verification failed.")

        # Get password from user.
        pass_prompt = _("Password: ")
        if not password:
            password = callback.askpass(pass_prompt)

        if not password:
            return callback.error(_("Unable to get password."))

        # Verify push password.
        verify_status = self.verify_static(password=str(password), **kwargs)
        if not verify_status:
            return callback.error(error_message)

        # Send OTP.
        if not self.send_otp(callback=callback):
            return callback.error()

        return callback.ok(ok_message)

    def verify(
        self,
        challenge: Union[str,None]=None,
        response: Union[str,None]=None,
        **kwargs,
        ):
        """ Call default verify method. """
        if challenge and response:
            return self.verify_mschap_static(challenge=challenge,
                                            response=response,
                                            **kwargs)
        else:
            return self.verify_static(**kwargs)

    def verify_static(self, password: str, **kwargs):
        """ Verify given password against 'password' token. """
        # Create password hash.
        password_hash = self.gen_password_hash(password=password)
        if password_hash == self.password_hash:
            return True
        return None
        # This point should never be reached.
        msg = _("WARNING: You may have hit a BUG of Token().verify_static().")
        raise Exception(msg)

    def verify_mschap_static(
        self,
        challenge: str,
        response: str,
        **kwargs,
        ):
        """ Verify MSCHAP challenge/response. """
        from otpme.lib import mschap_util
        # Get NT key from verify()
        status, \
        nt_key = mschap_util.verify(self.password_hash, challenge, response)
        if status:
            return status, nt_key, self.password_hash

        # Default should be None -> Token hash does not match request.
        return None, None, None

        # This point should never be reached.
        msg = _("WARNING: You may have hit a BUG of Token().verify_mschap_static().")
        raise Exception(msg)

    @check_acls(['edit:push_script'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def change_push_script(
        self,
        push_script: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token push script. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_push_script",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        return self.change_script(script_var='push_script',
                        script_options_var='push_script_options',
                        script=push_script, callback=callback)

    @check_acls(['edit:push_token'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def change_push_token(
        self,
        push_token: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token push token. """
        # Check if we got push_token as argument.
        if not push_token:
            return callback.error()

        if "/" in push_token:
            msg = _("Please use token name instead of token path.")
            return callback.error(msg)

        # Get user instance of token owner.
        user = backend.get_object(object_type="user",
                                uuid=self.owner_uuid)

        # Get token instance of push_token.
        token = user.token(push_token)

        if not token:
            msg = _("Token '{token}' does not exist.")
            msg = msg.format(token=push_token)
            return callback.error(msg)
        if token.pass_type != "otp":
            msg = _("Token '{token}' is not an OTP token.")
            msg = msg.format(token=push_token)
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_push_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        # Set push_token.
        self.push_token = token.uuid
        return self._cache(callback=callback)

    # FIXME: implement using phone number from ldif attribute! -> add search filter?
    @check_acls(['edit:phone_number'])
    @object_lock(full_lock=True)
    @audit_log()
    def change_phone_number(
        self,
        phone_number: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change object phone_number. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_phone_number",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()
        # Check if we got phone_number as argument.
        if phone_number is None:
            if self.phone_number is None:
                phone_number = ""
            else:
                phone_number = self.phone_number
            phone_number = callback.ask(message=_("Enter phone number: "),
                                        input_prefill=phone_number)
        if phone_number == "":
            self.phone_number = None
        else:
            self.phone_number = str(phone_number)
        return self._cache(callback=callback)

    def send_otp(self, callback: JobCallback=default_callback):
        """ Send OTP via push script. """
        if self.push_token is None:
            msg = _("No OTP push token configured. Cannot send OTP to user.")
            return callback.error(msg)

        if self.phone_number is None:
            msg, log_msg = _("No phone number defined for token. Push script needs to know how to get users phone number.", log=True)
            logger.info(log_msg)
            callback.send(msg)

        # Get user instance of token owner.
        owner = backend.get_object(object_type="user",
                                uuid=self.owner_uuid)
        # Get token instance of push_token.
        push_token = backend.get_object(object_type="token",
                                        uuid=self.push_token)

        if not push_token:
            msg = _("Push token '{token}' does not exist.")
            msg = msg.format(token=self.push_token)
            raise OTPmeException(msg)

        # Get OTP from push token.
        try:
            otp = push_token.gen_otp(verify_acls=False)[0]
        except:
            msg = _("Unable to generate OTP with token '{token}'.")
            msg = msg.format(token=push_token.name)
            raise OTPmeException(msg)

        callback.send(_("Calling push script to send OTP to user..."))

        # Set push script parameters.
        push_script_parms = {
                'otp'           : otp,
                'username'      : owner.name,
                'options'       : self.push_script_options,
                'phone_number'  : self.phone_number,
                }


        push_script_oid = backend.get_oid(object_type="script", uuid=self.push_script)
        log_msg = _("Starting token push script: {script}", log=True)[1]
        log_msg = log_msg.format(script=push_script_oid)
        logger.debug(log_msg)

        # Get groups the user is in.
        owner_groups = owner.get_groups()

        # Send OTP if we got one.
        try:
            push_script_result = run_script(script_type="push_script",
                                        script_uuid=self.push_script,
                                        script_parms=push_script_parms,
                                        user=owner.name,
                                        group=owner.group,
                                        groups=owner_groups)
        except Exception as e:
            config.raise_exception()
            msg, log_msg = _("Error running token push script: {error}", log=True)
            msg = msg.format(error=e)
            log_msg = log_msg.format(error=e)
            logger.warning(log_msg)
            return callback.error(msg)

        # Check auth script return code.
        if not push_script_result:
            msg, log_msg = _("Token push script failed: {script}", log=True)
            msg = msg.format(script=push_script_oid)
            log_msg = log_msg.format(script=push_script_oid)
            logger.warning(log_msg)
            return callback.error(msg)

        return callback.ok()

    @backend.transaction
    def _add(
        self,
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a token. """
        return_message = None

        # Get default pass length.
        pass_len = self.get_config_parameter("otp_push_default_pass_len")
        new_pass = stuff.gen_password(pass_len)

        self.change_password(password=new_pass,
                            verify_acls=False,
                            force=True,
                            callback=callback)

        msg = _("Push password: {password}")
        return_message = msg.format(password=new_pass)

        # Set default push script.
        default_push_script = self.get_config_parameter("default_otp_push_script")
        if verbose_level > 0:
            msg = _("Setting default push script: {script}")
            msg = msg.format(script=default_push_script)
            callback.send(msg)

        self.push_script_options = ['%USERNAME', '%PHONE_NUMBER', '[OTP]']

        self.change_push_script(default_push_script, callback=callback)

        return callback.ok(return_message)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        ptoken_name = ""
        if self.verify_acl("view_all:push_token"):
            ptoken_name = ""
            if self.push_token != None:
                # Get push token instance.
                ptoken = backend.get_object(object_type="token",
                                        uuid=self.push_token)
                if ptoken:
                    ptoken_name = ptoken.name

        lines = []

        lines.append(f'PUSH_TOKEN="{ptoken_name}"')

        push_script = ""
        if self.verify_acl("view_all:push_script"):
            if self.push_script:
                x = backend.get_object(object_type="script",
                                        uuid=self.push_script)
                push_script = x.rel_path
        lines.append(f'PUSH_SCRIPT="{push_script}"')

        push_script_options = ""
        if self.verify_acl("view_all:push_script"):
            if self.push_script_options:
                push_script_options = " ".join(self.push_script_options)
        lines.append(f'PUSH_SCRIPT_OPTIONS="{push_script_options}"')

        phone_number = ""
        if self.verify_acl("view_all:phone_number"):
            if self.phone_number:
                phone_number = self.phone_number
        lines.append(f'PHONE_NUMBER="{phone_number}"')

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
