# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import ssh
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.otpme_acl import check_acls
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
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

default_callback = config.get_callback()

logger = config.logger

read_acls =  []
write_acls =  []

read_value_acls = {
                "view"      : [
                            "2ftoken",
                            "2ftoken_status",
                            "card_type",
                            "key_type",
                            "ssh_public_key",
                            "ssh_private_key",
                            "auth_script",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            "signature",
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
                            "2ftoken",
                            "card_type",
                            "key_type",
                            "password",
                            "ssh_public_key",
                            "ssh_private_key",
                            "auth_script",
                            "offline_expiry",
                            "offline_unused_expiry",
                            ],
                "enable"    : [
                            "2ftoken",
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                "disable"   : [
                            "2ftoken",
                            "auth_script",
                            "offline",
                            "session_keep",
                            ],
                }

default_acls = []

recursive_default_acls = []

commands = {
    'password'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_password',
                    'oargs'             : ['auto_password', 'password'],
                    'job_type'          : 'process',
                    },
                },
            },
    'ssh_public_key'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_ssh_public_key',
                    'oargs'             : ['ssh_public_key'],
                    'job_type'          : 'process',
                    },
                },
            },
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'oargs'             : ['password'],
                    'job_type'          : 'process',
                    },
                },
            },
    '2f_token'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_2f_token',
                    'args'              : ['second_factor_token'],
                    'job_type'          : 'process',
                    },
                },
            },
    'enable_2f'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'enable_2f_token',
                    'job_type'          : 'process',
                    },
                },
            },
    'disable_2f'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'disable_2f_token',
                    'job_type'          : 'process',
                    },
                },
            },
    'card_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_card_type',
                    'args'              : ['card_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'key_type'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'change_key_type',
                    'args'              : ['key_type'],
                    'job_type'          : 'process',
                    },
                },
            },
    'sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'sign',
                    'oargs'             : ['tags', 'stdin_pass'],
                    'job_type'          : 'process',
                    },
                },
            },
    'resign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'resign',
                    'job_type'          : 'process',
                    },
                },
            },
    'add_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'add_sign',
                    'oargs'             : ['signature', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'del_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'del_sign',
                    'oargs'             : ['username', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'verify_sign'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'verify_sign',
                    'oargs'             : ['username', 'user_uuid', 'tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign_data'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'get_sign_data',
                    'oargs'             : ['tags'],
                    'job_type'          : 'process',
                    },
                },
            },
    'get_sign'   : {
            'OTPme-mgmt-1.0'    : {
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
                    sub_type="ssh",
                    sub_type_attribute="token_type")

def register_hooks():
    config.register_auth_on_action_hook("token", "resync")
    config.register_auth_on_action_hook("token", "change_key_type")
    config.register_auth_on_action_hook("token", "change_card_type")
    config.register_auth_on_action_hook("token", "change_2f_token")
    config.register_auth_on_action_hook("token", "enable_2f_token")
    config.register_auth_on_action_hook("token", "disable_2f_token")
    config.register_auth_on_action_hook("token", "add_sign")
    config.register_auth_on_action_hook("token", "del_sign")
    config.register_auth_on_action_hook("token", "change_ssh_public_key")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "ssh")

@match_class_typing
class SshToken(Token):
    """ Class for SSH tokens. """
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
        super(SshToken, self).__init__(object_id=object_id,
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
        self.token_type = "ssh"
        # Set password type.
        self.pass_type = "ssh_key"
        # Set SSH key type.
        self.key_type = "rsa"
        self.valid_key_types = [ "rsa", "dsa" ]
        # Set default values.
        self.ssh_public_key = None
        self.ssh_private_key = None
        # Will hold decrypted SSH private key.
        self._ssh_private_key = None
        # Challenge to verify in offline mode.
        self.offline_challenge = ""
        # FIXME: allow to modify this list!?
        # Valid token options (e.g. command=/some/script/path)
        self.valid_token_options = [
                                'cert-authority',
                                'command',
                                'restrict',
                                'environment',
                                'from',
                                'no-agent-forwarding',
                                'no-port-forwarding',
                                'no-pty',
                                'no-user-rc',
                                'no-X11-forwarding',
                                'permitopen',
                                'principals',
                                'tunnel',
                                ]
        # Valid token pass types that could be used as a second factor.
        self.valid_2f_pass_types = [ 'otp' ]
        # Hardware card/token type.
        self.card_type = None
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        self.signable = True
        self.signatures = {}
        self.cross_site_links = True
        self.need_password = True
        self.offline_pinnable = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'yubikey_gpg', 'openssh' ]

        self._sub_sync_fields = {
                    'host'  : {
                        'trusted'  : [
                            "KEY_TYPE",
                            "SSH_PUBLIC_KEY",
                            "SIGNATURES",
                            ]
                        },

                    'node'  : {
                        'untrusted'  : [
                            "KEY_TYPE",
                            "SSH_PUBLIC_KEY",
                            "SIGNATURES",
                            ]
                        },
                    }

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'SSH_PRIVATE_KEY'           : {
                                            'var_name'      : 'ssh_private_key',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'SSH_PUBLIC_KEY'            : {
                                            'var_name'      : 'ssh_public_key',
                                            'type'          : str,
                                            'required'      : False,
                                            'encoding'      : 'BASE64',
                                        },


            'OFFLINE_CHALLENGE'         : {
                                            'var_name'      : 'offline_challenge',
                                            'type'          : str,
                                            'required'      : False,
                                            'encryption'    : config.disk_encryption,
                                        },

            'KEY_TYPE'                  : {
                                            'var_name'      : 'key_type',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'CARD_TYPE'                 : {
                                            'var_name'      : 'card_type',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'SECOND_FACTOR_TOKEN'       : {
                                            'var_name'      : 'second_factor_token',
                                            'type'          : 'uuid',
                                            'required'      : False,
                                        },


            'SECOND_FACTOR_TOKEN_ENABLED': {
                                            'var_name'      : 'second_factor_token_enabled',
                                            'type'          : bool,
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

    def set_variables(self):
        """ Set instance variables. """
        # Run parent class method that may override default values with those
        # read from config.
        Token.set_variables(self)

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        need_encryption = True
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    def verify_acl(self, action: str):
        """ Verify ACLs required to allow <action>. """
        # Parent class cannot know the ACL to allow verification of signatures
        # e.g. "view:script" for script objects and "view_public_key" for SSH
        # tokens.
        if action == "verify_signature":
            if self._verify_acl("verify:signature") \
            or self._verify_acl("view:signature") \
            or self._verify_acl("view:ssh_public_key"):
                return True

        if action == "get_signatures":
            if self._verify_acl("view:signature") \
            or self.verify_acl("view:ssh_public_key"):
                return True

        # Finally try to verify ACL via parent class method.
        if self._verify_acl(action):
            return True

        return  False

    @check_acls(['view:ssh_public_key'])
    def get_sign_data(self, callback: JobCallback=default_callback, **kwargs):
        """ Return public key to be signed by parent class method. """
        ssh_public_key = self.ssh_public_key
        return callback.ok(ssh_public_key)

    def get_card_types(
        self,
        _caller: str="API",
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Get supported hardware card/token types. """
        card_types = [ 'gpg' ]
        if _caller == "CLIENT":
            card_types = "\n".join(card_types)
        return callback.ok(card_types)

    @check_acls(['edit:card_type'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_card_type(
        self,
        card_type: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get supported hardware card/token types. """
        if card_type:
            if not card_type in self.get_card_types():
                msg = _("Unsupported card type: {card_type}")
                msg = msg.format(card_type=card_type)
                return callback.error(msg)
            if card_type == self.card_type:
                msg = _("Card type already set to: {card_type}")
                msg = msg.format(card_type=card_type)
                return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_card_type",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.card_type = card_type
        return self._cache(callback=callback)

    @check_acls(['edit:key_type'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def change_key_type(
        self,
        key_type: str="rsa",
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Get supported hardware card/token types. """
        if not key_type in self.valid_key_types:
            msg = _("Unsupported key type: {key_type}")
            msg = msg.format(key_type=key_type)
            return callback.error(msg)
        if key_type == self.key_type:
            msg = _("Key type already set to: {key_type}")
            msg = msg.format(key_type=key_type)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_key_type",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        self.key_type = key_type
        return self._cache(callback=callback)

    @check_acls(['edit:ssh_public_key'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def change_ssh_public_key(
        self,
        ssh_public_key: Union[str,None]=None,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token SSH public key. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_ssh_public_key",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        # Check if we got SSH public key as argument.
        if ssh_public_key is None:
            ssh_public_key = callback.ask(_("Please enter/paste SSH public key: "))
        if ssh_public_key:
            self.ssh_public_key = ssh_public_key
            self.offline_challenge = stuff.gen_md5(ssh_public_key)
        else:
            self.ssh_public_key = None
            self.offline_challenge = None
        return self._cache(callback=callback)

    def get_private_key(self, password: str, instance: bool=False):
        """ Get decrytped private key. """
        if not self.ssh_private_key:
            raise Exception(_("No private key set."))
        # Try to decrypt RSA key.
        try:
            key = RSAKey(key=self.ssh_private_key, password=password)
        except Exception as e:
            msg = _("Error decrypting private key: {error}")
            msg = msg.format(error=e)
            raise Exception(msg)
        if instance:
            return key
        private_key = key.private_key_base64
        return private_key

    def resync(self, callback: JobCallback=default_callback, **kwargs):
        """ Wrapper method to call resync() of 2ftoken. """
        try:
            sftoken = self.get_sftoken()
        except Exception as e:
            msg = _("Error loading second factor token: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        return sftoken.resync(callback=callback, **kwargs)

    def gen_challenge(self, **kwargs):
        """ Generate challenge to be sigend by users private SSH key. """
        if not self.ssh_public_key:
            raise Exception(_("No SSH public key set."))
        if self.second_factor_token_enabled:
            sftoken = self.get_sftoken()
            otp_len = sftoken.otp_len
            if sftoken.pin_enabled:
                otp_len = otp_len + sftoken.pin_len
            return ssh.gen_challenge(self.ssh_public_key, otp_len=otp_len)
        return ssh.gen_challenge(self.ssh_public_key, otp_len=0)

    def test(
        self,
        password: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Test if SSH authentication with this token can be verified. """
        ok_message = _("Token verified successful.")
        error_message = _("Token verification failed.")

        try:
            challenge = self.gen_challenge()
        except Exception as e:
            msg = _("Unable to generate challenge: {error}")
            msg = msg.format(error=e)
            callback.error(msg)

        response = callback.sshauth(challenge=challenge)

        otp = None
        if self.second_factor_token_enabled:
            pass_prompt = _("OTP: ")
            if not otp:
                otp = callback.askpass(pass_prompt)
            if not otp:
                return callback.error(_("Unable to get OTP."))

        status = self.verify(challenge=challenge, response=response, otp=otp)

        if status:
            return callback.ok(ok_message)

        return callback.error(error_message)

    def verify(
        self,
        challenge: Union[str,None]=None,
        response: Union[str,None]=None,
        otp: Union[str,None]=None,
        session_uuid: Union[str,None]=None,
        **kwargs,
        ):
        """ Verify challenge/response. """
        if not self.ssh_public_key:
            log_msg = _("Token '{token_name}' is missing SSH public key.", log=True)[1]
            log_msg = log_msg.format(token_name=self.name)
            logger.warning(log_msg)
            return None

        if self.second_factor_token_enabled:
            try:
                sftoken = self.get_sftoken()
            except Exception as e:
                log_msg = _("Error loading second factor token: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                logger.critical(log_msg)
                return None

            # Check if token PIN is mandatory. by default we dont want a user to
            # type in the token PIN when used as second factor token.
            if sftoken.pin_mandatory:
                verify_pin = True
                otp_includes_pin = True
            else:
                verify_pin = False
                otp_includes_pin = False

            cutoff_len = sftoken.otp_len
            if otp_includes_pin:
                cutoff_len += sftoken.pin_len

            if len(otp) <= cutoff_len:
                log_msg = _("Second factor OTP token enabled but password is too short to include a OTP.", log=True)[1]
                logger.debug(log_msg)
                return None
            password = otp[:-cutoff_len]
            otp = otp[-cutoff_len:]
        else:
            password = otp

        # In offline mode the token config is encrypted via challenge/response
        # procedure using the SSH private key. The offline challenge is the MD5
        # sum of the SSH public key. If decryption was successful the token is
        # verified successful. We do this to make offline logins faster because
        # we need only one singing process via ssh-agent.
        if self.offline and not password:
            public_key_md5 = stuff.gen_md5(self.ssh_public_key)
            if self.offline_challenge != public_key_md5:
                log_msg = _("Failed to verify offline challenge.", log=True)[1]
                logger.warning(log_msg)
                return False

        elif password:
            if not self.ssh_private_key:
                log_msg = _("Skipping token without SSH private key for password authentication: {rel_path}", log=True)[1]
                log_msg = log_msg.format(rel_path=self.rel_path)
                logger.debug(log_msg)
                return None
            # Try to decrypt private key.
            try:
                self._ssh_private_key = self.get_private_key(password=password)
                # When authenticating with the private key encryption passphrase
                # set our pass type to static.
                self.pass_type = "static"
            except:
                # If we got the wrong password this is not a failure because
                # it may match an other token. So we continue to next token.
                return None

        elif challenge and response:
            response = decode(response, "base64")
            ssh_public_key = decode(self.ssh_public_key, "base64")
            if not ssh.verify_sign(public_key=ssh_public_key,
                                    data=response,
                                    plaintext=challenge):
                log_msg = _("Verifying SSH response failed.", log=True)[1]
                logger.warning(log_msg)
                return False

            challenge_time = int(challenge.split(":")[0])
            epoch_time = int(time.time())
            challenge_age = epoch_time - challenge_time
            if challenge_age > 15:
                log_msg = _("SSH challenge too old.", log=True)[1]
                logger.warning(log_msg)
                return False
        else:
            return None

        # If no second factor token is configured we are done.
        if not self.second_factor_token_enabled:
            return True

        # Verify second factor token.
        log_msg = _("Verifying second factor token: {sftoken_rel_path}", log=True)[1]
        log_msg = log_msg.format(sftoken_rel_path=sftoken.rel_path)
        logger.debug(log_msg)
        if sftoken.verify_otp(otp,
                            session_uuid=session_uuid,
                            otp_includes_pin=otp_includes_pin,
                            verify_pin=verify_pin, sft=True):
            return True
        return False

    @check_acls(['edit:2ftoken'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def change_2f_token(
        self,
        second_factor_token: str,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change token second factor token. """
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_ssh_public_key",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if second_factor_token == "":
            self.second_factor_token = None
        else:
            # Get user instance of token owner.
            user = backend.get_object(object_type="user", uuid=self.owner_uuid)
            # Get token instance of 2f_token by name.
            token = user.token(second_factor_token)

            if not token:
                msg = _("Token '{second_factor_token}' does not exist.")
                msg = msg.format(second_factor_token=second_factor_token)
                return callback.error(msg)
            if token.pass_type != "otp":
                msg = _("Token '{second_factor_token}' is not an OTP token.")
                msg = msg.format(second_factor_token=second_factor_token)
                return callback.error(msg)

            # Set 2f token.
            self.second_factor_token = token.uuid
        self.update_index('second_factor_token', self.second_factor_token)
        return self._cache(callback=callback)

    @check_acls(['enable:2ftoken'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def enable_2f_token(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Enable the second factor token. """
        if self.second_factor_token_enabled:
            return callback.error(_("Second factor token already enabled."))

        if not self.second_factor_token:
            return callback.error(_("No second factor token configured."))

        # Check if second factor token is available.
        try:
            self.get_sftoken(callback=callback)
        except Exception as e:
            msg = _("Unable to enable second factor token: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("enable_2f_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask(_("Enable second factor token?: "))
                if answer.lower() != "y":
                    return callback.abort()

        self.second_factor_token_enabled = True
        self.update_index('second_factor_token_enabled', True)
        return self._cache(callback=callback)

    @check_acls(['disable:2ftoken'])
    @object_lock()
    @backend.transaction
    @audit_log()
    def disable_2f_token(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Disable the second factor token. """
        if not self.second_factor_token_enabled:
            return callback.error(_("Second factor token already disabled."))

        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("disable_2f_token",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        if not force:
            if self.confirmation_policy == "paranoid":
                answer = callback.ask(_("Disable second factor token?: "))
                if answer.lower() != "y":
                    return callback.abort()

        self.second_factor_token_enabled = False
        self.update_index('second_factor_token_enabled', False)
        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log(ignore_args=['private_key', 'password'])
    def deploy(
        self,
        public_key: Union[str,None]=None,
        private_key: Union[str,None]=None,
        password: Union[str,None]=None,
        pass_hash_type: str="PBKDF2",
        card_type: Union[str,None]=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy SSH token. """
        if not public_key and not private_key:
            return callback.error(_("Need at least public or private key."))
        if private_key:
            if not password:
                return callback.error(_("Need password to add private key."))

            msg = _("Setting SSH private key to token: {rel_path}")
            msg = msg.format(rel_path=self.rel_path)
            callback.send(msg)

            # Encrypt private key with password.
            rsa_key = RSAKey(key=private_key)
            self.ssh_private_key = rsa_key.encrypt_key(password=password,
                                                    hash_type=pass_hash_type)
            # Get public key from private key if not given.
            if not public_key:
                public_key = rsa_key.ssh_public_key.split(" ")[1]
            # We cannot support cross site token links if the token includes
            # a SSH private key.
            self.cross_site_links = False

        msg = _("Setting SSH public key to token: {rel_path}")
        msg = msg.format(rel_path=self.rel_path)
        callback.send(msg)

        self.card_type = card_type
        self.ssh_public_key = public_key
        self.change_ssh_public_key(ssh_public_key=public_key,
                                    run_policies=False)

        return self._cache(callback=callback)

    @check_acls(['edit:password'])
    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log()
    def change_key_password(
        self,
        force: bool=False,
        run_policies: bool=True,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Change private key encryption password. """
        if not self.ssh_private_key:
            msg = _("No private key set for this token.")
            return callback.error(msg)
        if run_policies:
            try:
                self.run_policies("modify",
                                callback=callback,
                                _caller=_caller)
                self.run_policies("change_password",
                                callback=callback,
                                _caller=_caller)
            except Exception:
                return callback.error()

        is_admin = False
        if config.auth_token:
            is_admin = config.auth_token.is_admin()
        elif config.use_api:
            is_admin = True

        current_pass = callback.askpass(_("Current password: "))
        try:
            private_key = self.get_private_key(password=current_pass,
                                                instance=True)
        except:
            return callback.error(_("Wrong password."))

        password_checked = False
        while True:
            new_password1 = callback.askpass(_("New password: "))
            if not force or not is_admin:
                if not self.check_password(new_password1,
                                        callback=callback):
                    return callback.error()
                password_checked = True

            new_password2 = callback.askpass(_("Re-type password: "))
            if new_password1 == new_password2:
                password = new_password1
                break
            return callback.error(_("Sorry, passwords do not match."))

        # Make sure password is a string.
        password = str(password)

        if password == "":
            return callback.error(_("Cannot set empty password."))

        if not force or not is_admin:
            if not password_checked:
                 if not self.check_password(password, callback=callback):
                    return callback.error()

        if not force or not is_admin:
            if len(password) < self.password_min_len:
                msg = _("Password too short ({password_min_len}).")
                msg = msg.format(password_min_len=self.password_min_len)
                return callback.error(msg)
            if len(password) > self.password_max_len:
                msg = _("Password too long ({password_max_len}).")
                msg = msg.format(password_max_len=self.password_max_len)
                return callback.error(msg)

        # Encrypt private key with new password.
        #rsa_key = RSAKey(key=private_key)
        #self.ssh_private_key = rsa_key.encrypt_key(password=password)
        self.ssh_private_key = private_key.encrypt_key(password=password)

        return self._cache(callback=callback)

    @object_lock(full_lock=True)
    @backend.transaction
    def _add(
        self,
        public_key: Union[str,None]=None,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Add a token. """
        return_message = None
        if public_key:
            self.ssh_public_key = public_key
        else:
            return_message = _("NOTE: You have to add an SSH public key to this token to make it usable.")

        sf_note = _("NOTE: You may want to add a second factor token (e.g. OTP token) to improve security.")

        if return_message:
            return_message = f"{return_message}\n{sf_note}"
        else:
            return_message = sf_note

        return callback.ok(return_message)

    def get_offline_data(self):
        """ Get token offline data. """
        offline_data = {'ssh_public_key':self.ssh_public_key}
        return offline_data

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        second_factor_token_name = ""
        if self.verify_acl("view:2ftoken"):
            # Get 2f token instance.
            if self.second_factor_token:
                try:
                    sftoken = self.get_sftoken()
                    second_factor_token_name = sftoken.name
                except Exception as e:
                    msg = _("Error loading second factor token: {error}")
                    msg = msg.format(error=e)
                    callback.send(msg)
        lines = []

        if self.verify_acl("view:ssh_public_key"):
            lines.append(f'SSH_PUBLIC_KEY="{self.ssh_public_key}"')
        else:
            lines.append('SSH_PUBLIC_KEY=""')

        if self.verify_acl("view_all:ssh_private_key"):
            lines.append(f'SSH_PRIVATE_KEY="{self.ssh_private_key}"')
        else:
            lines.append('SSH_PRIVATE_KEY=""')

        if self.verify_acl("view:key_type"):
            lines.append(f'KEY_TYPE="{self.key_type}"')
        else:
            lines.append('KEY_TYPE=""')

        lines.append(f'SECOND_FACTOR_TOKEN="{second_factor_token_name}"')

        if self.verify_acl("view:2ftoken_status"):
            lines.append(f'SECOND_FACTOR_TOKEN_ENABLED="{self.second_factor_token_enabled}"')
        else:
            lines.append('SECOND_FACTOR_TOKEN_ENABLED=""')

        if self.verify_acl("view:card_type"):
            lines.append(f'CARD_TYPE="{self.card_type}"')
        else:
            lines.append('CARD_TYPE=""')

        lines.append(f'OFFLINE_CHALLENGE="{self.offline_challenge}"')

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
