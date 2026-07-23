# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
import hashlib
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData
from fido2.webauthn import AuthenticationResponse

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
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
from otpme.lib.audit import emit_audit
from otpme.lib.classes.token import Token
from otpme.lib.locking import object_lock
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode
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
                            "auth_script",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
                }

write_value_acls = {
                "edit"      : [
                            "auth_script",
                            "offline_expiry",
                            "offline_unused_expiry",
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

# Passkeys are deployed and tested exclusively via the browser
# (navigator.credentials.create / get); there is no CLI deploy or test
# flow because the credential is bound to a browser-accessible
# authenticator (platform biometric or a synced credential provider).
commands = {}

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
                    sub_type="passkey",
                    sub_type_attribute="token_type")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "passkey")


@match_class_typing
class PasskeyToken(Token):
    """ WebAuthn passkey: discoverable credential, user-verified.

    Differs from Fido2Token in three places: residentKey is required so
    the authenticator stores the credential itself (enables usernameless
    sign-in), userVerification is required (passkey-grade), and the
    PublicKeyCredentialUserEntity.id is the stable user UUID so cloud
    sync survives a username change. Everything else (server-side
    verify, counter handling, AttestedCredentialData on-disk shape) is
    identical to fido2 — same python-fido2 library, same on-disk format.
    """
    commands = commands
    # RFC 8176: hardware-secured key, explicit user-presence, and the
    # always-on user verification (PIN/biometric) characteristic of a
    # passkey.
    oidc_amr_values = ['hwk', 'user', 'mfa']
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
        self.token_type = "passkey"
        self.pass_type = "smartcard"
        self.credential_data = None
        self.rp = None
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        self.offline_pinnable = True
        self.supported_hardware_tokens = ['passkey']

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'RP'                        : {
                                            'var_name'      : 'rp',
                                            'type'          : str,
                                            'required'      : False,
                                        },

            'REG_STATE'                 : {
                                            'var_name'      : 'reg_state',
                                            'type'          : dict,
                                            'required'      : False,
                                        },

            'CREDENTIAL_DATA'           : {
                                            'var_name'      : 'credential_data',
                                            'type'          : str,
                                            'required'      : False,
                                        },
            }
        return Token._get_object_config(self, token_config=token_config)

    def _get_token_data_attrs(self):
        """ Attributes copied by dump/set_token_data. """
        return [
                'credential_data',
                ]

    def set_variables(self):
        Token.set_variables(self)

    def get_offline_config(self, second_factor_usage: bool=False):
        offline_config = self.object_config.copy()
        return offline_config

    @property
    def need_password(self):
        # Passkey always enforces user verification on the authenticator
        # side (PIN/biometric); no separate OTPme-side password.
        return False

    @need_password.setter
    def need_password(self, *args, **kwargs):
        return

    def get_fido2_server(self, rp_id=None):
        # rp is stored on the token once deployed. During registration it is
        # still None, so fall back to the site's current SSO FQDN -- the same
        # value that gets baked into the create_options / rpIdHash.
        if rp_id is None:
            rp_id = self.rp
        if rp_id is None:
            rp_id = config.site_sso_fqdn
        rp_data = {"id": rp_id, "name": "OTPme RP"}
        # attestation="none": passkeys (especially synced ones) rarely
        # ship a useful attestation; requiring it would lock out major
        # platform authenticators.
        return Fido2Server(rp_data, attestation="none")

    def _webauthn_user(self):
        """ PublicKeyCredentialUserEntity for register_begin.

        ``id`` must be a stable, non-PII byte string per WebAuthn
        spec — we use the user's OTPme UUID so renaming the user does
        not orphan synced passkeys in iCloud/Google/etc. """
        owner = config.auth_user
        owner_uuid = getattr(owner, 'uuid', None)
        if not owner_uuid:
            raise OTPmeException(_("Cannot derive WebAuthn user.id: missing UUID."))
        return {
            "id":           owner_uuid.encode(),
            "name":         owner.name,
            "displayName":  owner.name,
        }

    @object_lock(full_lock=True)
    @backend.transaction
    def pre_deploy(
        self,
        pre_deploy_args: dict=None,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Begin passkey registration. """
        fido2_server = self.get_fido2_server()
        user = self._webauthn_user()
        create_options, \
        self.reg_state = fido2_server.register_begin(user,
                                resident_key_requirement="required",
                                user_verification="required")
        create_options_json = json.dumps(dict(create_options))
        response = {'create_options': create_options_json}
        self._cache(callback=callback)
        return callback.ok(response)

    @object_lock(full_lock=True)
    @audit_log(ignore_args=['registration_data'])
    @backend.transaction
    def deploy(
        self,
        registration_data: str,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Complete passkey registration. """
        try:
            registration_data = json.loads(registration_data)
        except Exception:
            msg = _("Failed to load registration data.")
            return callback.error(msg)
        fido2_server = self.get_fido2_server()
        try:
            auth_data = fido2_server.register_complete(self.reg_state,
                                                    registration_data)
        except Exception as e:
            msg = _("Failed to complete registration: {error}")
            msg = msg.format(error=e)
            return callback.error(msg)
        self.credential_data = encode(auth_data.credential_data, "hex")
        # Bind the token to the RP the credential was registered for. Taken
        # from the server object so it always matches what get_fido2_server()
        # used; lets us filter a user's passkey tokens by rp at
        # authenticate_begin. Not recoverable from registration_data in
        # plaintext (only as origin / rpIdHash).
        self.rp = fido2_server.rp.id
        self.reg_state = {}
        self._cache(callback=callback)
        cred_hash = hashlib.sha256(auth_data.credential_data).hexdigest()[:16]
        actor = None
        try:
            if config.auth_token:
                actor = config.auth_token.rel_path
        except Exception:
            pass
        emit_audit("Crypto", "passkey_credential_added",
                   actor=actor,
                   token=self.rel_path,
                   user=getattr(self, 'owner_name', None),
                   credential_fingerprint=cred_hash)
        msg = _("Passkey deployed successful.")
        return callback.ok(msg)

    def verify(
        self,
        smartcard_data: dict,
        **kwargs,
        ):
        """ Verify a passkey assertion. """
        if not smartcard_data:
            return None
        self.auth_state = smartcard_data['auth_state']
        auth_response = smartcard_data['auth_response']
        try:
            auth_response = json.loads(auth_response)
        except Exception:
            log_msg = _("Failed to decode auth response.", log=True)[1]
            logger.warning(log_msg)
            return False
        credential_data = decode(self.credential_data, "hex")
        credentials = [AttestedCredentialData(credential_data)]
        fido2_server = self.get_fido2_server()
        try:
            fido2_server.authenticate_complete(self.auth_state,
                                                credentials,
                                                auth_response)
        except Exception as e:
            log_msg = _("Token verififcation failed: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
            return False
        parsed = AuthenticationResponse.from_dict(auth_response)
        counter = parsed.response.authenticator_data.counter
        last_counter = self.get_token_counter()
        if counter == 0 and last_counter <= 0:
            pass
        elif counter <= last_counter:
            log_msg = _("Token verififcation failed: Already used token counter", log=True)[1]
            logger.warning(log_msg)
            return False
        else:
            self._add_token_counter(token_counter=counter)
        return True

    @object_lock(full_lock=True)
    def _add(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add a passkey token. """
        self.used_otp_salt = stuff.gen_secret(32)
        if _caller == "CLIENT":
            return_message = _("NOTE: You have to deploy this passkey token to make it usable.")
            callback.send(return_message)
            return self._cache(callback=callback)
        return self._cache(callback=callback)

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)
        lines = []
        lines.append(f'RP="{self.rp}"')
        if self.verify_acl("view:credential_data"):
            lines.append(f'CREDENTIAL_DATA="{self.credential_data}"')
        else:
            lines.append('CREDENTIAL_DATA=""')
        return Token.show_config(self,
                                config_lines=lines,
                                callback=callback,
                                **kwargs)

    def show(self, **kwargs):
        return self.show_config(**kwargs)
