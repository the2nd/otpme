# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
from datetime import datetime
from cryptography import x509
from fido2.server import Fido2Server
from fido2.webauthn import RegistrationResponse
from fido2.webauthn import AttestedCredentialData
from cryptography.hazmat.primitives.asymmetric import padding

from typing import Union

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import oid
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_acl
from otpme.lib.audit import audit_log
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
                            "attestation_cert",
                            "auth_script",
                            "offline_status",
                            "offline_expiry",
                            "offline_unused_expiry",
                            "session_keep",
                            ],
                }

write_value_acls = {
                "edit"      : [
                            "attestation_cert",
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

commands = {
    'test'   : {
            'OTPme-mgmt-1.0'    : {
                'exists'    : {
                    'method'            : 'test',
                    'job_type'          : 'thread',
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
    register_hooks()
    register_token_type()
    register_commands("token",
                    commands,
                    sub_type="fido2",
                    sub_type_attribute="token_type")
    register_config_parameters()

def register_hooks():
    config.register_auth_on_action_hook("token", "deploy")
    config.register_auth_on_action_hook("token", "show_config_parameters")

def register_token_type():
    """ Register token type. """
    config.register_sub_object_type("token", "fido2")

def register_config_parameters():
    """ Registger config parameters. """
    # Object types our config parameters are valid for.
    object_types = [
                        'site',
                        'unit',
                        'user',
                        'token',
                    ]
    # Allow to rename default token?
    config.register_config_parameter(name="check_fido2_attestation_cert",
                                    ctype=bool,
                                    default_value=False,
                                    object_types=object_types)

@match_class_typing
class Fido2Token(Token):
    """ Class for fido2 tokens. """
    commands = commands
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
        super(Fido2Token, self).__init__(object_id=object_id,
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
        self.token_type = "fido2"
        # Set password type.
        self.pass_type = "smartcard"
        self.uv = None
        # Set default values.
        self.credential_data = None
        self.attestation_cert = None
        self.allow_offline = False
        self.offline_expiry = 0
        self.offline_unused_expiry = 0
        self.keep_session = False
        self.offline_pinnable = True
        # Hardware tokens that we can handle (e.g. on otpme-token deploy).
        self.supported_hardware_tokens = [ 'fido2' ]

    def _get_object_config(self):
        """ Merge token config with config from parent class. """
        token_config = {
            'UV'                        : {
                                            'var_name'      : 'uv',
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

            'ATTESTATION_CERT'          : {
                                            'var_name'      : 'attestation_cert',
                                            'type'          : str,
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

    def get_offline_config(self, second_factor_usage: bool=False):
        """ Get offline config of token. (e.g. without PIN). """
        offline_config = self.object_config.copy()
        # FIXME: implement self.allow_offline_rsp!!!
        need_encryption = False
        #if self.allow_offline_rsp:
        #    need_encryption = True
        offline_config['NEED_OFFLINE_ENCRYPTION'] = need_encryption
        return offline_config

    @property
    def rp(self):
        return config.realm

    def get_fido2_server(self):
        rp_data = {"id": config.realm, "name": "OTPme RP"}
        fido2_server = Fido2Server(rp_data, attestation="direct")
        return fido2_server

    @object_lock(full_lock=True)
    def pre_deploy(
        self,
        pre_deploy_args: dict={},
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy fido2 token. """
        try:
            self.uv = pre_deploy_args['uv']
        except KeyError:
            msg = _("Missing uv.")
            return callback.error(msg)
        fido2_server = self.get_fido2_server()
        user_id = config.auth_user.name.encode()
        user = {"id": user_id, "name": user_id}
        # Server: create options.
        create_options, \
        self.reg_state = fido2_server.register_begin(user,
                                user_verification=self.uv,
                                authenticator_attachment="cross-platform")
        create_options_json = json.dumps(dict(create_options))
        response = {'create_options':create_options_json}
        self._write(callback=callback)
        return callback.ok(response)

    @object_lock(full_lock=True)
    @backend.transaction
    @audit_log(ignore_args=['registration_data'])
    def deploy(
        self,
        registration_data: str,
        _caller: str="API",
        verbose_level: int=0,
        callback: JobCallback=default_callback,
        ):
        """ Deploy fido2 token. """
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
        check_attestation_cert = self.get_config_parameter("check_fido2_attestation_cert")
        if check_attestation_cert:
            # Parse the response to access the attestation object
            registration = RegistrationResponse.from_dict(registration_data)
            attestation_object = registration.response.attestation_object
            # x5c contains the certificate chain (DER-encoded), x5c[0] is the attestation cert.
            x5c = attestation_object.att_stmt.get("x5c")
            if not x5c:
                msg = _("Registration data misses attestation certificate.")
                return callback.error(msg)
            try:
                attestation_cert = x509.load_der_x509_certificate(x5c[0])
            except Exception as e:
                msg = _("Failed to load attestation certificate: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)
            subject = attestation_cert.subject.rfc4514_string()
            msg = _("Got attestation certificate: {subject}")
            msg = msg.format(subject=subject)
            callback.send(msg)
            issuer = attestation_cert.issuer.rfc4514_string()
            msg = _("Got attestation certificate issuer: {issuer}")
            msg = msg.format(issuer=issuer)
            callback.send(msg)
            # Check attestation certificate validity.
            now = datetime.now(attestation_cert.not_valid_before_utc.tzinfo)
            if attestation_cert.not_valid_before_utc > now:
                msg = _("Attestation certificate not yet valid: {not_valid_before}")
                msg = msg.format(not_valid_before=attestation_cert.not_valid_before_utc)
                return callback.error(msg)
            now = datetime.now(attestation_cert.not_valid_before_utc.tzinfo)
            if attestation_cert.not_valid_after_utc < now:
                msg = _("Attestation certificate not valid anymore: {not_valid_before}")
                msg = msg.format(not_valid_before=attestation_cert.not_valid_before_utc)
                return callback.error(msg)
            # Try to get fido2 CA cert.
            own_site = backend.get_object(uuid=config.site_uuid)
            if not own_site:
                msg = _("Failed to load site: {site_uuid}")
                msg = msg.format(site_uuid=config.site_uuid)
                return callback.error(msg)
            try:
                ca_cert = own_site.fido2_ca_certs[issuer]
            except KeyError:
                msg = _("We dont have a fido2 CA cert to verify attestation certificate: {subject}: {issuer}")
                msg = msg.format(subject=subject, issuer=issuer)
                return callback.error(msg)
            # Load fido2 CA cert.
            ca_cert = ca_cert.encode()
            try:
                ca_cert = x509.load_pem_x509_certificate(ca_cert)
            except Exception as e:
                msg = _("Failed to load fido2 CA cert: {subject}")
                msg = msg.format(subject=subject)
                return callback.error(msg)
            # Verify signature.
            ca_cert_public_key = ca_cert.public_key()
            try:
                ca_cert_public_key.verify(attestation_cert.signature,
                                    attestation_cert.tbs_certificate_bytes,
                                    padding.PKCS1v15(),
                                    attestation_cert.signature_hash_algorithm)
            except Exception as e:
                msg = _("Failed to verify signature: {error}")
                msg = msg.format(error=e)
                return callback.error(msg)
            msg = _("Attestation certificate verified succesfully.")
            callback.send(msg)
        # Set credential data.
        self.credential_data = encode(auth_data.credential_data, "hex")
        self.reg_state = {}
        # Write object.
        self._cache(callback=callback)
        msg = _("Fido2 token deployed successful.")
        return callback.ok(msg)

    def test(
        self,
        force: bool=False,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Test token authentication. """
        credential_data = decode(self.credential_data, "hex")
        credentials = [AttestedCredentialData(credential_data)]
        fido2_server = self.get_fido2_server()
        request_options, \
        self.auth_state = fido2_server.authenticate_begin(credentials,
                                                    user_verification=self.uv)
        request_options_json = json.dumps(dict(request_options))
        smartcard_data = {
                    'rp'                : self.rp,
                    'token_path'        : self.rel_path,
                    'pass_required'     : False,
                    'request_options'   : request_options_json,
                    }
        # Do smartcard authentication on client.
        auth_response = callback.scauth(smartcard_type="fido2",
                                smartcard_data=smartcard_data)
        try:
            auth_response = json.loads(auth_response)
        except Exception:
            msg = _("Failed to decode auth response.")
            return callback.error(msg)
        try:
            fido2_server.authenticate_complete(self.auth_state,
                                                credentials,
                                                auth_response)
        except Exception as e:
            msg = _("Token verififcation failed: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        msg = _("Token verified successful: {rel_path}")
        msg = msg.format(rel_path=self.rel_path)
        return callback.ok(msg)

    def verify(
        self,
        smartcard_data: dict,
        callback: JobCallback=default_callback,
        **kwargs,
        ):
        """ Verify signature. """
        self.auth_state = smartcard_data['auth_state']
        auth_response = smartcard_data['auth_response']
        try:
            auth_response = json.loads(auth_response)
        except Exception:
            msg = _("Failed to decode auth response.")
            return callback.error(msg)
        credential_data = decode(self.credential_data, "hex")
        credentials = [AttestedCredentialData(credential_data)]
        fido2_server = self.get_fido2_server()
        try:
            fido2_server.authenticate_complete(self.auth_state,
                                                credentials,
                                                auth_response)
        except Exception as e:
            msg = _("Token verififcation failed: {e}")
            msg = msg.format(e=e)
            return callback.error(msg)
        return True

    @object_lock(full_lock=True)
    def _add(
        self,
        callback: JobCallback=default_callback,
        _caller: str="API",
        **kwargs,
        ):
        """ Add a fido2 token. """
        if _caller == "CLIENT":
            return_message = _("NOTE: You have to deploy this fido2 token to make it usable.")
            return callback.ok(return_message)
        return callback.ok()

    def show_config(self, callback: JobCallback=default_callback, **kwargs):
        """ Show token config. """
        if not self.verify_acl("view_public:object"):
            msg = _("Permission denied.")
            return callback.error(msg, exception=PermissionDenied)

        lines = []

        if self.verify_acl("view:credential_data"):
            lines.append(f'CREDENTIAL_DATA="{self.credential_data}"')
        else:
            lines.append('CREDENTIAL_DATA=""')

        if self.verify_acl("view:attestation_cert"):
            lines.append(f'ATTESTATION_CERT="{self.attestation_cert}"')
        else:
            lines.append('ATTESTATION_CERT=""')

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
