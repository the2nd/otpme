# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s" % __name__))
except:
    pass

from otpme.lib import jwt
from otpme.lib import slp
from otpme.lib import sotp
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import otpme_pass
from otpme.lib.encryption.ec import ECKey
from otpme.lib.encoding.base import decode
from otpme.lib.classes.session import Session
from otpme.lib.daemon.scriptd import run_script

from otpme.lib.exceptions import *

class AuthHandler(object):
    """ Authenticate user, do session creation etc. """
    def __init__(self):
        # Load JWT signing key.
        try:
            self.site_key
        except:
            my_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            self.site_key = my_site._key

        self.logger = config.logger

        self.valid_auth_modes = [ 'static', 'otp', 'ssh', 'smartcard', 'auto' ]

        # Log method that is used for failed requests (e.g. AUTH_FAILED)
        self.error_log_method = self.logger.warning

    def get_one_iter_hash(self, password, quiet=False):
        """ Get (insecure) one iteration password hash. """
        x_hash = otpme_pass.gen_one_iter_hash(self.user.name,
                                                password,
                                                quiet=quiet)
        return x_hash

    def gen_pass_hash(self, hash_type=None, hash_params=None):
        """ Gen password hash and handle caching for performance reasons. """
        # Without password we cannot create a hash.
        if not self.password:
            return
        if hash_params is None:
            hash_params = self.pass_hash_params
        if hash_params is None:
            if hash_type is None:
                hash_type = self.auth_group.get_config_parameter('session_hash_type')
        # Generate NT hash.
        if not self.nt_hash:
            self.nt_hash = stuff.gen_nt_hash(self.password)

        if self.auth_type == "mschap":
            self.password_hash = self.nt_hash
            return

        # Create password_hash for clear-text requests. Its at
        # least needed to count failed logins.
        hash_data = otpme_pass.gen_pass_hash(username=self.user.name,
                                            password=self.password,
                                            hash_args=hash_params,
                                            hash_type=hash_type,
                                            quiet=False)
        password_hash = hash_data.pop('hash')
        hash_params = hash_data.pop('hash_args')
        # Finally set password hash.
        self.password_hash = password_hash
        self.pass_hash_params = hash_params

    def verify_session(self, session, **kwargs):
        """ Try to verify session. """
        # Try to verify session:
        verify_reply = session.verify(**kwargs)

        session_status = verify_reply['status']
        if session_status is None:
            return None

        request_type = verify_reply['type']

        # Session verified successful.
        if request_type == "auth":
            self.logger.debug("Authentication parameters of request "
                            "matching session '%s'." % session.name)
            # If we found a session that matches this authentication request set
            # auth_session.
            self.auth_session = session
            # If we have a session no need to create a new one.
            if self.auth_session.access_group == self.access_group:
                self.create_sessions = False
            # Set password hash from matched session hash.
            self.password_hash = session.pass_hash
            if self.auth_type == "mschap":
                # Set NT_KEY
                self.nt_key = verify_reply['nt_key']
            return session_status

        # Found SLP.
        if request_type == "logout":
            self.logger.debug("This is a logout request for session '%s'."
                                % session.name)
            # Set this is a session logout-request.
            self.session_logout = True
            # If we found a session that matches this authentication request set
            # auth_session.
            self.auth_session = session
            # If we have a session no need to create a new one.
            self.create_sessions = False
            # Set auth_slp which will be used later (log auth data).
            self.auth_slp = verify_reply['slp']
            if self.auth_type == "mschap":
                # Set NT hash of SLP.
                self.password_hash = verify_reply['slp_hash']
                # Set NT_KEY.
                self.nt_key = verify_reply['nt_key']
                # Gen one iter hash used to add SLP to used list.
                self.one_iter_hash = self.get_one_iter_hash(self.auth_slp)
            else:
                self.password_hash = self.one_iter_hash
            return session_status

        # Found for SRP.
        if request_type == "refresh":
            self.logger.debug("This is a refresh request for session '%s'."
                                % session.name)
            # Set this is a session logout-request:
            self.session_refresh = True
            # If we found a session that matches this authentication request set
            # auth_session.
            self.auth_session = session
            # If we have a session no need to create a new one.
            self.create_sessions = False
            # Set auth_srp which will be used later (log auth data!)
            self.auth_srp = verify_reply['srp']
            if self.auth_type == "mschap":
                # Set SRP password hash.
                self.password_hash = verify_reply['srp_hash']
                # Set NT_KEY.
                self.nt_key = verify_reply['nt_key']
            else:
                self.password_hash = self.one_iter_hash
            return session_status

        # Found SOTP.
        if request_type == "reauth":
            # For MSCHAP requests we can now check for an already used SOTP.
            if self.auth_type == "mschap":
                # Get SOTP.
                self.auth_sotp = verify_reply['sotp']
                # Gen one iter hash used to add SOTP to used list.
                self.one_iter_hash = self.get_one_iter_hash(self.auth_sotp)
                # Set NT hash from SOTP.
                self.password_hash = verify_reply['sotp_hash']
                # Set NT_KEY
                self.nt_key = verify_reply['nt_key']
                # If we found an already used SOTP and this sessions is the
                # REALM session, authentication is not done but also not failed
                # because one of the child sessions may have been created by
                # this SOTP.
                if session.access_group == config.realm_access_group:
                    if self.user.is_used_sotp(hash=self.one_iter_hash):
                        return None

            if self.auth_type == "clear-text":
                # For REALM session childs (SOTP reauth) we use a one iteration
                # hash like we do for the REALM session itself.
                self.password_hash = self.one_iter_hash

            msg = ("Found valid REALM session '%s' for this request (SOTP)."
                    % session.name)
            self.logger.debug(msg)

            self.found_sotp = True
            # Add SOTP to list of users used SOTPs.
            self.user.add_used_sotp(hash=self.one_iter_hash)
            # Set auth session if we found an SOTP.
            self.auth_session = session
            # Update session (e.g. last used timestamp).
            self.update_session(session)
            # No need to create a session on reauth via SOTP with REALM
            # accessgroup.
            if self.access_group == config.realm_access_group:
                self.create_sessions = False
            return session_status

        # Session renegotiation.
        if request_type.startswith("reneg_"):
            # Set reneg type.
            self.reneg_type = request_type
            # Set auth session if we found an SOTP.
            self.auth_session = session
            # If we have a session no need to create a new one.
            self.create_sessions = False
            # Set password hash.
            self.password_hash = self.one_iter_hash
            return session_status

        # Default should be None -> session does not match request.
        return None

    def verify_auth_token(self):
        """ Make sure token is valid (e.g. group membership etc.) """
        # Check if we have a auth token.
        if not self.auth_token:
            self.logger.error("Found no valid auth token.")
            self.auth_failed = True
            if self.realm_login:
                self.auth_message = "LOGIN_FAILED_NO_TOKEN"
            else:
                self.auth_message = "AUTH_FAILED_NO_TOKEN"
            return

        # Check if auth token is in list of users tokens.
        if not self.auth_token.uuid in self.user.tokens:
            # We found a token which is not in list of user tokens. This should
            # normally not happen and is probably a configuration error.
            self.logger.error("Auth token '%s' is not in token list of user '%s'."
                        % (self.auth_token.name, self.user.name))
            # If token is not in list of user tokens we fail.
            self.auth_failed = True
            self.auth_message = "AUTH_CONFIG_ERROR"
            return

        # If user of this request is not the token owner authentication must
        # fail. Token().owner_uuid should reference back to UUID of user.
        if self.auth_token.owner_uuid != self.user.uuid:
            # We found a token which is in list of user tokens but its
            # owner_uuid does not match uuid of this user. This should
            # normally not happen and is probably a configuration error.
            self.logger.error("Warning: Token '%s' is in list of tokens for user "
                        "'%s' but is owned by user '%s'. "
                        "Possibly configuration error."
                        % (self.auth_token.name,
                            self.user.name,
                            self.auth_token.owner))
            # Set auth_failed.
            self.auth_failed = True
            self.auth_message = "AUTH_CONFIG_ERROR"
            return

        self.logger.debug("Token '%s' used at login is a token of user '%s'."
                    % (self.auth_token.name, self.user.name))

        # Make sure we use the destination token for linked tokens.
        if self.auth_token.destination_token:
            self.auth_token.dst_token = self.auth_token.get_destination_token()
            if self.auth_token.dst_token:
                self.verify_token = self.auth_token.dst_token
            else:
                self.logger.error("Token '%s' is missing its destination token."
                            % self.auth_token.name)
                # If redirected token is missing its destination token we must
                # fail. This should normally not happen and is probably a
                # configuration error.
                self.auth_failed = True
                self.auth_message = "AUTH_CONFIG_ERROR"
                return
        else:
            self.verify_token = self.auth_token

        # We want to allow a session logout even if the token used at login is
        # disabled now.
        if not self.session_logout:
            if not self.auth_token.enabled:
                self.logger.debug("Token '%s' is disabled. Authentication will fail."
                            % self.auth_token.name)
                self.auth_failed = True
                return
            if not self.verify_token.enabled:
                self.logger.debug("Token '%s' is disabled. Authentication will fail."
                            % self.verify_token.rel_path)
                self.auth_failed = True
                return

        # Check token policies.
        if self.check_policies:
            try:
                self.verify_token.run_policies("authenticate")
            except PolicyException as e:
                msg = str(e)
                self.logger.warning(msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_DENIED_BY_POLICY"
                return
            except Exception as e:
                config.raise_exception()
                msg = "Internal server error"
                log_msg = "%s: %s" % (msg, e)
                self.logger.critical(log_msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"
                return

        # We want to allow a session logout even if the token used at login is
        # not allowed for login anymore (e.g. daemon settings changed).
        if not self.session_logout:
            if self.require_token_types \
            and not self.verify_token.token_type in self.require_token_types:
                self.logger.debug("Token '%s' is not a valid token type for this "
                            "request. Authentication will fail."
                            % self.auth_token.name)
                self.auth_failed = True
                self.auth_message = "AUTH_SESSION_INVALID_TOKEN_TYPE"
                self.count_fails = False
                return

            if self.require_pass_types \
            and not self.verify_token.pass_type in self.require_pass_types:
                self.logger.debug("Token '%s' pass type is not valid for this "
                            "request. Authentication will fail."
                            % self.auth_token.name)
                self.auth_failed = True
                self.auth_message = "AUTH_SESSION_INVALID_TOKEN_PASS_TYPE"
                self.count_fails = False
                return

        # Check if token is valid for the accessgroup.
        if not self.auth_group.is_assigned_token(self.auth_token.uuid):
            # But we want to ignore token group validity for logout requests.
            if not self.session_logout:
                self.logger.warning("Verification failed because token is not valid "
                            "for accessgroup '%s'."
                            % self.access_group)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_NO_VALID_ACCESSGROUP"
                return

    def verify_session_token(self, session):
        """ Make sure session token is valid for this request. """
        # Create token instance.
        token = backend.get_object(object_type="token",
                                uuid=session.auth_token,
                                realm=self.user.realm,
                                site=self.user.site,
                                run_policies=True,
                                _no_func_cache=True)
        if not token:
            msg = ("WARNING: Token '%s' does not exists anymore. Maybe it was "
                    "deleted while this sessions exists?" % session.auth_token)
            self.logger.error(msg)
            # If the token for this session does not exist anymore auth must
            # fail.
            self.auth_failed = True
            self.auth_message = "AUTH_TOKEN_UNKNOWN"
            return

        # Set auth token from session.
        self.auth_token = token
        if self.found_sotp:
            config.auth_type = "sotp"
        else:
            config.auth_type = "token"

        # On session logout we are done here.
        if self.session_logout:
            return

        # Verify auth token.
        if not self.auth_failed:
            self.verify_auth_token()
        if self.auth_failed:
            return

    def update_session(self, session):
        """ Update session. """
        # If this is a refresh-request...
        if self.session_refresh:
            # Set auth_failed because we dont want to allow logins using SRPs
            self.auth_failed = True
            self.logger.debug("Session refresh request. Updating Session '%s'"
                        % session.name)
            self.auth_message = "AUTH_SESSION_REFRESH"
            # Update session last used timestamp.
            self.auth_session.update_last_used_time(update_child_sessions=True)
            # On session refresh authentication fails but the action was
            # successful. Thus loglevel INFO is sufficient.
            self.error_log_method = self.logger.info
            # Session update done.
            return

        # If this is a logout-request...
        if self.session_logout:
            # Set auth_failed because we dont want to allow logins using SLPs.
            self.auth_failed = True
            # But we dont want a logout request to be counted as failed login.
            self.count_fails = False
            if self.realm_logout:
                self.logger.info("Realm logout request. Removing session '%s'"
                            % session.name)
                self.auth_message = "REALM_LOGOUT_OK"
            else:
                self.logger.info("Logout request. Removing session '%s'"
                            % session.name)
                self.auth_message = "SESSION_LOGOUT_OK"
            # Delete session if this is a logout request.
            session.delete(force=True, recursive=True, verify_acls=False)
            # On session logout authentication fails but the action was
            # successful. Thus loglevel INFO is sufficient.
            self.error_log_method = self.logger.info
            # Session update done.
            return

        if self.session_reneg:
            if self.reneg_type == "reneg_start":
                self.auth_message = "AUTH_SESSION_RENEG_START"
            else:
                self.auth_message = "AUTH_SESSION_RENEG_DONE"
            # FIXME: Is this still the case?
            # Session renegotiation must return AUTH_OK to make it work with
            # e.g. radius requests.
            self.auth_status = True
            self.auth_failed = False
            # Update session last used timestamp.
            self.auth_session.update_last_used_time(update_child_sessions=True)
            return

        # If authentication is not already failed update session.
        if not self.auth_failed:
            # If this is a authentication request (not refresh and not logout)
            # set auth_status True.
            self.auth_status = True
            # If we found a SOTP we should not count up the login counter.
            if self.found_sotp:
                self.auth_message = "AUTH_OK_SOTP"
            else:
                self.auth_message = "AUTH_OK_SESSION"
            # Update session last used timestamp.
            self.auth_session.update_last_used_time(update_child_sessions=False)
            return

    def verify_user_sessions(self):
        """ Verify user sessions. """
        return_attributes = ['uuid', 'session_id', 'accessgroup']
        # Get REALM sessions for this user.
        result = backend.search(object_type="accessgroup",
                                attribute="name",
                                value=config.realm_access_group,
                                realm=config.realm,
                                site=config.site,
                                return_type="uuid")
        realm_access_group_uuid = result[0]
        user_realm_sessions = backend.get_sessions(user=self.user.uuid,
                                    access_group=realm_access_group_uuid,
                                    return_attributes=return_attributes)
                                    # We have to check all sessions here because
                                    # e.g. a smartcard session will do SOTP auth
                                    # when connecting to mgmtd.
                                    #session_type=self.auth_type)

        # Get realm sessions that have the requested accessgroup as child.
        verify_sessions = []
        realm_session_ids = []
        for session_uuid in user_realm_sessions:
            # Get session instance.
            session_id = user_realm_sessions[session_uuid]['session_id'][0]
            session = backend.get_object(object_type="session",
                                        uuid=session_uuid)
            if not session:
                continue
            # Outdate expired session.
            try:
                if not session.exists(outdate=True):
                    continue
            except LockWaitAbort:
                continue
            realm_session_ids.append(session_id)
            session_ag_uuid = user_realm_sessions[session_uuid]['accessgroup'][0]
            session_ag = backend.get_object(uuid=session_ag_uuid)
            session_ag_childs = session_ag.childs(recursive=True)
            if self.auth_group.uuid != session_ag.uuid:
                if self.auth_group.name not in session_ag_childs:
                    continue
            verify_sessions.append(session)

        # Get sessions for the session master.
        session_master = self.auth_group.parents(recursive=True,
                                                session_master=True,
                                                return_type="instance")
        session_master_session_ids = []
        if session_master:
            session_master_sessions = backend.get_sessions(user=self.user.uuid,
                                                access_group=session_master.uuid,
                                                return_attributes=return_attributes,
                                                session_type=self.auth_type)
            for session_uuid in session_master_sessions:
                # Get session instance.
                session_id = session_master_sessions[session_uuid]['session_id'][0]
                session = backend.get_object(object_type="session",
                                            uuid=session_uuid)
                if not session:
                    continue
                # Outdate expired session.
                try:
                    if not session.exists(outdate=True):
                        continue
                except LockWaitAbort:
                    continue
                if session in verify_sessions:
                    continue
                verify_sessions.append(session)
                session_master_session_ids.append(session_id)

        # Get sessions for this user/accessgroup.
        if self.auth_group.uuid != realm_access_group_uuid:
            group_session_ids = backend.get_sessions(user=self.user.uuid,
                                            access_group=self.auth_group.uuid,
                                            return_attributes=return_attributes,
                                            session_type=self.auth_type)
            for session_uuid in group_session_ids:
                # Get session instance.
                session_id = group_session_ids[session_uuid]['session_id'][0]
                session = backend.get_object(object_type="session",
                                            uuid=session_uuid)
                if not session:
                    continue
                # Outdate expired session.
                try:
                    if not session.exists(outdate=True):
                        continue
                except LockWaitAbort:
                    continue
                if session in verify_sessions:
                    continue
                verify_sessions.append(session)

        if not verify_sessions:
            self.logger.debug("No session found for this request.")

        # We use just one iteration for SOTPs because of performance
        # reasons (e.g. login and session renegotiation). This should
        # not be a problem because everyone with access to the OTPme
        # server can still do bad stuff and the RSP itself changes on
        # each login or renegotiation.
        password_hash = self.one_iter_hash

        # Check users sessions.
        processed_sessions = []
        for session in verify_sessions:
            if session.uuid in processed_sessions:
                continue
            processed_sessions.append(session.uuid)

            check_for_used_sotp = False
            if session.session_id in realm_session_ids:
                check_for_used_sotp = True
            if session.session_id in session_master_session_ids:
                check_for_used_sotp = True
            if self.allow_sotp_reuse:
                check_for_used_sotp = False

            if check_for_used_sotp:
                # For clear-text sessions we can check for an already used
                # SOTP before verifying the session.
                if self.auth_type == "clear-text":
                    # If we found an already used SOTP there is no need to
                    # check tis REALM session again. But we have to check if
                    # the child session this OTP created still exists and
                    # must be verified. We can NOT use self.check_used()
                    # here because this will make this request fail.
                    if self.user.is_used_sotp(hash=password_hash):
                        continue

            self.logger.debug("Verifying session '%s'." % session.name)

            # FIXME: implement session reneg for non-REALM sessions???
            if session.session_id in realm_session_ids:
                # Add realm session childs to list.
                realm_session_ids += session.child_sessions
                if session.access_group == config.realm_access_group:
                    check_auth = False
                    check_sotp = True
                    # No need to check for session renegotiation with MSCHAP
                    # requests.
                    if self.auth_type == "mschap":
                        do_reneg = False
                    else:
                        do_reneg = True
                else:
                    check_auth = True
                    check_sotp = False
                    do_reneg = False
            else:
                # Make sure we have a password hash.
                self.gen_pass_hash(hash_params=session.pass_hash_params)
                password_hash = self.password_hash
                do_reneg = False
                check_auth = True
                check_sotp = False
                if self.access_group == config.sso_access_group:
                    check_sotp = True
                if session_master:
                    if session_master.name == config.sso_access_group:
                        check_sotp = True

            if self.session_reneg is not None:
                do_reneg = self.session_reneg

            kwargs = {
                'do_reneg'          : do_reneg,
                'reneg_salt'        : self.reneg_salt,
                'rsp_hash_type'     : self.rsp_hash_type,
                'check_auth'        : check_auth,
                'check_sotp'        : check_sotp,
                'password'          : self.password,
                'password_hash'     : password_hash,
                'challenge'         : self.challenge,
                'response'          : self.response,
                }

            if self.access_group != config.realm_access_group:
                kwargs['auth_ag'] = self.access_group

            # Try to verify session.
            if self.verify_session(session, **kwargs) is not None:
                self.verify_session_token(session)
                self.update_session(session)
                self.request_cacheable = True
                break

    def logout_user_session(self, slp):
        """ Try to logout old session by given SLP. """
        self.logger.debug("Trying to logout old user session...")
        # Make sure SLP is string.
        slp = str(slp)
        # Get sessions for this user.
        user_sessions = backend.get_sessions(user=self.user.uuid,
                                access_group=self.auth_group.uuid)
        for session_uuid in user_sessions:
            # Get session instance.
            session = backend.get_object(object_type="session",
                                        uuid=session_uuid)
            if not session:
                continue
            # Outdate sessions.
            try:
                if not session.exists(outdate=True):
                    continue
            except LockWaitAbort:
                continue
            # Try to verify session.
            verify_reply = session.verify(password=slp,
                                        check_auth=False,
                                        check_srp=False,
                                        do_reneg=False,
                                        check_sotp=False,
                                        check_slp=True)

            session_status = verify_reply['status']
            if session_status is None:
                continue

            request_type = verify_reply['type']
            # Found SLP.
            if request_type == "logout":
                # Delete session if it matches the given SLP.
                session.delete(force=True, recursive=True, verify_acls=False)
                self.logger.debug("Logged out old user session: %s" % session.name)
                return session_status

    def check_used(self):
        """ Verify request password against already used SOTPs. """
        # Without password we cannot check.
        if not self.password:
            return

        self.logger.debug("Checking for used SOTP...")
        if not self.one_iter_hash:
            raise Exception("You have to set self.one_iter_hash first.")

        # Check if we checked this hash before (in this auth request). This is
        # to lower our load.
        if self.one_iter_hash in self.checked_hashes:
            return

        # Add hash to processed hashes.
        self.checked_hashes.append(self.one_iter_hash)

        # This check is needed because we dont want to count recurring SOTP
        # requests as failed logins.
        if not self.allow_sotp_reuse:
            if self.user.is_used_sotp(hash=self.one_iter_hash):
                self.logger.warning("Request contains an already used SOTP. "
                                    "Authentication will fail.")
                # If the password from this request is an already used SOTP
                # authentication must fail.
                self.auth_failed = True
                self.auth_message = "AUTH_ALREADY_USED_SOTP"

    def get_client(self):
        """ Try to get client of this request. """
        # If we got a host set client infos from it.
        if self.host and not self.client:
            self.client = self.host
            if not self.client:
                self.auth_failed = True
                self.auth_message = "AUTH_CLIENT_MISSING"
                return
            if self.host_ip:
                self.client_ip = self.host_ip
            # Search for host/node.
            if self.host_type:
                result = backend.search(attribute="name",
                                        value=self.host,
                                        object_type=self.host_type,
                                        return_type="instance")
            else:
                result = backend.search(attribute="name",
                                        value=self.host,
                                        object_types=['host', 'node'],
                                        return_type="instance")
                if result:
                    x_host = result[0]
                    if x_host.type != "node" and x_host.type != "host":
                        self.logger.warning("Unknown host type %s" % self.host_type)
                        self.auth_failed = True
                        self.auth_message = "AUTH_UNKNOWN_HOST_TYPE"
                        return
            if not result:
                # No need to verify host (e.g. realm join).
                if not self.verify_host:
                    return
                self.logger.warning("Unknown %s: %s" % (self.host_type, self.host))
                self.auth_failed = True
                self.auth_message = "AUTH_UNKNOWN_HOST"
                return
            # Get host.
            self.auth_host = result[0]
            self.access_group = config.realm_access_group

            # Check host policies.
            if self.check_policies:
                try:
                    self.auth_host.run_policies("authenticate")
                except PolicyException as e:
                    msg = str(e)
                    self.logger.warning(msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "AUTH_DENIED_BY_POLICY"
                    return
                except Exception as e:
                    config.raise_exception()
                    msg = "Internal server error"
                    log_msg = "%s: %s" % (msg, e)
                    self.logger.critical(log_msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"
                    return
            # Nothing more to do for host requests.
            return

        # Try to get client by IP address.
        if not self.client:
            if not self.client_ip:
                self.auth_failed = True
                self.auth_message = "AUTH_CLIENT_IP_MISSING"
                return
            client_result = backend.search(object_type="client",
                                        attribute="address",
                                        value=self.client_ip,
                                        return_type="name")
            if client_result:
                self.client = client_result[0]

        if not self.client:
            self.auth_failed = True
            self.auth_message = "AUTH_CLIENT_MISSING"
            return

        # Create client instance for the client of this request.
        self.auth_client = backend.get_object(object_type="client",
                                                realm=config.realm,
                                                site=config.site,
                                                name=self.client,
                                                run_policies=True,
                                                _no_func_cache=True)

        # If client is set it must exist for authentication to proceed.
        if not self.auth_client:
            # If client does not exist authentication is failed.
            self.auth_failed = True
            self.logger.error("Client '%s' does not exist." % self.client)
            self.auth_message = "AUTH_CLIENT_UNKNOWN"
            return

        # If client is not enabled authentication must fail.
        if not self.auth_client.enabled and not self.user.allow_disabled_login:
            self.logger.debug("Client '%s' is disabled." % self.client)
            # If client is disabled auth must fail.
            self.auth_failed = True
            self.auth_message = "AUTH_CLIENT_DISABLED"
            return

        # Get accessgroup from client.
        if not self.access_group:
            self.access_group = self.auth_client.access_group
            if not self.access_group:
                msg = ("Client does not have accessgroup set: %s"
                        % self.auth_client.name)
                self.logger.debug(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_CLIENT_NO_ACCESSGROUP"
                return

        # Check client policies.
        if self.check_policies:
            try:
                self.auth_client.run_policies("authenticate")
            except PolicyException as e:
                msg = str(e)
                self.logger.warning(msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_DENIED_BY_POLICY"
                return
            except Exception as e:
                config.raise_exception()
                msg = "Internal server error"
                log_msg = "%s: %s" % (msg, e)
                self.logger.critical(log_msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"
                return

    def check_accessgroup(self):
        """ Get accessgroup instance. """
        # If auth is already failed not need to check accessgroup.
        if self.auth_failed:
            return
        # Create accessgroup instance.
        self.auth_group = backend.get_object(object_type="accessgroup",
                                            realm=config.realm,
                                            site=config.site,
                                            name=self.access_group,
                                            run_policies=True,
                                            _no_func_cache=True)
        # Check if group exists.
        if not self.auth_group:
            self.logger.warning("Access group '%s' does not exist."
                            % self.access_group)
            # If group does not exist auth must fail.
            self.auth_failed = True
            self.auth_message = "AUTH_GROUP_UNKNOWN"
            return

        # If group is not enabled authentication must fail.
        if not self.auth_group.enabled and not self.user.allow_disabled_login:
            self.logger.warning("Access group '%s' is disabled." % self.access_group)
            # If group is disabled auth must fail.
            self.auth_failed = True
            self.auth_message = "AUTH_GROUP_DISABLED"
            return

        # Check if sessions are enabled for the accessgroup.
        if self.create_sessions:
            # FIXME: maybe we will add two options for accessgroups in the future.
            #        AccessGroup().session_verify_enabled and AccessGroup().session_creation_enabled
            #
            # If sessions are not enabled for the given access_group disable
            # session creation. Verification must still be done because we have
            # to check for sessions created from access_group parents.
            if not self.auth_group.sessions_enabled:
                self.create_sessions = False
                self.logger.debug("Session creation for accessgroup '%s' is "
                            "disabled. Verification of parent sessions will "
                            "still be done." % self.access_group)

    def check_user(self):
        """ Check user status. """
        # If auth is already failed no need to check user status.
        if self.auth_failed:
            return

        # Make sure authentication with users realm is not disabled.
        if not self.user.is_admin() \
        and not self.realm_logout \
        and not self.user.allow_disabled_login:
            user_realm = backend.get_object(object_type="realm",
                                        uuid=self.user.realm_uuid)
            if not user_realm.auth_enabled:
                self.logger.warning("Authentication with realm is disabled: %s"
                                    % (user_realm.name))
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_REALM_DISABLED"
                return

            # Make sure authentication with users site is not disabled.
            user_site = backend.get_object(object_type="site",
                                    uuid=self.user.site_uuid)
            if not user_site.auth_enabled:
                self.logger.warning("Authentication with site is disabled: %s/%s"
                                    % (user_site.realm, user_site.name))
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_SITE_DISABLED"
                return

        # Make sure users unit is not disabled.
        if not self.user.is_admin() \
        and not self.realm_logout \
        and not self.user.allow_disabled_login:
            users_unit = self.user.get_parent_object()
            if not users_unit.enabled:
                self.logger.warning("Users unit is disabled: %s"
                                    % (users_unit.name))
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_UNIT_DISABLED"
                return

        # If user is disabled or locked authentication is failed.
        if not self.user.enabled:
            self.logger.warning("User '%s' is disabled." % self.user.name)
            self.auth_failed = True
            self.auth_message = "AUTH_USER_DISABLED"
            return

        if self.user.is_blocked(self.access_group,
                                realm=config.realm,
                                site=config.site):
            msg = ("User '%s' is blocked for accessgroup '%s'."
                    % (self.user.name, self.access_group))
            self.logger.warning(msg)
            self.auth_failed = True
            self.auth_message = "AUTH_USER_BLOCKED"
            self.count_fails = False

        # Check user policies.
        if self.check_policies:
            try:
                self.user.run_policies("authenticate")
            except PolicyException as e:
                msg = str(e)
                self.logger.warning(msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_DENIED_BY_POLICY"
                return
            except Exception as e:
                config.raise_exception()
                msg = "Internal server error"
                log_msg = "%s: %s" % (msg, e)
                self.logger.critical(log_msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"
                return

    def get_user_tokens(self):
        """ Select user tokens based on request parameters. """
        # If auth is already failed no need to select user tokens.
        if self.auth_failed:
            return
        # If user is already authenticated (by session) no need to select user
        # tokens.
        if self.auth_status is True:
            return

        if self.user_token:
            # If a token was given load it.
            token = self.user.token(self.user_token)
            if not token:
                raise Exception(_("Token does not exist: %s") % self.user_token)

            self.logger.debug("Verifying token from request: %s" % token.rel_path)
            if not self.auth_group.is_assigned_token(token.uuid):
                self.logger.warning("Token '%s' is not in accessgroup '%s'. "
                                "Authentication will fail."
                                % (token.rel_path, self.access_group))
                # If the given token is not in the given accessgroup auth must
                # fail.
                self.auth_failed = True
                self.auth_message = "AUTH_TOKEN_NOT_IN_GROUP"
                return

            # Make sure we resolve token links.
            if token.destination_token:
                if not token.dst_token:
                    self.logger.error("Token '%s' is missing its destination token."
                                % token.name)
                    # This should normally not happen and is probably a
                    # configuration error.
                    self.auth_failed = True
                    self.auth_message = "AUTH_CONFIG_ERROR"
                    return
                verify_token = token.dst_token
            else:
                verify_token = token

            token_pass_type = verify_token.pass_type
            if token_pass_type == "ssh_key":
                if self.auth_type == "ssh":
                    self.valid_user_tokens_ssh = [ token ]
            if token_pass_type == "smartcard":
                self.valid_user_tokens_smartcard = [ token ]
            if token_pass_type == "static":
                self.valid_user_tokens_static = [ token ]
            if token_pass_type == "otp":
                self.valid_user_tokens_otp = [ token ]
            if token_pass_type == "script_static":
                self.valid_user_tokens_script_static = [ token ]
            if token_pass_type == "script_otp":
                self.valid_user_tokens_script_otp = [ token ]
            if token_pass_type == "otp_push":
                self.valid_user_tokens_otp_push = [ token ]

        else:
            self.logger.debug("Selecting user tokens based on access_group '%s'."
                            % self.access_group)

            select_static_tokens = True
            select_otp_tokens = True
            select_ssh_tokens = True

            # Make sure we honor self.require_pass_types when selecting tokens.
            if self.auth_mode == "static" or self.auth_mode == "auto":
                if self.require_pass_types \
                and "static" not in self.require_pass_types:
                    select_static_tokens = False

            if self.auth_mode == "otp" or self.auth_mode == "auto":
                if self.require_pass_types \
                and "otp" not in self.require_pass_types:
                    select_otp_tokens = False

            if self.auth_type == "ssh":
                if self.require_pass_types \
                and "ssh_key" not in self.require_pass_types:
                    select_ssh_tokens = False

            # Select user tokens by pass type and self.require_token_types if
            # given.
            if select_static_tokens:
                self.valid_user_tokens_static += self.user.get_tokens(
                                                pass_type="static",
                                                token_types=self.require_token_types,
                                                access_group=self.auth_group,
                                                host=self.auth_host,
                                                client=self.auth_client,
                                                return_type="instance", quiet=False)
                self.valid_user_tokens_script_static += self.user.get_tokens(
                                                pass_type="script_static",
                                                access_group=self.auth_group,
                                                token_types=self.require_token_types,
                                                host=self.auth_host,
                                                client=self.auth_client,
                                                return_type="instance", quiet=False)

            if select_otp_tokens:
                self.valid_user_tokens_otp += self.user.get_tokens(
                                                pass_type="otp",
                                                access_group=self.auth_group,
                                                token_types=self.require_token_types,
                                                host=self.auth_host,
                                                client=self.auth_client,
                                                return_type="instance", quiet=False)
                self.valid_user_tokens_script_otp += self.user.get_tokens(
                                                pass_type="script_otp",
                                                access_group=self.auth_group,
                                                token_types=self.require_token_types,
                                                host=self.auth_host,
                                                client=self.auth_client,
                                                return_type="instance", quiet=False)
                self.valid_user_tokens_otp_push += self.user.get_tokens(
                                                pass_type="otp_push",
                                                access_group=self.auth_group,
                                                token_types=self.require_token_types,
                                                host=self.auth_host,
                                                client=self.auth_client,
                                                return_type="instance", quiet=False)

            if select_ssh_tokens:
                self.valid_user_tokens_ssh += self.user.get_tokens(
                                            pass_type="ssh_key",
                                            access_group=self.auth_group,
                                            token_types=self.require_token_types,
                                            host=self.auth_host,
                                            client=self.auth_client,
                                            return_type="instance", quiet=False)

        if not self.user_default_token:
            for token in list(self.valid_user_tokens_static):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_static.remove(token)
        if not self.user_default_token:
            for token in list(self.valid_user_tokens_otp):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_otp.remove(token)
        if not self.user_default_token:
            for token in list(self.valid_user_tokens_script_static):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_script_static.remove(token)
        if not self.user_default_token:
            for token in list(self.valid_user_tokens_script_otp):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_script_otp.remove(token)
        if not self.user_default_token:
            for token in list(self.valid_user_tokens_otp_push):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_otp_push.remove(token)
        if not self.user_default_token:
            for token in list(self.valid_user_tokens_ssh):
                if token.uuid == self.user.default_token:
                    self.user_default_token = token
                    self.valid_user_tokens_ssh.remove(token)

        # If no token was found log it and set authentication failed.
        if not self.valid_user_tokens_static \
        and not self.valid_user_tokens_otp \
        and not self.valid_user_tokens_script_static \
        and not self.valid_user_tokens_script_otp \
        and not self.valid_user_tokens_otp_push \
        and not self.valid_user_tokens_smartcard \
        and not self.valid_user_tokens_ssh \
        and not self.user_default_token:
            self.logger.warning("Unable to find a token to verify this request.")
            self.auth_failed = True
            self.auth_message = "AUTH_TOKEN_MISSING"

    def verify_user_token(self, token):
        """ Verify the given user token. """
        if not token.enabled:
            self.logger.debug("Not verifying disabled token: %s" % token.name)
            return None

        # Make sure we use the destination token for linked tokens.
        if token.destination_token:
            if not token.dst_token.enabled:
                self.logger.debug("Not verifying disabled destination token: %s"
                            % token.dst_token.rel_path)
                return None
            _verify_token = token.dst_token
        else:
            _verify_token = token

        # Check for a second factor token.
        if _verify_token.second_factor_token_enabled:
            try:
                _sftoken = _verify_token.get_sftoken()
            except Exception as e:
                self.logger.critical("Unable to load second factor token of '%s': %s"
                                % (token.rel_path, e))
                return None
        else:
            _sftoken = None

        # Set auth data depending on token type.
        token_verify_parms = {}
        if _verify_token.pass_type == "otp":
            token_verify_parms = {
                    'auth_type'         : self.auth_type,
                    'challenge'         : self.challenge,
                    'response'          : self.response,
                    'otp'               : self.password,
                    }

        if _verify_token.pass_type == "static":
            token_verify_parms = {
                    'auth_type'         : self.auth_type,
                    'challenge'         : self.challenge,
                    'response'          : self.response,
                    'password'          : self.password,
                    }

        if _verify_token.pass_type == "ssh_key":
            if self.auth_type == "mschap":
                return None
            token_verify_parms = {
                    'auth_type'         : self.auth_type,
                    'challenge'         : self.challenge,
                    'response'          : self.response,
                    'otp'               : self.password,
                    }

        if _verify_token.token_type.startswith("script_"):
            token_verify_parms = {
                    'auth_type'         : self.auth_type,
                    'auth_user'         : self.user.name,
                    'auth_group'        : self.access_group,
                    'auth_token'        : _verify_token.name,
                    'auth_client'       : self.client,
                    'auth_client_ip'    : self.client_ip,
                    }
            if self.auth_type == "clear-text":
                if _verify_token.token_type == "script_otp":
                    token_verify_parms['auth_otp'] = self.password
                if _verify_token.token_type == "script_static":
                    token_verify_parms['auth_pass'] = self.password
            if self.auth_type == "mschap":
                token_verify_parms['auth_challenge'] = self.challenge
                token_verify_parms['auth_response'] = self.response

        if _verify_token.pass_type == "otp_push":
            token_verify_parms = {
                    'auth_type'         : self.auth_type,
                    'challenge'         : self.challenge,
                    'response'          : self.response,
                    'password'          : self.password,
                    }

        # Handle smartcard tokens.
        found_smartcard_token = False
        if _verify_token.pass_type == "smartcard":
            found_smartcard_token = True
        if _sftoken and _sftoken.pass_type == "smartcard":
            found_smartcard_token = True
        if found_smartcard_token:
            # Add smartcard data to token verify parameters.
            token_verify_parms['smartcard_data'] = self.smartcard_data

        # Add session UUID.
        token_verify_parms['session_uuid'] = self.new_session_uuid

        self.logger.debug("Verifying %s-token '%s'."
                    % (token.token_type, token.rel_path))

        verify_status = None
        # Try to verify token. A status of None means continue to next token.
        if _verify_token.temp_password_hash is not None:
            self.create_sessions = False
            if self.auth_type == "mschap":
                token_verify_parms['temp'] = True
            else:
                # Verify temp password.
                t_args = {}
                t_args['challenge'] = self.challenge
                t_args['response'] = self.response
                t_args['password'] = self.password
                try:
                    verify_status = _verify_token.verify_temp_password(**t_args)
                except Exception as e:
                    self.logger.critical("Verification of token (temp) '%s' returned error: %s"
                                    % (token.name, e))
                    config.raise_exception()
                if verify_status is True:
                    self.temp_password_auth = True

        # Verify token.
        if verify_status is None:
            try:
                verify_status = _verify_token.verify(**token_verify_parms)
            except Exception as e:
                self.logger.critical("Verification of token '%s' returned error: %s"
                                % (token.name, e))
                config.raise_exception()

        if self.auth_type == "mschap":
            # For OTP tokens verify() returns a tuple with verify status,
            # clear-text OTP, and NT_KEY. For static password tokens the
            # password hash is returned instead of the OTP.
            mschap_status = verify_status
            # Get status from return value.
            verify_status = mschap_status[0]

        if verify_status is None:
            # If we got "None" as status token verification was not successful
            # but is also not failed and we can check next token.
            return None

        # If status is not None we found token of this request.
        self.auth_token = token
        self.verify_token = _verify_token
        if self.found_sotp:
            config.auth_type = "sotp"
        else:
            config.auth_type = "token"

        # Verify auth token.
        if not self.auth_failed:
            self.verify_auth_token()
        if self.auth_failed:
            return

        # Make sure we have a password hash.
        if self.password and not self.realm_login and not self.realm_logout:
            if self.temp_password_auth:
                if self.verify_token.temp_password_hash:
                    self.password_hash = self.verify_token.temp_password_hash
                    self.pass_hash_params = self.verify_token.temp_password_hash_params
                    self.request_cacheable = True
            elif self.verify_token.password_hash:
                if not self.verify_token.second_factor_token_enabled:
                    self.password_hash = self.verify_token.password_hash
                    self.pass_hash_params = self.verify_token.password_hash_params
            if not self.password_hash:
                self.gen_pass_hash()

        # Check token policies.
        if self.check_policies:
            try:
                self.verify_token.run_policies("authenticate")
            except PolicyException as e:
                msg = str(e)
                self.logger.warning(msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_DENIED_BY_POLICY"
                return False
            except Exception as e:
                config.raise_exception()
                msg = "Internal server error"
                log_msg = "%s: %s" % (msg, e)
                self.logger.critical(log_msg)
                self.auth_failed = True
                self.count_fails = False
                self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"
                return False

        # otp_push tokens need special handling.
        if self.verify_token.pass_type == "otp_push" and verify_status:
            self.logger.debug("Token '%s' verified successful. Sending OTP to user..."
                        % token.name)
            # Make sure auth will fail.
            verify_status = False
            # But we dont want this request to be counted as failed login.
            self.count_fails = False
            # Now send the OTP.
            try:
                self.verify_token.send_otp()
                otp_sent = True
            except Exception as e:
                self.logger.warning("Error sending OTP to user: %s" % e)
                otp_sent = False
            # Reset failed login counter for this user/group.
            self.reset_user_fail_counter()
            if otp_sent:
                self.auth_message = "AUTH_OTP_PUSH"
                # Authentication with otp_push tokens always fails but if
                # the OTP was sent successful loglevel INFO is sufficient.
                self.error_log_method = self.logger.info
            else:
                self.auth_message = "AUTH_OTP_PUSH_FAILED"

        if verify_status is False:
            # If status is "False" the OTP was already used or any other
            # definitively failure occurred.
            self.auth_status = False
            # And thus no more verification should be done.
            self.auth_failed = True
            # And we want this request to be counted as failed login, but only
            # if self.count_fails was not set before (e.g. by otp_push token)
            if self.count_fails is None:
                self.count_fails = True
            return False

        # If token was verified successful set session parameters. Set auth mode
        # based on token type if needed.
        if self.auth_mode == "auto":
            if self.verify_token.pass_type in [ 'otp', 'otp_push', 'script_otp' ]:
                self.auth_mode = "otp"
            if self.verify_token.pass_type in [ 'static', 'script_static' ]:
                self.auth_mode = "static"
            if self.verify_token.pass_type in [ 'smartcard' ]:
                self.auth_mode = "smartcard"
            if self.verify_token.pass_type in [ 'ssh_key' ]:
                self.auth_mode = "ssh"

        if self.auth_type == "mschap":
            # Set auth data we got from token.verify().
            self.nt_key = mschap_status[1]
            # Get clear-text OTP.
            if self.verify_token.pass_type == "otp":
                self.password = mschap_status[2]
                self.gen_pass_hash()
            # For static password tokens mschap_status contains the password
            # hash instead of the used clear-text password.
            if self.verify_token.pass_type == "static":
                self.password_hash = mschap_status[2]

        # Check if the user has an auth script enabled.
        if self.user.auth_script_enabled:
            # Set auth type idependent values.
            user_script_parms = {
                    'options'           : self.user.auth_script_options,
                    'auth_type'         : self.auth_type,
                    'auth_user'         : self.user.name,
                    'auth_group'        : self.access_group,
                    'auth_token'        : self.verify_token.name,
                    'auth_client'       : self.client,
                    'auth_client_ip'    : self.client_ip,
                    }

            if self.auth_mode == "otp":
                user_script_parms['auth_otp'] = self.password

            if self.auth_mode == "static":
                user_script_parms['auth_pass'] = self.password

            if self.auth_type == "mschap":
                user_script_parms['auth_challenge'] = self.challenge
                user_script_parms['auth_response'] = self.response
                user_script_parms['auth_nt_key'] = self.nt_key

            if self.auth_type == "ssh":
                user_script_parms['auth_challenge'] = self.challenge
                user_script_parms['auth_response'] = self.response
                user_script_parms['auth_otp'] = self.password

            auth_script_oid = backend.get_oid(object_type="script", uuid=self.user.auth_script)
            msg = "Starting user authorization script: %s" % auth_script_oid
            self.logger.debug(msg)

            # Get groups the user is in.
            user_groups = self.user.get_groups(return_type="name")

            # Run auth script.
            try:
                auth_script_result = run_script(script_type="auth_script",
                                            script_uuid=self.user.auth_script,
                                            script_parms=user_script_parms,
                                            user=self.user.name,
                                            group=self.user.group,
                                            groups=user_groups)
            except Exception as e:
                msg = ("Error running user authorization script: %s" % e)
                self.logger.warning(msg)
                self.auth_message = "USER_AUTH_SCRIPT_ERROR"
                self.auth_failed = True
                #config.raise_exception()
                return False

            # Check auth script return code.
            if not auth_script_result:
                msg = ("User '%s' authenticated successful with token '%s' "
                        "but user authorization script returned failure."
                        % (self.user.name, self.verify_token.name))
                self.logger.debug(msg)
                self.auth_message = "USER_AUTH_SCRIPT_FAILED"
                self.auth_failed = True
                # FIXME: Do we want to allow the auth script to decide
                #        if we should count failed login requests!!?
                # Return False as we found a valid token but user auth script
                # failed.
                return False

        # Check if the token has an auth script enabled.
        if self.verify_token.auth_script_enabled:
            # Set auth type idependent values.
            token_script_parms = {
                    'options'           : self.verify_token.auth_script_options,
                    'auth_type'         : self.auth_type,
                    'auth_user'         : self.user.name,
                    'auth_group'        : self.access_group,
                    'auth_token'        : self.verify_token.name,
                    'auth_client'       : self.client,
                    'auth_client_ip'    : self.client_ip,
                                }

            if self.auth_mode == "otp":
                token_script_parms['auth_otp'] = self.password

            if self.auth_mode == "static":
                token_script_parms['auth_pass'] = self.password

            if self.auth_type == "mschap":
                token_script_parms['auth_challenge'] = self.challenge
                token_script_parms['auth_response'] = self.response
                token_script_parms['auth_nt_key'] = self.nt_key

            if self.auth_type == "ssh":
                token_script_parms['auth_challenge'] = self.challenge
                token_script_parms['auth_response'] = self.response
                token_script_parms['auth_otp'] = self.password

            self.logger.debug("Starting token authorization script...")
            # Run auth script.
            try:
                auth_script_result = run_script(script_type="auth_script",
                                            script_uuid=self.verify_token.auth_script,
                                            script_parms=token_script_parms,
                                            user=self.user.name,
                                            group=self.user.group)
            except Exception as e:
                config.raise_exception()
                self.logger.critical("Error running token authorization script: %s"
                                % e)
                self.auth_message = "TOKEN_AUTH_SCRIPT_ERROR"
                self.auth_failed = True
                return False

            # Check auth script return code.
            if not auth_script_result:
                self.logger.debug("Token '%s' verified successful but token "
                            "authorization script returned failure."
                            % self.verify_token.name)
                self.auth_message = "TOKEN_AUTH_SCRIPT_FAILED"
                self.auth_failed = True
                # Return False as we found a valid token but auth script failed.
                return False

        # At this point token verification was successful!
        # Set auth status.
        self.auth_status = True

        # Handle non-realm login requests.
        self.logger.debug("Token '%s' verified successful."
                    % self.auth_token.name)
        if self.auth_mode == "otp":
            if self.verify_token.pass_type == "script_otp":
                if self.realm_login:
                    self.auth_message = "LOGIN_OK_SCRIPT_OTP"
                else:
                    self.auth_message = "AUTH_OK_SCRIPT_OTP"
            if self.verify_token.pass_type == "otp":
                if self.realm_login:
                    self.auth_message = "LOGIN_OK_OTP"
                else:
                    self.auth_message = "AUTH_OK_OTP"
        if self.auth_mode == "static":
            if self.verify_token.pass_type == "script_static":
                if self.realm_login:
                    self.auth_message = "LOGIN_OK_SCRIPT_STATIC"
                else:
                    self.auth_message = "AUTH_OK_SCRIPT_STATIC"
            if self.verify_token.pass_type == "static":
                if self.realm_login:
                    self.auth_message = "LOGIN_OK_STATIC"
                else:
                    self.auth_message = "AUTH_OK_STATIC"
        if self.auth_token.pass_type == "ssh_key":
            if self.auth_type == "ssh":
                if self.password:
                    if self.realm_login:
                        self.auth_message = "LOGIN_OK_SSH_OTP"
                    else:
                        self.auth_message = "AUTH_OK_SSH_OTP"
                else:
                    if self.realm_login:
                        self.auth_message = "LOGIN_OK_SSH"
                    else:
                        self.auth_message = "AUTH_OK_SSH"
            else:
                if self.realm_login:
                    self.auth_message = "LOGIN_OK_STATIC"
                else:
                    self.auth_message = "AUTH_OK_STATIC"

        if self.auth_mode == "smartcard":
            if self.realm_login:
                self.auth_message = "LOGIN_OK_SMARTCARD"
            else:
                self.auth_message = "AUTH_OK_SMARTCARD"

        if self.auth_mode == "static":
            self.request_cacheable = True

        # Return True because we found a valid token.
        return True

    def verify_user_tokens(self, tokens):
        """ Check if one of the given tokens can authenticate this request. """
        for token in tokens:
            token_status = self.verify_user_token(token=token)
            # True means token verification successful.
            if token_status is True:
                return True
            # False means token verification failed.
            if token_status is False:
                return False

        # Default should be None (e.g. no valid token found)
        return None

    def verify_jwt(self):
        """ Verify received JWT. """
        # Get users site public key to verify the JWT.
        site = backend.get_object(object_type="site",
                            uuid=self.user.site_uuid)
        site_jwt_key = site._cert_public_key

        # The JWT reason we need to check.
        required_reason = "REALM_AUTH"
        if self.realm_login:
            required_reason = "REALM_LOGIN"

        # Verify outer JWT. This JWT must be signed by the users site
        # certificate to indicate an authenticated user.
        try:
            outer_jwt_data = jwt.decode(jwt=self.redirect_response,
                                key=site_jwt_key,
                                algorithm='RS256')
        except Exception as e:
            msg = "JWT verification failed: %s" % e
            self.logger.warning(msg)
            self.auth_failed = True
            self.auth_message = "AUTH_INVALID_OUTER_JWT"

        if not self.auth_failed:
            # Get JWT challenge.
            try:
                jwt_string = outer_jwt_data['challenge']
            except:
                msg = "JWT data is missing challenge."
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_CHALLENGE_MISSING"
                self.count_fails = False

        if not self.auth_failed:
            # Make sure we got the correct JWT. The JWT includes a challenge,
            # so if the JWT string does not match the redirect challenge we got
            # from OTPmeServer() authentication must fail.
            if jwt_string != self.redirect_challenge:
                msg = "Received wrong redirect challenge."
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_WRONG_JWT_CHALLENGE"

        if not self.auth_failed:
            # Get login token.
            try:
                login_token_uuid = outer_jwt_data['login_token']
            except:
                login_token_uuid = None
                msg = "JWT data is missing login token."
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_TOKEN_MISSING"
                self.count_fails = False

        if not self.auth_failed:
            # Get auth accessgroup.
            try:
                auth_accessgroup = outer_jwt_data['accessgroup']
            except:
                auth_accessgroup = None
                msg = "JWT data is missing login accessgroup."
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_ACCESSGROUP_MISSING"
                self.count_fails = False

        if not self.auth_failed:
            # Get auth reason.
            try:
                auth_reason = outer_jwt_data['reason']
            except:
                auth_reason = None
                msg = "JWT data is missing auth reason."
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_ACCESSGROUP_MISSING"
                self.count_fails = False

        if not self.auth_failed:
            # Verify outer JWT auth accessgroup.
            if auth_accessgroup != self.access_group:
                msg = ("Outer JWT accessgroup mismatch: %s <> %s"
                        % (self.access_group, auth_accessgroup))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_ACCESSGROUP_MISMATCH"
                self.count_fails = False

        if not self.auth_failed:
            # Verify outer JWT auth reason.
            if auth_reason != required_reason:
                msg = ("Outer JWT reason mismatch: %s <> %s"
                        % (required_reason, auth_reason))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_REASON_MISMATCH"
                self.count_fails = False

        # Decode inner JWT. This is the JWT we sent to the client in the
        # preauth_check phase. It must be signed by our site cert and
        # include our site/realm in its payload.
        if not self.auth_failed:
            try:
                inner_jwt_data = jwt.decode(jwt=jwt_string,
                                    key=self.site_key,
                                    algorithm='RS256')
            except Exception as e:
                msg = "Unable to decode inner JWT: %s" % e
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_INVALID_INNER_JWT"

            # Get inner JWT data.
            jwt_reason = inner_jwt_data['reason']
            jwt_realm = inner_jwt_data['realm']
            jwt_site = inner_jwt_data['site']
            jwt_user = inner_jwt_data['user']
            jwt_accessgroup = inner_jwt_data['accessgroup']

            if jwt_realm != config.realm:
                msg = ("Inner JWT realm mismatch: %s <> %s"
                        % (config.realm, jwt_site))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_REALM_MISMATCH"

            if jwt_site != config.site:
                msg = ("Inner JWT site mismatch: %s <> %s"
                        % (config.site, jwt_site))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_SITE_MISMATCH"

            if jwt_user != self.user.name:
                msg = ("Inner JWT user mismatch: %s <> %s"
                        % (self.user.name, jwt_user))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_USER_MISMATCH"

            if jwt_accessgroup != self.access_group:
                msg = ("Inner JWT accessgroup mismatch: %s <> %s"
                        % (self.access_group, jwt_accessgroup))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_ACCESSGROUP_MISMATCH"

            if jwt_reason != required_reason:
                msg = ("Inner JWT reason mismatch: %s <> %s"
                        % (required_reason, jwt_reason))
                self.logger.warning(msg)
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_ACCESSGROUP_MISMATCH"

        if not self.auth_failed:
            # Get user token used to request JWT from his site.
            self.auth_token = backend.get_object(object_type="token",
                                                uuid=login_token_uuid,
                                                run_policies=True,
                                                _no_func_cache=True)
            if not self.auth_token:
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_UNKNOWN_TOKEN"

        if not self.auth_failed:
            if self.auth_token.realm != site.realm:
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_INVALID_TOKEN_REALM"

        if not self.auth_failed:
            if self.auth_token.site != site.name:
                self.auth_failed = True
                self.auth_message = "AUTH_JWT_INVALID_TOKEN_SITE"

        # Verify auth token (group membership etc.)
        if not self.auth_failed:
            self.verify_auth_token()

        if not self.auth_failed:
            self.auth_status = True
            if self.realm_login:
                self.auth_message = "LOGIN_OK_JWT"
            else:
                self.auth_message = "AUTH_OK_JWT"

    def check_max_sessions(self):
        """ Check for max_sessions. """
        # Get sessions of the user.
        user_sessions = backend.get_sessions(user=self.user.uuid,
                                access_group=self.auth_group.uuid)
        # Walk through session list.
        session_list = []
        for session_uuid in user_sessions:
            # Get session instance for already existing session.
            session_x = backend.get_object(object_type="session",
                                            uuid=session_uuid)
            if not session_x:
                continue
            # Outdate sessions.
            try:
                if not session_x.exists(outdate=True):
                    continue
            except LockWaitAbort:
                continue
            session_list.append(session_x)

        # List that will hold all user session instances.
        # Check if we would (+1) reach max_sessions when adding this session.
        if (len(session_list) + 1) <= self.auth_group.max_sessions:
            return

        user_sessions = {}
        self.logger.debug("Max sessions reached for this accessgroup: %s"
                    % self.auth_group.max_sessions)
        # If relogin timeout is set check if there is a session we can
        # replace.
        if (len(session_list) + 1) >= self.auth_group.max_sessions:
            if self.auth_group.relogin_timeout > 0:
                self.logger.debug("Checking for sessions older than relogin "
                            "timeout: %s" % self.auth_group.relogin_timeout)
                # Walk through session list.
                for session_x in session_list:
                    # Add sessions to dict with a dict key that starts
                    # with last used timestamp.
                    dict_key = "%s %s" % (session_x.last_used,
                                        session_x.session_id)
                    dict_entry = { dict_key : session_x }
                    user_sessions.update(dict_entry)

                found_obsolete_session = False
                # Walk through user sessions list reverse sorted by last
                # used timestamp.
                for dict_key in sorted(user_sessions, reverse=False):
                    session_x = user_sessions[dict_key]
                    if not session_x.last_used:
                        continue
                    session_age = time.time() - session_x.last_used
                    if session_age < self.auth_group.relogin_timeout:
                        continue
                    self.logger.debug("Deleting session '%s' based on "
                                "max_sessions/relogin_timeout "
                                "configured for this group."
                                % session_x.name)
                    session_x.delete(force=True, recursive=True,
                                    verify_acls=False)
                    session_list.remove(session_x)
                    found_obsolete_session = True
                    break
                if not found_obsolete_session:
                    if (len(session_list) + 1) >= self.auth_group.max_sessions:
                        self.logger.debug("Max sessions reached for this accessgroup "
                                    "and no outdated session found.")
            else:
                self.logger.debug("Max sessions reached for this accessgroup and "
                            "no relogin allowed.")

        if self.auth_failed:
            # If relogin is disabled or we havent found a obsolete
            # session auth has failed.
            self.auth_message = "AUTH_FAILED_MAX_SESSIONS"

    def create_user_sessions(self):
        """ Create sessions. """
        # If session creation is disabled we are done.
        if not self.create_sessions:
            return

        # Cannot create sessions for script OTP token when doing MSCHAP auth.
        if self.verify_token.pass_type == "script_otp":
            if self.auth_type == "mschap":
                self.logger.warning("Cannot create sessions for MSCHAP "
                                "request with token/password type: %s"
                                % self.verify_token.pass_type)
                return

        # Check if there is a session master for auth_group configured.
        session_master = self.auth_group.parents(recursive=True,
                                                sessions=True,
                                                session_master=True,
                                                return_type="instance")

        # If we found the session master and it has sessions enabled it must be
        # used as session_start_group.
        if session_master and session_master.sessions_enabled:
            self.logger.debug("Found a valid session master: '%s'."
                        % session_master)
            self.session_start_group = session_master.name
        else:
            # If there is no session master use accessgroup from request as
            # session start group.
            self.session_start_group = self.access_group

        if not self.auth_failed:
            if self.verify_token.pass_type == "static":
                session_logout_pass = slp.gen(self.new_session_uuid)
            else:
                # Make sure we have a valid password hash.
                if not self.realm_login:
                    self.gen_pass_hash()
                session_logout_pass = slp.gen(self.one_iter_hash)
            # Create parent session instance.
            client_uuid = None
            if self.auth_client:
                client_uuid = self.auth_client.uuid
            if self.auth_host:
                client_uuid = self.auth_host.uuid
            session = Session(self.auth_type, self.user.name,
                            pass_hash=self.password_hash,
                            pass_hash_params=self.pass_hash_params,
                            slp=session_logout_pass,
                            token=self.auth_token.uuid,
                            uuid=self.new_session_uuid,
                            access_group=self.session_start_group,
                            client=client_uuid,
                            client_ip=self.client_ip)
            # Invoke method to create child sessions which also creates
            # parent session so we need no session.add() here. Child
            # sessions are always created regardless if sessions are
            # enabled for each child.
            add_status = session.create_child_sessions(offline_data_key=self.offline_data_key)
            if add_status:
                # Call exists() to fill in all session variables.
                session.exists()
                # Set log_session_id to new created session_id with info tag
                # that its new.
                self.log_session_id = "new:%s" % session.session_id
                # Add session as child of REALM session if this is a SOTP
                # request.
                if self.found_sotp:
                   self.logger.info("Adding session '%s' as child session of '%s."
                                % (session.name, self.auth_session.name))
                   self.auth_session.add_child_session(session.uuid)

            # Set session created for this request.
            self.auth_session = session
            self.request_cacheable = True

    def reset_user_fail_counter(self):
        """ Reset users failed login counter. """
        # Get fail count for this user/group.
        fail_count = self.user.failcount(self.access_group)
        if fail_count == 0:
            return
        self.logger.info("Resetting login fail count for '%s/%s' from '%s' to 0."
                    % (self.user.name, self.access_group, fail_count))
        try:
            self.user.unblock(self.access_group,
                            verify_acls=False,
                            run_policies=False)
        except Exception as e:
            self.logger.critical("Error resetting login fail count: %s" % e)
            config.raise_exception()

    def build_log_message(self):
        """ Build log message. """
        # Set variables to build final log entry.
        log_username = None
        log_auth_type = None
        log_token_name = None
        log_access_group = None
        log_client = None
        log_client_ip = None
        log_client = None
        log_client_ip = None
        log_session_id = None
        if self.user:
            log_username = self.user.name
        if self.auth_type:
            log_auth_type = self.auth_type
        if self.auth_token:
            log_token_name = self.auth_token.name
        if self.auth_group:
            log_access_group = self.auth_group.name
        if self.client:
            log_client = self.client
        if self.client_ip:
            log_client_ip = self.client_ip
        if self.host:
            log_client = self.host
        if self.host_ip:
            log_client_ip = self.host_ip
        if self.auth_session:
            log_session_id = self.auth_session.session_id

        # Final success message.
        log_message = ("%s: user=%s token=%s access_group=%s client=%s "
                        "client_ip=%s auth_type=%s session=%s"
                        % (self.auth_message,
                        log_username,
                        log_token_name,
                        log_access_group,
                        log_client,
                        log_client_ip,
                        log_auth_type,
                        log_session_id))
        return log_message

    def authenticate(self, user, ecdh_curve=None, auth_type="clear-text",
        auth_mode="auto", realm_login=False, realm_logout=False,
        login_interface=None, reneg=None, reneg_salt=None, rsp_hash_type=None,
        unlock=False, password=None, challenge=None, response=None,
        smartcard_data=None, client=None, client_ip=None, access_group=None,
        user_token=None, count_fails=None, host_type=None, host=None,
        host_ip=None, replace_sessions=None, require_token_types=None,
        require_pass_types=None, redirect_challenge=None,
        allow_sotp_reuse=False, redirect_response=None, gen_jwt=None,
        jwt_challenge=None, rsp_ecdh_client_pub=None, verify_host=True,
        client_offline_enc_type=None):
        """
        Try to authenticate user:
            auth_type can be clear-text, mschap or ssh:
                - clear-text: you have to pass a cleartext password:
                    password=mypass
                - mschap: you have to pass a MSCHAP challenge and response in hex form:
                    challenge=977614e28d995326
                    response=1327dd6f5a1b45a9198074f26114f52ae9af30130c7fe77e)
                - ssh: ssh public/private key challenge/response authentication
            auth_mode can be one of the following:
                - static: try to verify against all static password tokens
                - otp: try to verify against all OTP tokens
                - ssh: verify ssh challenge/response with optional OTP
                - auto: determine auth mode on token type
            realm_login can be True or False
                - if set to True a RSP (realm session password) and optionally
                  offline tokens are returned on success.
            realm_logout can be True or False and indicates a realm logout request
            client must be a valid client name
            client_ip must be an client IP
                - if client name is set and client has an one or more IPs the
                  request IP must match to one of those addresses.
                - if client name is not set we try to get the client name via
                  the client IP of the request. in this case only one client
                  must have this IP assigned.
            access_group must be a valid accessgroup name
                - the accessgroup is used to control access
                  and get session parameters.
            user_token must be a valid token name
                - if specified authentication is only tried with the given token
            count_fails can be True or False
                - specifies if a failed authentication should count up failcount
                  of user
            require_token_types must be a list of allowed token types for this request
            require_pass_types must be a list of allowed token types for this request
            gen_jwt can be True of False
                - specifies if we should generated a JWT on successful auth.
            jwt_challenge must be a string
                - optional challenge that will be added to the JWT payload
        """
        string_vars = {
                'password'                  : password,
                'challenge'                 : challenge,
                'response'                  : response,
                'auth_type'                 : auth_type,
                'auth_mode'                 : auth_mode,
                'access_group'              : access_group,
                'client'                    : client,
                'client_ip'                 : client_ip,
                'host'                      : host,
                'host_ip'                   : host_ip,
                'host_type'                 : host_type,
                'user_token'                : user_token,
                'rsp_ecdh_client_pub'       : rsp_ecdh_client_pub,
                'client_offline_enc_type'   : client_offline_enc_type,
                }

        # Make sure some variables are strings (e.g. a numeric OTP)
        for x in string_vars:
            val = string_vars[x]
            if val != None and not isinstance(val, bool):
                string_vars[x] = str(val)

        # Set request variables.
        self.user = user
        self.password = string_vars['password']
        self.user_token = string_vars['user_token']
        self.challenge = string_vars['challenge']
        self.response = string_vars['response']
        self.auth_type = string_vars['auth_type']
        self.auth_mode = string_vars['auth_mode']
        self.smartcard_data = smartcard_data
        self.realm_login = realm_login
        self.realm_logout = realm_logout
        self.unlock = unlock
        self.temp_password_auth = False
        self.login_interface = login_interface
        self.access_group = string_vars['access_group']
        self.client = string_vars['client']
        self.client_ip = string_vars['client_ip']
        self.host = string_vars['host']
        self.host_ip = string_vars['host_ip']
        self.host_type = string_vars['host_type']
        self.verify_host = verify_host
        self.replace_sessions = replace_sessions
        self.count_fails = count_fails
        self.redirect_challenge = redirect_challenge
        self.redirect_response = redirect_response
        self.jwt = None
        self.client_offline_enc_type = string_vars['client_offline_enc_type']
        self.jwt_challenge = jwt_challenge
        self.request_cacheable = False
        if gen_jwt is None:
            if self.jwt_challenge:
                self.gen_jwt = True
            else:
                self.gen_jwt = None
        else:
            self.gen_jwt = gen_jwt

	    # Check if we have to log authentication data for this request.
        if isinstance(config.log_auth_data, bool):
            self.log_auth_data = config.log_auth_data
        elif isinstance(config.log_auth_data, list):
            if self.user.name in config.log_auth_data:
                self.log_auth_data = True
            else:
                self.log_auth_data = False

        # Will be set to True if authentication was successful.
        self.auth_status = False
        # Indicates that authentication has failed and there is no need to try
        # again (e.g. with other token).
        self.auth_failed = False
        # Will hold auth message. default is failed.
        self.auth_message = "AUTH_FAILED"
        # Will hold the access_group (instance) for this request.
        self.auth_group = None
        # Will hold the session (instance) for this request.
        self.auth_session = None
        # Will hold the session UUID assigned to a new session.
        self.new_session_uuid = None
        # Will hold encryption key for secure handling of offline
        # token data (e.g. used OTPs)
        self.offline_data_key = None
        # Will hold the token (instance) that authenticated the user.
        self.auth_token = None
        # Will hold the token that is used to verify passwords etc. For linked
        # tokens this is the destination token the "link" token points to. For
        # normal tokens this will be set to auth_token.
        self.verify_token = None
        # Will hold the client (instance) of this request.
        self.auth_client = None
        # Will hold the peer host/node (instance) of this request.
        self.auth_host = None
        # Will hold all allowed token types for this request.
        self.require_token_types = require_token_types
        # Will hold all allowed pass types for this request.
        self.require_pass_types = require_pass_types
        # Users default token to be verified first.
        self.user_default_token = None
        # Will hold a list of user static-password tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_static = []
        # Will hold a list of user OTP tokens that could be used to authenticate
        # this request.
        self.valid_user_tokens_otp = []
        # Will hold a list of user script_static tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_script_static = []
        # Will hold a list of user script_otp tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_script_otp = []
        # Will hold a list of user otp_push tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_otp_push = []
        # Will hold a list of user ssh tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_ssh = []
        # Will hold a list of user smartcard tokens that could be used to
        # authenticate this request.
        self.valid_user_tokens_smartcard = []
        # Will to hold realm session password.
        self.rsp = None
        # Indicates that the password is a SOTP.
        self.found_sotp = False
        # Indicates that this is a session renegotiation request.
        self.session_reneg = reneg
        self.reneg_type = None
        self.reneg_salt = reneg_salt
        # Will hold password hash.
        self.password_hash = None
        self.pass_hash_params = None
        # Will hold NT hash of the request password.
        self.nt_hash = None
        # Will hold a one iteration hash of the password which is used for
        # REALM sessions and to check for already used SOTP.
        self.one_iter_hash = None
        # Will hold NT Key (if this is an MSCHAP request)
        self.nt_key = None
        # Will hold the SOTP.
        self.auth_sotp = None
        # Will hold the SLP.
        self.auth_slp = None
        # Will hold the SRP.
        self.auth_srp = None
        # Will hold all checked password hashes. (e.g checked for already used SOTP)
        self.checked_hashes = []
        # Indicates if we should verify sessions.
        self.verify_sessions = True
        # Indicates if we should create sessions.
        self.create_sessions = True
        # Will hold the accessgroup that will be used as start point on session
        # creation.
        self.session_start_group = None
        # Will be set to True if this is a session logout request.
        self.session_logout = False
        # Will be set to True if this is a session refresh request.
        self.session_refresh = False
        # Supported RSP hash types.
        self.rsp_hash_types = ['PBKDF2']
        # Allow reuse of SOTPs.
        self.allow_sotp_reuse = allow_sotp_reuse
        if rsp_hash_type:
            if rsp_hash_type not in self.rsp_hash_types:
                msg = "Unsupported RSP hash type: %s" % rsp_hash_type
                raise OTPmeException(msg)
        self.rsp_hash_type = rsp_hash_type

        if self.realm_login:
            if self.access_group != config.realm_access_group:
                msg = ("Realm login requests must have "
                        "accessgroup 'REALM' set.")
                raise OTPmeException(msg)
            if not self.host_type or not self.host or not self.host_ip:
                msg = ("Realm login requests must contain 'host_type', "
                                "'host' and 'host_ip'.")
                raise OTPmeException(msg)
            self.auth_message = "REALM_LOGIN_FAILED"
            self.verify_sessions = False

        if self.realm_logout:
            self.count_fails = False
            if self.access_group != config.realm_access_group:
                msg = ("Realm logout requests must have accessgroup "
                        "'REALM' set.")
                raise OTPmeException(msg)
            if not self.host or not self.host_ip:
                msg = ("Realm logout requests must contain "
                        "'host_type', 'host' and 'host_ip'.")
                raise OTPmeException(msg)
            self.auth_message = "REALM_LOGOUT_FAILED"

        # We do not check policies on screen unlock (e.g. to allow screen
        # unlock while login is restricted by policy).
        self.check_policies = True
        if self.unlock:
            self.logger.info("This is a screen unlock request.")
            self.check_policies = False
        # We do not check policies on realm logout.
        if self.realm_logout:
            self.check_policies = False

        if self.host_type:
            if self.host_type != "node" and self.host_type != "host":
                msg = (_("Unknown host type: %s" % self.host_type))
                raise OTPmeException(msg)

        if self.auth_type == "mschap":
            self.logger.debug("Processing MSCHAP authentication request.")
            if self.challenge:
                if len(self.challenge) != 16:
                    self.auth_message = "AUTH_INVALID_MSCHAP_CHALLENGE"
                    self.auth_failed = True
            else:
                self.auth_message = "AUTH_MISSING_MSCHAP_CHALLENGE"
                self.auth_failed = True

            if self.response:
                if len(self.response) != 48:
                    self.auth_message = "AUTH_INVALID_MSCHAP_RESPONSE"
                    self.auth_failed = True
            else:
                self.auth_message = "AUTH_MISSING_MSCHAP_RESPONSE"
                self.auth_failed = True

        elif self.auth_type == "clear-text":
            self.logger.debug("Processing clear-text authentication request.")
            if not self.password:
                self.auth_message = "AUTH_MISSING_PASS"
                self.auth_failed = True

        elif self.auth_type == "ssh":
            self.logger.debug("Processing SSH authentication request.")
            # When doing SSH authentication we cannot verify sessions.
            self.verify_sessions = False
            # We can only create sessions when using SSH tokens to do realm
            # logins.
            self.create_sessions = False

            if not self.challenge:
                self.auth_message = "AUTH_MISSING_SSH_CHALLENGE"
                self.auth_failed = True

            if not self.response:
                self.auth_message = "AUTH_MISSING_SSH_RESPONSE"
                self.auth_failed = True

        elif self.auth_type == "smartcard":
            self.logger.debug("Processing smartcard authentication request.")
            # When doing smartcard authentication we cannot verify sessions.
            self.verify_sessions = False
            # We can only create sessions when using smartcard tokens to do realm
            # logins.
            self.create_sessions = False
            if not self.smartcard_data:
                self.auth_message = "AUTH_MISSING_SMARTCARD_DATA"
                self.auth_failed = True

        elif self.auth_type == "jwt":
            # When doing JWT authentication we cannot verify sessions.
            self.verify_sessions = False
            if not self.redirect_challenge:
                self.auth_message = "AUTH_MISSING_REDIRECT_CHALLENGE"
                self.auth_failed = True

            if not self.redirect_response:
                self.auth_message = "AUTH_MISSING_REDIRECT_RESPONSE"
                self.auth_failed = True

        else:
            self.auth_message = "AUTH_INVALID_AUTH_TYPE"
            self.auth_failed = True

        if not self.auth_mode in self.valid_auth_modes:
            self.logger.warning("Received invalid auth mode: %s"
                            % self.auth_mode)
            self.auth_message = "AUTH_INVALID_AUTH_MODE"
            self.auth_failed = True

        # Make sure authentication of our site is not disabled.
        if not self.auth_failed:
            if not self.user.is_admin() and not self.realm_logout:
                my_site = backend.get_object(object_type="site",
                                            uuid=config.site_uuid)
                if not my_site.auth_enabled:
                    msg = ("Authentication disabled for this site: %s/%s"
                            % (my_site.realm, my_site.name))
                    self.logger.debug(msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "AUTH_DISABLED"

        # Check if we got a valid client/host.
        self.get_client()
        # Check user status.
        self.check_user()
        # Handle accessgroup.
        self.check_accessgroup()

        # FIXME: do we need a better solution for this? do we want to allow sessions in REALM accessgroup other client types than hosts/nodes??
        # Do not create sessions for REALM group if this is not a realm_login
        # requests. This is needed to allow e.g. unlocking of a KDE session
        # (pam_otpme) without adding a new session.
        if self.access_group == config.realm_access_group \
        and not (self.realm_login or self.realm_logout):
            self.create_sessions = False

        if not self.auth_failed and self.auth_status is False:
            # Generate hash to be used for REALM sessions and to check for used
            # SOTP.
            if self.password and not self.one_iter_hash:
                self.one_iter_hash = self.get_one_iter_hash(self.password)

            # Check if the request contains an already used SOTP.
            if not self.auth_failed and not self.auth_status:
                if self.access_group == config.realm_access_group:
                    if not self.session_logout and not self.realm_logout:
                        if not self.allow_sotp_reuse:
                            self.check_used()

        # Try to verify request against existing session if enabled.
        if not self.auth_failed and self.verify_sessions:
            # Verify sessions.
            self.verify_user_sessions()

        # Handle JWT (cross-site) authentication.
        if self.auth_type == "jwt":
            # No need to count failed logins for JWT requests.
            self.count_fails = False
            self.verify_jwt()

        if not self.realm_logout:
            if not self.auth_failed and self.auth_status is False:
                # Get user tokens that are valid for this request.
                self.get_user_tokens()
                # Create session UUID for a new session that may be
                # added. This is needed before verifying user tokens
                # because the session UUID will be added to any used
                # OTP/token counter object by the token.verify() method.
                # We need this to handle offline token data sync in a
                # secure manner (see offline_data_key below).
                self.new_session_uuid = stuff.gen_uuid()

        if self.client_offline_enc_type:
            # Generate key used to encrypt used OTPs/token counters
            # on client side when doing offline logins. This key is
            # also added to the server session and used by syncd to
            # en-/decrypt objects when syncing with client hosts.
            try:
                #enc_mod = encryption.get_module(self.client_offline_enc_type)
                enc_mod = config.get_encryption_module(self.client_offline_enc_type)
            except Exception as e:
                msg = "Unable to load offline encryption: %s" % e
                raise OTPmeException(msg)
            try:
                self.offline_data_key = enc_mod.gen_key()
            except Exception as e:
                msg = "Failed to generate offline encryption key: %s" % e
                raise OTPmeException(msg)

        # Verify default token first.
        if not self.auth_failed and self.auth_status is False:
            if self.user_default_token:
                self.logger.debug("Verifying user default token...")
                self.verify_user_tokens(tokens=[self.user_default_token])

        # Verify OTP push tokens second.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_otp_push:
                self.logger.debug("Verifying otp_push tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_otp_push)

        # Verify OTP tokens
        # FIXME: Currently we need to check OTP tokens first because they may
        #        be used as a second factor token (e.g. with password tokens)
        #        and when verifying the OTP will be added to the list of
        #        already used OTPs to prevent brute force attacks against the
        #        static password (e.g .with a stolen OTP) and thus the second
        #        verification (not as second factor token) will fail.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_otp:
                self.logger.debug("Verifying OTP tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_otp)

        # Verify "password" tokens before U2F tokens because they may use a U2F
        # token as second factor token.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_static:
                self.logger.debug("Verifying static password tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_static)

        # Verify SSH tokens before U2F tokens because they may use a U2F token
        # as second factor token.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_ssh:
                self.logger.debug("Verifying SSH tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_ssh)

        # Verify smartcard tokens.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_smartcard:
                self.logger.debug("Verifying smartcard tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_smartcard)

        # Verify script_static tokens.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_script_static:
                self.logger.debug("Verifying script_static tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_script_static)

        # Verify script_otp tokens.
        if not self.auth_failed and self.auth_status is False:
            if self.valid_user_tokens_script_otp:
                self.logger.debug("Verifying script_otp tokens...")
                self.verify_user_tokens(tokens=self.valid_user_tokens_script_otp)

        # Check policies.
        if not self.auth_failed:
            authorize_token = False
            if self.check_policies and self.auth_token:
                if self.auth_host:
                    if self.auth_host.site == config.site:
                        authorize_token = True
                if self.auth_client:
                    authorize_token = True
            if authorize_token:
                try:
                    # Check token policies.
                    self.auth_token.run_policies("authorize",
                                            token=self.auth_token)
                    # Check user policies.
                    self.user.run_policies("authorize",
                                        token=self.auth_token)
                    # Check accessgroup policies.
                    self.auth_group.run_policies("authorize",
                                            token=self.auth_token)
                    # Check host/node/client role/group policies.
                    if self.auth_host:
                        self.auth_host.authorize_token(self.auth_token,
                                                    self.login_interface)
                    if self.auth_client:
                        self.auth_client.authorize_token(self.auth_token)
                except PolicyException as e:
                    msg = str(e)
                    self.logger.warning(msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "AUTH_DENIED_BY_POLICY"
                except LoginsLimited as e:
                    msg = str(e)
                    self.logger.warning(msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "LOGINS_LIMITED"
                except Exception as e:
                    config.raise_exception()
                    msg = "Internal server error"
                    log_msg = "%s: %s" % (msg, e)
                    self.logger.critical(log_msg)
                    self.auth_failed = True
                    self.count_fails = False
                    self.auth_message = "AUTH_INTERNAL_SERVER_ERROR"

        # Log request auth data if enabled.
        if self.log_auth_data and (config.loglevel == "DEBUG" or config.debug_enabled):
            self.logger.warning("Logging of sensitive authentication data is "
                        "enabled. You should disable LOG_AUTH_DATA in "
                        "production environments!!!")
            self.logger.debug("AUTHENTICATION DATA OF REQUEST:")
            self.logger.debug("AUTH_TYPE:        %s" % self.auth_type)
            self.logger.debug("USERNAME:         %s" % self.user.name)
            if self.password:
                self.logger.debug("PASSWORD:         %s" % self.password)
            if self.password_hash:
                self.logger.debug("PASSWORD_HASH:    %s" % self.password_hash)
            if self.auth_sotp:
                self.logger.debug("SOTP:             %s" % self.auth_sotp)
            if self.auth_srp:
                self.logger.debug("SRP:              %s" % self.auth_srp)
            if self.auth_slp:
                self.logger.debug("SLP:              %s" % self.auth_slp)
            if self.challenge:
                self.logger.debug("CHALLENGE:        %s" % self.challenge)
            if self.response:
                self.logger.debug("RESPONSE:         %s" % self.response)
            if self.nt_key:
                self.logger.debug("NT_KEY:           %s" % self.nt_key)

        # If max_sessions is set for this group we have to check if we need to
        # remove other sessions.
        if not self.auth_failed:
            if self.auth_group.max_sessions > 0:
                if self.create_sessions:
                    if not self.realm_logout:
                        self.check_max_sessions()

        # If authentication was successful.
        ecdh_server_pub_pem = None
        if self.auth_status is True and self.auth_failed is False:
            # Handle realm logins.
            if self.realm_login:
                if not rsp_ecdh_client_pub:
                    msg = (_("Authentication request misses DH public key."))
                    raise AuthFailed(msg)
                # Session creation must be enabled for realm logins.
                self.create_sessions = True
                self.logger.debug("Generating RSP...")
                # Generate realm session password.
                ecdh_key = ECKey()
                ecdh_key.gen_key(curve=ecdh_curve)
                ecdh_server_pub_pem = ecdh_key.export_public_key()
                # Load ECDH client public key.
                ecdh_client_pub_pem = ecdh_key.load_public_key(rsp_ecdh_client_pub)
                dh_secret = ecdh_key.dhexchange(ecdh_client_pub_pem)
                self.rsp = sotp.derive_rsp(secret=dh_secret,
                                        hash_type=self.rsp_hash_type,
                                        salt=ecdh_server_pub_pem)
                rsp_hash = self.get_one_iter_hash(self.rsp)
                # Set password hash to realm session password hash.
                self.password_hash = rsp_hash

            # Build JWT.
            if self.gen_jwt:
                reason = "REALM_AUTH"
                if self.realm_login:
                    reason = "REALM_LOGIN"
                if self.session_reneg:
                    reason = "SESSION_RENEG"
                if self.session_refresh:
                    reason = "SESSION_REFRESH"
                jwt_data = {
                        'realm'             : config.realm,
                        'site'              : config.site,
                        'reason'            : reason,
                        'message'           : self.auth_message,
                        'challenge'         : self.jwt_challenge,
                        'login_time'        : time.time(),
                        'login_token'       : self.auth_token.uuid,
                        'accessgroup'       : self.access_group,
                        }
                self.jwt = jwt.encode(payload=jwt_data,
                                    key=self.site_key,
                                    algorithm='RS256')

            # On session refresh/reneg we are done here.
            if self.session_reneg or self.session_refresh:
                auth_reply = {
                        'status'            : True,
                        'token'             : self.auth_token,
                        'jwt'               : self.jwt,
                        'message'           : self.auth_message,
                        }
                # Log final success message.
                ok_message = self.build_log_message()
                self.logger.info(ok_message)
                return auth_reply

            # Build auth reply.
            auth_reply = {
                'status'            : True,
                'login_time'        : time.time(),
                'message'           : self.auth_message,
                'token'             : self.auth_token,
                'jwt'               : self.jwt,
                'ecdh_server_pub'   : ecdh_server_pub_pem,
                'timeout'           : self.auth_group.session_timeout,
                'unused_timeout'    : self.auth_group.unused_session_timeout,
                'temp_pass_auth'    : self.temp_password_auth,
                }

            if self.auth_type == "mschap":
                auth_reply['password_hash'] = self.password_hash
                auth_reply['nt_key'] = self.nt_key


            # Handle session creation.
            if self.replace_sessions:
                for _slp in self.replace_sessions:
                    self.logout_user_session(_slp)
            self.create_user_sessions()

            if self.auth_session:
                auth_reply['session'] = self.auth_session.uuid
                auth_reply['offline_data_key'] = self.offline_data_key

            # Reset failed login counter for this user/group.
            self.reset_user_fail_counter()

            # Get users login token.
            login_token_uuid = None
            if self.auth_token:
                login_token_uuid = self.auth_token.uuid
            auth_reply['login_token_uuid'] = login_token_uuid

            if self.realm_login:
                # Get users login script.
                login_script = None
                login_script_uuid = None
                login_script_path = None
                login_script_opts = None
                login_script_signs = None
                if self.user.login_script and self.user.login_script_enabled:
                    x = backend.get_object(object_type="script",
                                    uuid=self.user.login_script)
                    if x:
                        login_script = decode(x.script, "base64")
                        login_script_uuid = x.uuid
                        login_script_path = x.rel_path
                        login_script_opts = self.user.login_script_options
                        login_script_signs = x.signatures.copy()

                auth_reply['login_script'] = login_script
                auth_reply['login_script_uuid'] = login_script_uuid
                auth_reply['login_script_path'] = login_script_path
                auth_reply['login_script_opts'] = login_script_opts
                auth_reply['login_script_signs'] = login_script_signs

                # Get users key script.
                key_script = None
                key_script_uuid = None
                key_script_path = None
                key_script_opts = None
                key_script_signs = None
                if self.user.key_script:
                    x = backend.get_object(object_type="script",
                                        uuid=self.user.key_script)
                    if x:
                        key_script = decode(x.script, "base64")
                        key_script_uuid = x.uuid
                        key_script_path = x.rel_path
                        key_script_opts = self.user.key_script_options.copy()
                        key_script_signs = x.signatures.copy()

                auth_reply['key_script'] = key_script
                auth_reply['key_script_uuid'] = key_script_uuid
                auth_reply['key_script_path'] = key_script_path
                auth_reply['key_script_opts'] = key_script_opts
                auth_reply['key_script_signs'] = key_script_signs
                # Get shares to mount on client.
                if self.user.auto_mount:
                    search_attrs = {
                                    'token' : {'value':self.auth_token.uuid},
                                }
                    user_shares = backend.search(object_type="share",
                                                attributes=search_attrs,
                                                return_type="instance")
                    token_roles = self.auth_token.get_roles(return_type="uuid", recursive=True)
                    if token_roles:
                        search_attrs = {
                                        'role' : {'values':token_roles},
                                    }
                        user_shares += backend.search(object_type="share",
                                                    attributes=search_attrs,
                                                    return_type="instance")
                    shares = {}
                    for share in user_shares:
                        if not share.enabled:
                            continue
                        share_nodes = share.get_nodes(include_pools=True,
                                                    return_type="instance")
                        if not share_nodes:
                            share_nodes = backend.search(object_type="node",
                                                        attribute="uuid",
                                                        value="*",
                                                        realm=share.realm,
                                                        site=share.site,
                                                        return_type="instance")
                        if share_nodes:
                            node_fqdns = []
                            for node in share_nodes:
                                node_fqdns.append(node.fqdn)
                            share_id = "%s/%s" % (share.site, share.name)
                            shares[share_id] = {}
                            shares[share_id]['name'] = share.name
                            shares[share_id]['site'] = share.site
                            shares[share_id]['nodes'] = node_fqdns
                            shares[share_id]['encrypted'] = share.encrypted
                    auth_reply['shares'] = shares

            # Get SSH private key from token.
            ssh_private_key = None
            if self.verify_token.token_type == "ssh":
                if self.verify_token._ssh_private_key:
                    self.logger.debug("Got SSH private key from token: %s"
                                % self.verify_token.rel_path)
                    ssh_private_key = self.verify_token._ssh_private_key
            auth_reply['ssh_private_key'] = ssh_private_key
            auth_reply['request_cacheable'] = self.request_cacheable
            if self.auth_session:
                auth_reply['slp'] = self.auth_session.slp

            if self.access_group == config.sso_access_group:
                auth_reply['session_hash'] = self.auth_session.pass_hash

            # Update last used timestamps for user and token.
            self.user.update_last_used_time()
            self.auth_token.update_last_used_time()

            if self.realm_login:
                self.logger.debug("Realm login successful with token '%s'."
                            % self.auth_token.name)

            # Log final success message.
            ok_message = self.build_log_message()
            self.logger.info(ok_message)

            # Finally return.
            return auth_reply

        if self.realm_logout:
            # Update last used timestamps for user and token.
            self.user.update_last_used_time()
            # Token may not exist anymore.
            if self.auth_token:
                self.auth_token.update_last_used_time()

            # Log final logout message.
            logout_message = self.build_log_message()
            self.error_log_method(logout_message)

            # Logout reply.
            auth_reply = {
                    'status'        : False,
                    'login_time'    : time.time(),
                    }
            if self.realm_logout:
                auth_reply['message'] = self.auth_message
            else:
                auth_reply['message'] = "AUTH_FAILED"
            # Finally return.
            return auth_reply

        # We want a failed auth request to be counted as failed login, but only
        # if self.count_fails was not modified before.
        if self.count_fails is None:
            self.count_fails = True

        # If we reached this point auth has failed and we can count failed login
        # if enabled and we got an accessgroup and a password hash.
        if self.count_fails:
            if self.auth_group:
                if self.auth_group.max_fail == 0:
                    self.logger.warning("Will not count failed logins because of"
                                        "max_fail=0.")
                self.count_fails = False
            else:
                self.logger.critical("Cannot count failed login without "
                                    "accessgroup.")
                self.count_fails = False
            if not self.one_iter_hash:
                self.logger.debug("Cannot count failed login without "
                                    "password hash.")
                self.count_fails = False

        # Do not lock out admin user.
        if self.user and self.user.name == config.admin_user_name:
            self.count_fails = False

        if self.count_fails:
            # Check if this is an clear-text request as we cannot count logon
            # failures per password for MSCHAP sessions (no password hash
            # available)
            if self.auth_type == "clear-text":
                # We only count each failed password once for clear-text
                # requests which makes sense IMHO (e.g. a wrong configured mail
                # client may try very often with the same wrong password. This
                # should not lock a user/access_group)
                self.user.count_fail(self.one_iter_hash,
                                    access_group=self.access_group)
            elif self.auth_type == "mschap":
                # For MSCHAP requests there is no password_hash available
                # because only challenge and response are transmitted so
                # we count logon failures per response. In most cases the
                # response will be different for each request even if the
                # password is the same because the challenge changes. this
                # makes it fairly impossible to implement this feature for
                # MSCHAP requests. :(
                self.user.count_fail(self.response,
                                    access_group=self.access_group)
            elif self.auth_type == "ssh":
                # For SSH logins there may be an OTP from the second factor
                # token which could be used to count failed logins.
                self.user.count_fail(self.one_iter_hash,
                                    access_group=self.access_group)
        # Log final failed message.
        failed_message = self.build_log_message()
        self.error_log_method(failed_message)

        # Authentication failed!!
        auth_reply = {
                'status'        : False,
                'login_time'    : time.time(),
                }
        if self.realm_logout:
            auth_reply['message'] = self.auth_message
        else:
            auth_reply['message'] = "AUTH_FAILED"
        # Finally return.
        return auth_reply

        # This point should never be reached.
        msg = ("WARNING: You may have hit a BUG of "
            "AuthHandler().authenticate(). Authentication failed.")
        self.logger.critical(msg)
        raise Exception(msg)
