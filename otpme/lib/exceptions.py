# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

class OTPmeException(Exception):
    pass

class PermissionDenied(OTPmeException):
    pass

class OverlapDetected(OTPmeException):
    pass

class LoopDetected(OTPmeException):
    pass

class JobNotStoppable(OTPmeException):
    pass

class AlreadyExists(OTPmeException):
    pass

class AlreadyRunning(OTPmeException):
    pass

class AlreadyMaster(OTPmeException):
    pass

class NotConfigured(OTPmeException):
    pass

class NotRunning(OTPmeException):
    pass

class TimeoutReached(OTPmeException):
    pass

class SearchException(OTPmeException):
    pass

class SizeLimitExceeded(OTPmeException):
    pass

class ExitOnSignal(OTPmeException):
    pass

class InvalidOID(OTPmeException):
    pass

class UnknownOID(OTPmeException):
    pass

class UnknownUUID(OTPmeException):
    pass

class UnknownUser(OTPmeException):
    pass

class UnknownObject(OTPmeException):
    pass

class UnknownTemplate(OTPmeException):
    pass

class UnknownClass(OTPmeException):
    pass

class UnknownCommand(OTPmeException):
    pass

class UnknownLoginSession(OTPmeException):
    pass

class UnknownObjectType(OTPmeException):
    pass

class AlreadyLoggedIn(OTPmeException):
    pass

class NotLoggedIn(OTPmeException):
    pass

class AuthFailed(OTPmeException):
    pass

class RenegFailed(OTPmeException):
    pass

class RefreshFailed(OTPmeException):
    pass

class LogoutFailed(OTPmeException):
    pass

class AddressAlreadyInUse(OTPmeException):
    pass

class AddressAlreadyAssigned(OTPmeException):
    pass

class AlreadyRegistered(OTPmeException):
    pass

class NoTagsMatch(OTPmeException):
    pass

class InvalidTag(OTPmeException):
    pass

class InvalidType(OTPmeException):
    pass

class InvalidPublicKey(OTPmeException):
    pass

class NoSignature(OTPmeException):
    pass

class FaultySignature(OTPmeException):
    pass

class SignatureRevoked(OTPmeException):
    pass

class CertAlreadyRevoked(OTPmeException):
    pass

class CertVerifyFailed(OTPmeException):
    pass

class EmptyTransaction(OTPmeException):
    pass

class NoMatch(OTPmeException):
    pass

class AlreadyConnected(OTPmeException):
    pass

class ConnectionRedirect(OTPmeException):
    pass

class ConnectionTimeout(OTPmeException):
    pass

class ConnectionQuit(OTPmeException):
    pass

class ServerQuit(ConnectionQuit):
    pass

class ClientQuit(ConnectionQuit):
    pass

class DaemonQuit(OTPmeException):
    pass

class DaemonReload(OTPmeException):
    pass

class DaemonRestart(OTPmeException):
    pass

class CloseSocket(OTPmeException):
    pass

class QueueClosed(OTPmeException):
    pass

class NotFound(OTPmeException):
    pass

class VerificationFailed(OTPmeException):
    pass

class NoOfflineSessionFound(OTPmeException):
    pass

class HostDisabled(OTPmeException):
    pass

class SyncDisabled(OTPmeException):
    pass

class EncryptException(OTPmeException):
    pass

class DecryptException(OTPmeException):
    pass

class UnknownMasterNode(OTPmeException):
    pass

class MandatoryAttribute(OTPmeException):
    pass

class BackendUnavailable(OTPmeException):
    pass

class ObjectDeleted(OTPmeException):
    pass

class ObjectLocked(OTPmeException):
    pass

class LockWaitAbort(OTPmeException):
    pass

class LockWaitTimeout(OTPmeException):
    pass

class UnknownLock(OTPmeException):
    pass

class OTPmeTypeError(OTPmeException):
    pass

class PolicyException(OTPmeException):
    pass

class NotRegistered(OTPmeException):
    pass

class UnsupportedHashType(OTPmeException):
    pass

class UnsupportedEncodingType(OTPmeException):
    pass

class UnsupportedEncryptionType(OTPmeException):
    pass

class UnsupportedCompressionType(OTPmeException):
    pass

class LoginsLimited(OTPmeException):
    pass

class SiteNotTrusted(OTPmeException):
    pass

class NoUnitFound(OTPmeException):
    pass

class ProcessingFailed(OTPmeException):
    pass

class ShowHelp(OTPmeException):
    pass

class OTPmeJobException(OTPmeException):
    pass

class MasterNodeElectionFailed(OTPmeException):
    pass

class LoginInterfaceException(PolicyException):
    pass
