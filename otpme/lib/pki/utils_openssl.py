# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pytz
import datetime

# Import openssl from within functions to prevent startup delay:
#   https://github.com/pyca/pyopenssl/issues/137
#import OpenSSL
OpenSSL = None

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

logger = config.logger

#with open("ca-key.pem", "r") as fh:
#    ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, fh.read())
#with open("ca-cert.pem", "r") as fh:
#    ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fh.read())

def check_pyopenssl_version():
    """ Check for slow pyopenssl version and print warning. """
    import OpenSSL
    #from otpme.lib.messages import message
    from otpme.lib.messages import error_message
    if OpenSSL.__version__.startswith('0.15'):
        error_message(_("WARNING: You are probably using a pyopenssl version "
                    "that leads to poor performance at the module load stage."))
        error_message(_("WARNING: see https://github.com/pyca/pyopenssl/issues/137"))


def create_csr(common_name, key=None, key_len=2048, sign_algo=b"sha256",
    country=None, state=None, locality=None, organization=None,
    ou=None, email=None):
    """ Create CSR. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()

    # Make sure we convert strings to int()
    try:
        key_len = int(key_len)
    except:
        raise Exception("'key_len' must be int")

    # Load given key.
    if key:
        _key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    else:
        # Generate key pair.
        _key = OpenSSL.crypto.PKey()
        _key.generate_key(OpenSSL.crypto.TYPE_RSA, key_len)

    # Generate CSR.
    _req = OpenSSL.crypto.X509Req()
    _req.get_subject().CN = common_name
    if country:
        _req.get_subject().C = country
    if state:
        _req.get_subject().ST = state
    if locality:
        _req.get_subject().L = locality
    if organization:
        _req.get_subject().O = organization
    if ou:
        _req.get_subject().OU = ou
    if email:
        _req.get_subject().emailAddress = email

    # Add public key to CSR.
    _req.set_pubkey(_key)
    # Set signature algorithm.
    _req.sign(_key, sign_algo)

    # Get private key as PEM.
    private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                _key)
    # Get CSR as PEM.
    csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM,
                                                _req)
    return csr, private_key


def create_certificate(common_name, serial_number, cert_type, cert_req=None,
    self_signed=False, ca_cert=None, ca_key=None, key=None, key_usage=None,
    basic_constraints=None, sign_algo=b"sha256", key_len=2048, country=None,
    state=None, locality=None, email=None, organization=None, ou=None,
    valid=365, out_format=b"pem"):
    """ Create a certificate. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()

    # Make sure we convert strings to int()
    try:
        key_len = int(key_len)
    except:
        raise Exception("'key_len' must be int")

    try:
        valid = int(valid)
    except:
        raise Exception("'valid' must be int")

    # Output formats we support
    supported_out_formats = [ b"pem", b"p12" ]

    if not out_format in supported_out_formats:
        raise Exception(_("Unknown output format: %s") % out_format)
    if self_signed and cert_req:
        raise Exception("Cannot create self signed certificate from CSR.")
    if not self_signed and not (ca_cert and ca_key):
        raise Exception("Need ca_cert and ca_key.")

    if not self_signed and (ca_cert and ca_key):
        CA_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert)
        CA_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key)

    # Will hold all x509 extensions for the certificate
    extension_list = []

    # Create x509 instance (cert request)
    x509 = OpenSSL.crypto.X509()

    #print(dir(x509))

    if cert_req:
        # Load CSR
        _csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, cert_req)
        # Get public key.
        _key = _csr.get_pubkey()
        # Get subject.
        subj = _csr.get_subject()
        # Make sure the CSR common name matches.
        if subj.commonName != common_name:
            raise Exception(_("Common name of CSR does not match: %s")
                            % common_name)
    else:
        if key:
            # Load given key.
            _key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        else:
            # Generate key pair.
            _key = OpenSSL.crypto.PKey()
            _key.generate_key(OpenSSL.crypto.TYPE_RSA, key_len)
        # Create subject.
        subj = x509.get_subject()

    # Build subject for certificate.
    subj.commonName = common_name
    if country:
        subj.countryName = country
    if state:
        subj.stateOrProvinceName = state
    if locality:
        subj.localityName = locality
    if organization:
        subj.organizationName = organization
    if ou:
        subj.OU = ou
    if email:
        subj.emailAddress = email

    # Set cert subject.
    x509.set_subject(subj)

    # Set cert public key.
    x509.set_pubkey(_key)

    # Set cert serial number.
    x509.set_serial_number(serial_number)

    # Check if we should generate a self-sign cert.
    if self_signed:
        # For self-signed certs we have to use the client cert key for signing.
        sign_key = _key
        # Set issue subject to our own.
        x509.set_issuer(subj)
    else:
        # Sign key must be the ca key for non self-signed certs.
        sign_key = CA_key
        # Set cert issuer to CA's subject.
        x509.set_issuer(CA_cert.get_subject())

    # Check if cert type should be critical.
    if cert_type[0] == "critical":
        cert_type_criticial = True
        cert_type.pop(0)
    else:
        cert_type_criticial = False

    # Set cert type (e.g. client, server, sslCA ...)
    ext_name = b"nsCertType"
    cert_types_list = b",".join(cert_type)
    cert_type_ext = OpenSSL.crypto.X509Extension(ext_name,
                                                cert_type_criticial,
                                                cert_types_list)
    extension_list.append(cert_type_ext)

    # Set key usage if given.
    if key_usage:
        if key_usage[0] == b"critical":
            key_usage_criticial = True
            key_usage.pop(0)
        else:
            key_usage_criticial = False

        ext_name = b"keyUsage"
        key_usages_list = b",".join(key_usage)
        key_usage_ext = OpenSSL.crypto.X509Extension(ext_name,
                                                    key_usage_criticial,
                                                    key_usages_list)
        extension_list.append(key_usage_ext)

    # Set basic constraints if given.
    if basic_constraints:
        if basic_constraints[0] == b"critical":
            basic_constraints_criticial = True
            basic_constraints.pop(0)
        else:
            basic_constraints_criticial = False

        ext_name = b"basicConstraints"
        basic_constraints_list = b",".join(basic_constraints)
        basic_constraints_ext = OpenSSL.crypto.X509Extension(ext_name,
                                                basic_constraints_criticial,
                                                basic_constraints_list)
        extension_list.append(basic_constraints_ext)

    # Add extensions to our new cert (request)
    x509.add_extensions(extension_list)

    # Calculate cert validity.
    now = datetime.datetime.now(tz=pytz.UTC)
    sooner = now - datetime.timedelta(days=1)
    later = now + datetime.timedelta(days=valid)

    # Set cert validity.
    x509.set_notBefore(sooner.strftime("%Y%m%d%H%M%SZ"))
    x509.set_notAfter(later.strftime("%Y%m%d%H%M%SZ"))

    # Sign the cert.
    x509.sign(sign_key, sign_algo)

    # Return the new cert and key in the requested format.
    if out_format == "pem":
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                    x509)
        # If we got a CSR there is no private key to return.
        if cert_req:
            key_pem = None
        else:
            key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                    _key)
        return cert_pem, key_pem

    elif out_format == "p12":
        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(_key)
        p12.set_certificate(x509)
        if not self_signed:
            p12.set_ca_certificates([CA_cert])
        p12_bundle = p12.export(passphrase="")
        return p12_bundle

    else:
        raise Exception(_("Unknown format: %s") % out_format)


def gen_revoke_timestamp():
    """ Create timestamp used when generating CRL. """
    import time
    return time.strftime("%Y%m%d%H%M%SZ")


def revoke_certificate(ca_cert, ca_key, cert=None, serial_number=None,
    ca_crl=None, reason=b"unspecified", valid=3650, sign_algo=b"sha256"):
    """ Revoke a certificate
            valid reasons are: unspecified, keyCompromise, CACompromise,
                               affiliationChanged, superseded,
                               cessationOfOperation, certificateHold,
                               removeFromCRL
    """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()

    major_version = OpenSSL.__version__.split(".")[0]
    major_version = int(major_version)

    if major_version < 1:
        if sign_algo is not None:
            msg = ("Ignoring parameter 'sign_algo' for pyopenssl version '%s'."
                    % major_version)
            logger.info(msg)

    # Make sure we convert strings to int()
    try:
        valid = int(valid)
    except:
        msg = ("'valid' must be int")
        raise OTPmeException(msg)

    #print(revoked.all_reasons())
    #print(x509.get_subject().get_components())

    # Load CA cert and key.
    CA_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert)
    CA_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key)

    # If we got an cert get serial number.
    if cert:
        Cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        # Get certs serial number in hex format.
        serial_number = hex(Cert.get_serial_number())[2:]
        # Get certs expire date
        not_after = Cert.get_notAfter()

        # Calculate unix timestamp for certs "not_after" + 30 days.
        year = int(not_after[:4])
        month = int(not_after[4:6])
        day = int(not_after[6:8])
        hour = int(not_after[8:10])
        minute = int(not_after[10:12])
        cert_end_time = datetime.datetime(year, month, day, hour, minute)
        remove_time = cert_end_time + datetime.timedelta(days=30)
        # FIXME: Workaround for "OverflowError: mktime argument out of range"
        #        with time.mktime() on some platforms.
        #        http://stackoverflow.com/questions/2518706/python-mktime-overflow-error
        #revoke_until = time.mktime(remove_time.timetuple())
        epoch = datetime.datetime(1970, 1, 1)
        diff = remove_time - epoch
        revoke_until = diff.total_seconds()
    elif serial_number:
        revoke_until = False

    # Load CRL or create an emtpy one.
    if ca_crl:
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, ca_crl)
    else:
        crl = OpenSSL.crypto.CRL()

    # Create revoke object.
    revoked = OpenSSL.crypto.Revoked()
    # Set cert serial to be revoked.
    revoked.set_serial(serial_number)

    # Do not add already revoked certificate.
    if crl.get_revoked() != None:
        for r in crl.get_revoked():
            if r.get_serial() == revoked.get_serial():
                raise CertAlreadyRevoked("Certificate already revoked.")

    revoked.set_reason(reason)
    revoked.set_rev_date(gen_revoke_timestamp())

    # Add it to CRL.
    crl.add_revoked(revoked)
    # Create base64 encoded CRL.
    if major_version > 0:
        crl_text = crl.export(CA_cert, CA_key, days=valid, digest=sign_algo)
    else:
        crl_text = crl.export(CA_cert, CA_key, days=valid)
    # Return CRL
    x = revoked.get_serial(), revoke_until, crl_text
    return x


def get_ca_chain(cert, crl=None, last_issuer=None, cert_chain=None):
    """ Return CA chain needed to verify given certificate
        and optionally include CA CRLs.
    """
    from otpme.lib.classes.ca import Ca
    issuer = get_issuer(cert)
    ca = Ca(path=issuer)

    if not ca.exists():
        raise Exception("Unknown CA '%s'." % issuer)

    if issuer == last_issuer:
        return cert_chain

    if cert_chain:
        if crl:
            cert_chain = "%s%s%s" % (cert_chain, ca.cert, ca.crl)
        else:
            cert_chain = "%s%s" % (cert_chain, ca.cert)
    else:
        if crl:
            cert_chain = "%s%s" % (ca.cert, ca.crl)
        else:
            cert_chain = ca.cert

    cert_chain = get_ca_chain(ca.cert, crl=crl,
                            last_issuer=issuer,
                            cert_chain=cert_chain)
    return cert_chain


def get_issuer(cert):
    """ Get certificates issuer CN. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()
    c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    issuer = c.get_issuer()
    return issuer.commonName


def get_cn(cert):
    """ Return certificates common name. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()
    c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    common_name = c.get_subject().commonName
    return common_name


def pem_to_der(cert):
    """ Convert cert form PEM to DER. """
    from Crypto.PublicKey import RSA
    key = RSA.importKey(cert)
    der_cert = key.publickey().exportKey("DER")
    return der_cert


def check_crl(crl, serial_number):
    """ Check if cert serial number is present in CRL. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()

    # Load CRL or create an emtpy one.
    _crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl)

    # Create revoke object.
    revoked = OpenSSL.crypto.Revoked()
    # Set cert serial to be revoked.
    serial_number = serial_number.encode()
    revoked.set_serial(serial_number)

    # Check if certificate was revoked.
    if _crl.get_revoked() != None:
        for r in _crl.get_revoked():
            if r.get_serial() == revoked.get_serial():
                return True
    return False


def verify_cn(cn, cert=None, csr=None):
    """ Make sure cert/crs matches given CN. """
    try:
        global OpenSSL
        if OpenSSL is None:
            raise
    except:
        import OpenSSL
        check_pyopenssl_version()

    if cert:
        x = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    elif csr:
        x = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    else:
        raise Exception("Need <cert> or <csr>.")

    # Get subject.
    subj = x.get_subject()

    # Make sure common name matches.
    if subj.commonName != cn:
        raise Exception(_("Common name does not match: %s") % cn)


#def get_revoked_from_crl(crl):
#    """ Get revoked certificate serials from CRL. """
#    Crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl)
#    revoked = Crl.get_revoked()
#    # Return list with revoked certificate serial numbers.
#    return revoked
#

# FIXME: Whats the correct format for cert serials? for CRL generation we need hex format!
#def get_serial(cert):
#    """ Return certificates serial number. """
#    try:
#        global OpenSSL
#        if OpenSSL is None:
#            raise
#    except:
#        import OpenSSL
#        check_pyopenssl_version()
#    c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
#    serial_number = hex(c.get_serial_number())[2:]
#    #print(c.get_subject().get_components())
#    return serial_number
