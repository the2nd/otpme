# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import pytz
import datetime

from cryptography import x509
from cryptography.x509 import CRLReason
from cryptography.x509 import ReasonFlags
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.exceptions import *

logger = config.logger

cn_attribute_order = [
                    'country',
                    'state',
                    'locality',
                    'organization',
                    'ou',
                    'email',
                ]

cn_attributes = {
    'common_name'               : 'COMMON_NAME',
    'country'                   : 'COUNTRY_NAME',
    'state'                     : 'STATE_OR_PROVINCE_NAME',
    'locality'                  : 'LOCALITY_NAME',
    'organization'              : 'ORGANIZATION_NAME',
    'ou'                        : 'ORGANIZATIONAL_UNIT_NAME',
    #'street_address'            : 'STREET_ADDRESS',
    'serial_number'             : 'SERIAL_NUMBER',
    'surname'                   : 'SURNAME',
    'given_name'                : 'GIVEN_NAME',
    'title'                     : 'TITLE',
    'generation_qualifier'      : 'GENERATION_QUALIFIER',
    #'x500_unique_identifier'    : 'X500_UNIQUE_IDENTIFIER',
    'dn_qualifier'              : 'DN_QUALIFIER',
    'pseudonym'                 : 'PSEUDONYM',
    #'user_uid'                  : 'USER_ID',
    'domain_component'          : 'DOMAIN_COMPONENT',
    'email'                     : 'EMAIL_ADDRESS',
    'jurisdiction_state'        : 'JURISDICTION_STATE_OR_PROVINCE_NAME',
    'jurisdiction_country'      : 'JURISDICTION_COUNTRY_NAME',
    'jurisdiction_locality'     : 'JURISDICTION_LOCALITY_NAME',
    'business_category'         : 'BUSINESS_CATEGORY',
    #'postal_address'            : 'POSTAL_ADDRESS',
    #'postal_code'               : 'POSTAL_CODE',
}

key_usage_attributes = [
    'digital_signature',
    'content_commitment',
    'key_encipherment',
    'data_encipherment',
    'key_agreement',
    'key_cert_sign',
    'crl_sign',
    'encipher_only',
    'decipher_only',
]

for x in cn_attributes:
    if x in cn_attribute_order:
        continue
    cn_attribute_order.append(x)

def get_ca_chain(cert, crl=None, last_issuer=None, cert_chain=None):
    """ Return CA chain needed to verify given certificate
        and optionally include CA CRLs.
    """
    from otpme.lib.classes.ca import Ca
    if isinstance(cert, str):
        cert = cert.encode()
    if isinstance(crl, str):
        crl = crl.encode()
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
    if isinstance(cert, str):
        cert = cert.encode()
    c = x509.load_pem_x509_certificate(data=cert, backend=default_backend())
    issuer = c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = issuer[0].value
    return issuer

def get_cn(cert):
    """ Return certificates common name. """
    if isinstance(cert, str):
        cert = cert.encode()
    c = x509.load_pem_x509_certificate(data=cert, backend=default_backend())
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn[0].value
    return cn

def check_crl(crl, sn):
    """ Check if cert serial number is present in CRL. """
    if isinstance(crl, str):
        crl = crl.encode()
    # Load CRL or create an emtpy one.
    _crl = x509.load_pem_x509_crl(crl, default_backend())
    # Check if cert serial number is found.
    for x in _crl:
        if x.serial_number == sn:
            return True
    return False

def verify_cn(cn, cert=None, csr=None):
    """ Make sure cert/crs matches given CN. """
    if isinstance(cert, str):
        cert = cert.encode()
    if isinstance(csr, str):
        csr = csr.encode()
    if cert:
        x = x509.load_pem_x509_certificate(data=cert, backend=default_backend())
    elif csr:
        x = x509.load_pem_x509_csr(csr, default_backend())
    else:
        msg = ("Need <cert> or <csr>.")
        raise OTPmeException(msg)

    _cn = x.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    _cn = _cn[0].value

    # Make sure common name matches.
    if cn == _cn:
        return True

    msg = (_("Common name does not match: %s") % cn)
    raise OTPmeException(msg)

def create_csr(cn, key_len=2048, sign_algo="sha256",
    key=None, ca_cert=False, ca_path_len=None, **kwargs):
    """ Create CSR. """
    if sign_algo == "sha256":
        _sign_algo = hashes.SHA256()
    else:
        msg = "Unknown sing algorithm: %s" % sign_algo
        raise OTPmeException(msg)

    # Make sure we convert strings to int()
    try:
        key_len = int(key_len)
    except:
        msg = ("'key_len' must be int")
        raise OTPmeException(msg)

    if isinstance(key, str):
        key = key.encode()
    if isinstance(ca_cert, str):
        ca_cert = ca_cert.encode()

    # Load given key.
    if key:
        _key = serialization.load_pem_private_key(data=key,
                                            password=None,
                                            backend=default_backend())
    else:
        _key = rsa.generate_private_key(public_exponent=65537,
                                        key_size=key_len,
                                        backend=default_backend())

    # Create CSR builder.
    builder = x509.CertificateSigningRequestBuilder()
    # CA cert related settings.
    basic_constraints = x509.BasicConstraints(ca=ca_cert,
                                        path_length=ca_path_len)
    builder = builder.add_extension(basic_constraints, critical=False)

    # Add CN attributes.
    _cn = x509.NameAttribute(NameOID.COMMON_NAME, cn)


    cn_attrs = []
    cn_attrs.append(_cn)
    for x in cn_attribute_order:
        if x not in kwargs:
            continue
        x_name = cn_attributes[x]
        attr_oid = getattr(NameOID, x_name)
        attr_val = kwargs[x]
        if attr_val is None:
            continue
        x_attr = x509.NameAttribute(attr_oid, attr_val)
        cn_attrs.append(x_attr)

    csr_cn = x509.Name(cn_attrs)
    # Add CN.
    builder = builder.subject_name(csr_cn)

    # Gen CSR.
    request = builder.sign(private_key=_key,
                        algorithm=_sign_algo,
                        backend=default_backend())

    private_key = _key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption())
    private_key = private_key.decode()
    csr = request.public_bytes(encoding=serialization.Encoding.PEM)
    csr = csr.decode()

    return csr, private_key

def create_certificate(cn, sn, cert_req=None, self_signed=False,
    sign_key=None, ca_cert=None, ca_key=None, key=None, key_usage=None,
    ext_key_usage=None, basic_constraints=None, cn_alt=None,
    override_cn_attributes=False, sign_algo="sha256", key_len=2048,
    timezone="UTC", valid=365, **kwargs):
    """ Create a certificate. """
    add_cn_attributes = False
    if override_cn_attributes:
        add_cn_attributes = True

    if isinstance(ca_cert, str):
        ca_cert = ca_cert.encode()
    if isinstance(ca_key, str):
        ca_key = ca_key.encode()
    if isinstance(cert_req, str):
        cert_req = cert_req.encode()
    if isinstance(key, str):
        key = key.encode()

    if sign_algo == "sha256":
        _sign_algo = hashes.SHA256()
    else:
        msg = "Unknown sing algorithm: %s" % sign_algo
        raise OTPmeException(msg)

    # Make sure we convert strings to int()
    try:
        key_len = int(key_len)
    except:
        msg = ("'key_len' must be int")
        raise OTPmeException(msg)

    try:
        valid = int(valid)
    except:
        msg = ("<valid> must be int: %s" % valid)
        raise OTPmeException(msg)

    if self_signed and cert_req:
        if not sign_key:
            msg = "Need <sign_key> when creating self signed cert from CSR."
            raise OTPmeException(msg)
    if not self_signed and not (ca_cert and ca_key):
        raise OTPmeException("Need ca_cert and ca_key.")

    if not self_signed and (ca_cert and ca_key):
        CA_cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
        CA_key = serialization.load_pem_private_key(data=ca_key,
                                                password=None,
                                                backend=default_backend())
    cn_attrs = []
    if cert_req:
        # Load CSR
        _csr = x509.load_pem_x509_csr(cert_req, default_backend())

        # Get CN attributes from CSR.
        for x in cn_attribute_order:
            x_name = cn_attributes[x]
            attr_oid = getattr(NameOID, x_name)
            x_attrs = _csr.subject.get_attributes_for_oid(attr_oid)
            for a in x_attrs:
                cn_attrs.append(a)

        # Get subject.
        cn_attr = _csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        cn_val = cn_attr.value

        cn_attrs.append(cn_attr)

        # Make sure the CSR common name matches.
        if cn_val != cn:
            msg = (_("Common name of CSR does not match: %s") % cn)
            raise OTPmeException(msg)

        # Get public key.
        cert_public_key = _csr.public_key()

    else:
        # Add CN attributes.
        cn_attr = x509.NameAttribute(NameOID.COMMON_NAME, cn)

        if key:
            # Load given key.
            _key = serialization.load_pem_private_key(data=key,
                                                password=None,
                                                backend=default_backend())
        else:
            # Generate key pair.
            _key = rsa.generate_private_key(public_exponent=65537,
                                            key_size=key_len,
                                            backend=default_backend())
        # Get public key.
        cert_public_key = _key.public_key()
        add_cn_attributes = True

    # Add CN attributes from kwargs.
    if add_cn_attributes:
        cn_attrs.append(cn_attr)
        for x in cn_attribute_order:
            if x not in kwargs:
                continue
            x_name = cn_attributes[x]
            attr_oid = getattr(NameOID, x_name)
            attr_val = kwargs[x]
            # Do not override with None values if disabled.
            if not override_cn_attributes:
                if attr_val is None:
                    continue
            x_attr = x509.NameAttribute(attr_oid, attr_val)
            cn_attrs.append(x_attr)

    # Get builder.
    builder = x509.CertificateBuilder()

    # Add CN.
    csr_cn = x509.Name(cn_attrs)
    builder = builder.subject_name(csr_cn)

    # Set altnames.
    if cn_alt:
        alt_names = []
        for x in cn_alt:
            alt_name = x509.DNSName(x)
            alt_names.append(alt_name)
        # Build subject alternative names.
        _alt_names = x509.SubjectAlternativeName(alt_names)
        # Add subject alternative names.
        builder = builder.add_extension(_alt_names, critical=False)

    # Set cert public key.
    builder = builder.public_key(cert_public_key)

    # Set cert serial number.
    builder = builder.serial_number(sn)

    # Check if we should generate a self-sign cert.
    if self_signed:
        if sign_key:
            _sign_key = serialization.load_pem_private_key(data=sign_key,
                                                password=None,
                                                backend=default_backend())
        else:
            # For self-signed certs we have to use the client cert key for signing.
            _sign_key = _key
        # Set issue subject to our own.
        cert_issuer = x509.Name(cn_attrs)
    else:
        # Sign key must be the CA key for non self-signed certs.
        _sign_key = CA_key
        # Set cert issuer to CA's CN.
        cert_issuer = CA_cert.subject
        cert_issuer = x509.Name(cert_issuer)

    # Add issuer.
    builder = builder.issuer_name(cert_issuer)

    # Set basic constraints.
    if basic_constraints:
        if basic_constraints[0] == "critical":
            basic_constraints_criticial = True
            basic_constraints.pop(0)
        else:
            basic_constraints_criticial = False

        ca = False
        path_len = None
        for x in list(basic_constraints):
            _x = x.split(":")
            x_key = _x[0]
            try:
                x_val = _x[1]
            except:
                x_val = None

            if x_key == "CA":
                if x_val.lower() == "true":
                    ca = True
            if x_key == "pathlen":
                try:
                    path_len = int(x_val)
                except:
                    msg = "<pathlen> must be int()."
                    raise OTPmeException(msg)

        # Add basic constraints to our new cert.
        _basic_constraints = x509.BasicConstraints(ca=ca, path_length=path_len)
        builder = builder.add_extension(_basic_constraints,
                                    critical=basic_constraints_criticial)

    # Set key usage.
    if key_usage:
        if key_usage[0] == b"critical":
            key_usage_criticial = True
            key_usage.pop(0)
        else:
            key_usage_criticial = False

        key_usage_kwargs = {}
        for x in key_usage_attributes:
            if x not in key_usage:
                key_usage_kwargs[x] = False
                continue
            key_usage_kwargs[x] = True
        _key_usage = x509.KeyUsage(**key_usage_kwargs)
        builder = builder.add_extension(_key_usage, critical=key_usage_criticial)

    # Check if extended key usage should be critical.
    if ext_key_usage:
        if ext_key_usage[0] == "critical":
            ext_key_usage_critical = True
            ext_key_usage.pop(0)
        else:
            ext_key_usage_critical = False

        # Get extended key usage attributes.
        ext_key_usage_oids = []
        for x in ext_key_usage:
            try:
                attr_oid = getattr(ExtendedKeyUsageOID, x)
            except:
                msg = "Unknown extended key usage: %s" % x
                raise OTPmeException(msg)
            ext_key_usage_oids.append(attr_oid)

        # Build extended key usage.
        if ext_key_usage_oids:
            _ext_key_usage = x509.ExtendedKeyUsage(ext_key_usage_oids)
            # Add extended key usage.
            builder = builder.add_extension(_ext_key_usage,
                                        critical=ext_key_usage_critical)

    # Calculate cert validity.
    tz = pytz.timezone(timezone)
    now = datetime.datetime.now(tz=tz)
    #sooner = now - datetime.timedelta(days=1)
    sooner = now
    later = now + datetime.timedelta(days=valid)

    # Set cert validity.
    builder = builder.not_valid_before(sooner)
    builder = builder.not_valid_after(later)

    # Sign the cert.
    cert = builder.sign(private_key=_sign_key,
                                algorithm=_sign_algo,
                                backend=default_backend())

    # Get cert in PEM format.
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_pem = cert_pem.decode()

    # Get key in PEM format.
    key_pem = None
    if not cert_req:
        key_pem = _key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption())
        key_pem = key_pem.decode()
    return cert_pem, key_pem

def revoke_certificate(ca_cert, ca_key, cert=None, sn=None,
    ca_crl=None, reason=b"unspecified", next_update=365, valid=3650,
    sign_algo="sha256", timezone="UTC", crl_update=False):
    """ Revoke a certificate
            valid reasons are: unspecified, keyCompromise, CACompromise,
                               affiliationChanged, superseded,
                               cessationOfOperation, certificateHold,
                               removeFromCRL
    """
    if sign_algo == "sha256":
        _sign_algo = hashes.SHA256()
    else:
        msg = "Unknown sing algorithm: %s" % sign_algo
        raise OTPmeException(msg)

    # Make sure we convert strings to int().
    try:
        valid = int(valid)
    except:
        msg = ("<valid> must be int.")
        raise OTPmeException(msg)

    try:
        next_update = int(next_update)
    except:
        msg = "<next_update> must be int, got %s." % type(next_update)
        raise OTPmeException(msg)

    if sn is not None:
        try:
            sn = int(sn)
        except:
            msg = ("<sn> must be int.")
            raise OTPmeException(msg)

    if isinstance(ca_key, str):
        ca_key = ca_key.encode()
    if isinstance(ca_cert, str):
        ca_cert = ca_cert.encode()
    if isinstance(ca_crl, str):
        ca_crl = ca_crl.encode()
    if isinstance(cert, str):
        cert = cert.encode()

    # Load CA cert and key.
    CA_cert = x509.load_pem_x509_certificate(data=ca_cert,
                                        backend=default_backend())
    CA_key = serialization.load_pem_private_key(data=ca_key,
                                        password=None,
                                        backend=default_backend())

    # If we got an cert get serial number.
    if cert:
        Cert = x509.load_pem_x509_certificate(cert, default_backend())
        # Get certs serial number.
        try:
            sn = Cert.serial_number
        except AttributeError:
            sn = Cert.serial
        # Get certs expire date
        not_after = Cert.not_valid_after
        not_after = not_after.strftime('%Y%m%d%H%M%SZ')

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
    elif sn is not None:
        revoke_until = None
    else:
        msg = "Need <sn>."
        raise OTPmeException(msg)

    # Revocation date.
    tz = pytz.timezone(timezone)
    revocation_date = datetime.datetime.now(tz=tz)
    # Next CRL update.
    _next_update = datetime.timedelta(next_update, 0, 0)

    # Get CRL issuer from CA cert.
    crl_issuer = CA_cert.subject
    crl_issuer = x509.Name(crl_issuer)

    # CRL builder.
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(crl_issuer)
    builder = builder.last_update(revocation_date)
    builder = builder.next_update(revocation_date + _next_update)

    # Load CRL or create an emtpy one.
    if ca_crl:
        old_crl = x509.load_pem_x509_crl(ca_crl, default_backend())
        # Add certs from old CRL.
        for x in old_crl:
            if crl_update:
                if x.serial_number == sn:
                    continue
                builder.add_revoked_certificate(x)
            else:
                builder.add_revoked_certificate(x)
                # Make sure we do not add an already revoked cert.
                if x.serial_number != sn:
                    continue
                msg = ("Certificate already revoked.")
                raise CertAlreadyRevoked(msg)

    # Create revoke object.
    revoked_cert = x509.RevokedCertificateBuilder()

    # Add revocation reason.
    if reason:
        _reason = getattr(ReasonFlags, reason.decode())
        _reason = CRLReason(_reason)
        revoked_cert = revoked_cert.add_extension(_reason, critical=False)
    # Add serial number.
    revoked_cert = revoked_cert.serial_number(sn)
    # Add revocation date.
    revoked_cert = revoked_cert.revocation_date(revocation_date)
    # Build revocation certificate.
    revoked_cert = revoked_cert.build(default_backend())
    # Add revoked cert.
    builder = builder.add_revoked_certificate(revoked_cert)
    # Build CRL.
    crl = builder.sign(private_key=CA_key,
                    algorithm=_sign_algo,
                    backend=default_backend())

    # Get CRL as PEM.
    crl_data = crl.public_bytes(encoding=serialization.Encoding.PEM)
    crl_data = crl_data.decode()

    serial_number = str(revoked_cert.serial_number)
    return serial_number, revoke_until, crl_data

def check_ssl_cert_key(cert, key):
    from otpme.lib import backend
    from otpme.lib.pki.cert import SSLCert
    site = backend.get_object(uuid=config.site_uuid)
    cert = SSLCert(cert=site.radius_cert, key=site.radius_key)
    message = "test"
    try:
        signature = cert.sign(message)
        cert.verify(message, signature)
    except Exception as e:
        msg = "Key does not match certificate."
        raise Exception(msg)

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

