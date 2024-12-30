# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.encoding.base import encode
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

class SSLCert(object):
    """ Class that represents a SSL certificate. """
    def __init__(self, cert=None, key=None, cert_format="PEM", key_format="PEM"):
        self.cert = cert
        self.key = key
        self._cert = None
        self._key = None
        if cert:
            if cert_format == "PEM":
                cert_method = x509.load_pem_x509_certificate
            else:
                cert_method = x509.load_der_x509_certificate
            if isinstance(cert, str):
                cert = cert.encode()
            self._cert = cert_method(cert, default_backend())
        if key:
            if key_format == "PEM":
                key_method = serialization.load_pem_private_key
            else:
                key_method = serialization.load_der_private_key
            if isinstance(key, str):
                key = key.encode()
            # Workaround for https://github.com/pyca/cryptography/issues/7236
            self._key = key_method(data=key,
                                password=None,
                                backend=default_backend(),
                                unsafe_skip_rsa_key_validation=True)

    def __hash__(self):
        return hash(self.__dict__)
    def __eq__(self, other):
        return self.tpl == other
    def __repr__(self):
        return repr(self.__dict__)

    def fingerprint(self, digest="sha256"):
        """ Get cert fingerprint. """
        if digest == "sha256":
            _digest = hashes.SHA256()
        elif digest == "sha1":
            _digest = hashes.SHA1()
        else:
            msg = "Unknown digest: %s" % digest
            raise OTPmeException(msg)
        fingerprint_bytes = self._cert.fingerprint(_digest)
        fingerprint = encode(fingerprint_bytes, "hex")
        return fingerprint

    def dump(self, encoding="PEM"):
        """ Return certificate in the given encoding. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        if encoding == "PEM":
            out_encoding = serialization.Encoding.PEM
        else:
            out_encoding = serialization.Encoding.DER
        cert_data = self._cert.public_bytes(encoding=out_encoding)
        if encoding == "PEM":
            if isinstance(cert_data, bytes):
                cert_data = cert_data.decode()
        return cert_data

    def private_key(self, encoding="PEM"):
        """ Get certificates private key as PEM string. """
        if encoding == "PEM":
            out_encoding = serialization.Encoding.PEM
        else:
            out_encoding = serialization.Encoding.DER
        encryption_algorithm = serialization.NoEncryption()
        out_format = serialization.PrivateFormat.PKCS8
        key_data = self._key.private_bytes(encoding=out_encoding,
                                    format=out_format,
                                    encryption_algorithm=encryption_algorithm)
        if encoding == "PEM":
            if isinstance(key_data, bytes):
                key_data = key_data.decode()
        return key_data

    def public_key(self, encoding="PEM"):
        """ Get certificates public key as PEM string. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        if encoding == "PEM":
            out_encoding = serialization.Encoding.PEM
        else:
            out_encoding = serialization.Encoding.DER
        out_format = serialization.PublicFormat.SubjectPublicKeyInfo
        public_key = self._cert.public_key()
        key_data = public_key.public_bytes(encoding=out_encoding,
                                            format=out_format)
        if encoding == "PEM":
            if isinstance(key_data, bytes):
                key_data = key_data.decode()
        return key_data

    def get_ca_chain(self, cert=None, crl=False, last_issuer=None, cert_chain=""):
        """ Return CA chain needed to verify given certificate
            and optionally include CA CRLs
        """
        # FIXME: Move get_ca_chain() to Certificate() class!?
        from otpme.lib.classes.ca import Ca
        if not cert:
            if not self._cert:
                raise Exception("No certificate loaded.")
            cert = self

        if isinstance(cert, str):
            cert = SSLCert(cert=cert)

        issuer = cert.get_issuer()

        ca = Ca(path=issuer)
        if not ca.exists():
            raise Exception(_("Unknown CA '%s'.") % issuer)

        if issuer == last_issuer:
            return cert_chain

        if crl:
            cert_chain = "%s%s%s" % (cert_chain, ca.cert, ca.crl)
        else:
            cert_chain = "%s%s" % (cert_chain, ca.cert)

        ca_cert = SSLCert(cert=ca.cert)

        cert_chain = ca_cert.get_ca_chain(cert=ca.cert,
                                crl=crl,
                                last_issuer=issuer,
                                cert_chain=cert_chain)
        return cert_chain

    def get_issuer(self):
        """ Get certificates issuer CN. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        issuer = self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer = issuer[0].value
        return issuer

    def get_start_time(self, get_datetime=False):
        """ Get certificates validity start time. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        not_before = self._cert.not_valid_before
        if get_datetime:
            return not_before
        start_time = not_before.strftime('%Y%m%d%H%M%SZ')
        return start_time

    def get_end_time(self, get_datetime=False):
        """ Get certificates validity end time. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        not_after = self._cert.not_valid_after
        if get_datetime:
            return not_after
        end_time = not_after.strftime('%Y%m%d%H%M%SZ')
        return end_time

    def get_cn(self):
        """ Return certificates common name. """
        if not self._cert:
            raise Exception("No certificate loaded.")
        cn = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn[0].value
        return cn

    def encrypt_key(self, passphrase, encoding="PEM"):
        """ Return encrypted key. """
        if not self.key:
            raise Exception("No private key loaded.")
        if encoding == "PEM":
            out_encoding = serialization.Encoding.PEM
        else:
            out_encoding = serialization.Encoding.DER
        if isinstance(passphrase, str):
            passphrase = passphrase.encode()
        _algo = serialization.BestAvailableEncryption
        out_format = serialization.PrivateFormat.TraditionalOpenSSL
        key_data = self._key.private_bytes(encoding=out_encoding,
                                        format=out_format,
                                        encryption_algorithm=_algo(passphrase))
        if encoding == "PEM":
            if isinstance(key_data, bytes):
                key_data = key_data.decode()
        return key_data

    def sign(self, data, digest="sha256", encoding=None):
        """ Sign given data. """
        if self._key is None:
            msg = (_("Cannot sign: Cert private key missing."))
            raise OTPmeException(msg)

        if digest == "sha256":
            _digest = hashes.SHA256()
        else:
            msg = "Unknown digest: %s" % digest
            raise OTPmeException(msg)

        _padding = padding.PSS(mgf=padding.MGF1(_digest),
                            salt_length=padding.PSS.MAX_LENGTH)
        if isinstance(data, str):
            data = data.encode()
        # Sign data.
        try:
            signature = self._key.sign(data=data,
                                        padding=_padding,
                                        algorithm=_digest)
        except Exception as e:
            raise Exception(_("Error signing data: %s") % e)
        if encoding:
            signature = encode(signature, encoding)

        return signature

    def verify(self, data, signature, digest="sha256", encoding=None):
        """ Verify given data and signature. """
        if not self._cert:
            raise Exception("No certificate loaded.")

        if digest == "sha256":
            _digest = hashes.SHA256()
        else:
            msg = "Unknown digest: %s" % digest
            raise OTPmeException(msg)

        if encoding:
            signature = decode(signature, encoding)

        if isinstance(data, str):
            data = data.encode()

        _padding = padding.PSS(mgf=padding.MGF1(_digest),
                            salt_length=padding.PSS.MAX_LENGTH)

        public_key = self._cert.public_key()
        try:
            public_key.verify(signature=signature,
                            data=data,
                            padding=_padding,
                            algorithm=_digest)
            return True
        except Exception as e:
            config.raise_exception()
            raise Exception(_("Error verifying signature: %s") % e)

    def get_serial(self):
        """ Return certificates serial number. """
        serial_number = self._cert.serial_number
        return serial_number
