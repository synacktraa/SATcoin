import datetime

from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .asymmetric import RSA


class Certificate:

    def __init__(
        self, 
        province: x509.ObjectIdentifier, 
        country: x509.ObjectIdentifier, 
        locality: x509.ObjectIdentifier,
        organization: x509.ObjectIdentifier,
        private_key : RSA.RsaMemPrivateKey,
    ) -> None:

        self.private_key = private_key
        self.subject = x509.Name(
            [
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            ]
        )

    def build(
        self, 
        csr: x509.CertificateSigningRequest, 
        public_key: RSA.RsaMemPublicKey
    ) -> x509.Certificate:

        return x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).sign(
            self.private_key, 
            hashes.SHA256(), 
            default_backend()
        )
    
    @staticmethod
    def as_pem(certificate: x509.Certificate) -> bytes:
        return certificate.public_bytes(encoding=serialization.Encoding.PEM)


    @staticmethod
    def load(certificate_pem: bytes) -> x509.Certificate:
        return x509.load_pem_x509_certificate(
            certificate_pem, 
            backend=default_backend()
        )

    @staticmethod
    def verify(certificate: x509.Certificate, public_key: RSA.RsaMemPublicKey):

        return public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding = padding.PKCS1v15(),
            algorithm = hashes.SHA256(),
        )
