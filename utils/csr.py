from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes

from .asymmetric import RSA


class CSR:

    def __init__(self, 
        province: x509.ObjectIdentifier, 
        country: x509.ObjectIdentifier, 
        locality: x509.ObjectIdentifier,
        organization: x509.ObjectIdentifier,
        domain: x509.ObjectIdentifier
    ) -> None:

        self.new_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]
        )
    
    
    def build(
        self, 
        private_key: RSA.RsaMemPrivateKey
    ) -> x509.CertificateSigningRequest:

        return x509.CertificateSigningRequestBuilder().subject_name(
                self.new_subject
            ).sign(
                private_key, 
                hashes.SHA256(), 
                default_backend()
        )

    
    @staticmethod
    def as_pem(csr: x509.CertificateSigningRequest) -> bytes:
        return csr.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    @staticmethod
    def load(pem_formatted_CSR: bytes) -> x509.CertificateSigningRequest:
        return x509.load_pem_x509_csr(pem_formatted_CSR, default_backend())
