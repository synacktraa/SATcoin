from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from typing import Union, Optional

class RSA:

    RsaPemPrivateKey = bytes
    RsaPemPublicKey = bytes
    RsaMemPrivateKey = rsa.RSAPrivateKey
    RsaMemPublicKey = rsa.RSAPublicKey

    def load_mem_private_key(
        private_key: Optional[RsaPemPrivateKey] = None
    ) -> RsaMemPrivateKey:
    
        # Loads pem formatted private key into memory
        if isinstance(private_key, RSA.RsaPemPrivateKey):
            return serialization.load_pem_private_key(
                private_key,
                password=None,
                backend=default_backend()
            )
        
        # Generates and loads new private key into memory
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        

    def ret_pem_private_key(private_key: RsaMemPrivateKey) -> RsaPemPrivateKey:
        
        # returns pem formatted private key from memory
        return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
        )


    def load_mem_public_key(
        key: Union[RsaMemPrivateKey, RsaPemPublicKey]
    ) -> RsaMemPublicKey:
        
        # Generates and loads new publicy key using private key into memory
        if isinstance(key, RSA.RsaMemPrivateKey):
            return key.public_key()
        
        # loads pem formatted public key into memory
        elif isinstance(key, RSA.RsaPemPublicKey):
            return serialization.load_pem_public_key(
                key,
                backend=default_backend()
            )
        assert AssertionError, "Invalid input"


    def ret_pem_public_key(public_key: RsaMemPublicKey) -> RsaPemPublicKey:
        
        # returns pem formatted public key from memory
        return public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    

    def sign(private_key: RsaMemPrivateKey, message: bytes):
        
        # signs message using private key
        return private_key.sign(
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
    

    def verify(
        public_key: RsaMemPublicKey, 
        signature: bytes, 
        message: bytes
    ) -> None:
    
        # verifies the digital signature using public key and message
        return public_key.verify(
            signature=signature,
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )


    def encrypt(public_key: RsaMemPublicKey, message: bytes):
        
        return public_key.encrypt(
            plaintext=message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(private_key: RsaMemPrivateKey, encrypted_data: bytes):

        return private_key.decrypt(
            ciphertext=encrypted_data,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )