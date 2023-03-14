from cryptography.fernet import Fernet

class AES:

    def keygen():
        return Fernet.generate_key()

    def encrypt(message: bytes, key: bytes) -> bytes:
        f = Fernet(key)
        return f.encrypt(message)
    
    def decrypt(token: bytes, key: bytes) -> bytes:
        f = Fernet(key)
        return f.decrypt(token)