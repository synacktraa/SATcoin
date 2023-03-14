import socket
import threading
import select

from utils.asymmetric import RSA
from utils.cert import Certificate
from utils.csr import CSR

class Certauth:

    def __init__(self) -> None:

        self.instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.instance.bind(('127.0.0.1', 59002))
        
        self.instance.listen()

        self.private_key = RSA.load_mem_private_key()
        self.public_key = RSA.load_mem_public_key(self.private_key)
        self.pem_pubkey = RSA.ret_pem_public_key(self.public_key)
        
        self.cert_obj = Certificate(
            "West Bengal", 
            "IN", 
            "Kolkata", 
            "CERTAUTH Inc.", 
            self.private_key
        )

    def run(self):

        with open('./CA_pubkey.pem', 'wb') as fp:
            fp.write(self.pem_pubkey)

        print('Certificate Authority in running...')


        website, address = self.instance.accept()
        website.send(self.pem_pubkey)
        website_pubkey = RSA.load_mem_public_key(website.recv(2048))
        PEMCSR = website.recv(2048)
        csr = CSR.load(PEMCSR)
        certificate = self.cert_obj.build(csr, website_pubkey)
        website.send(Certificate.as_pem(certificate))
        website.close()


Certauth().run()