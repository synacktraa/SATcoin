import threading
import socket
from typing import Dict, List, Union

from utils.csr import CSR
from utils.asymmetric import RSA
from utils.symmetric import AES


class Faucet:

    def __init__(self) -> None:
            
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", 59000))
        self.server.listen()

        self.clients : Dict[str, Dict[str, Union[socket.socket, RSA.RsaPemPublicKey]]] = dict()
        self.session : List[str] = list()

        self.private_key = RSA.load_mem_private_key()
        self.public_key = RSA.load_mem_public_key(self.private_key)
        self.pem_pubkey = RSA.ret_pem_public_key(self.public_key)

        self.csr_obj = CSR("West Bengal", "IN", "Kolkata", "SynAck Faucet LLC.", "synackfaucet.in")

    def handler(self, _from):

        sender = self.clients[_from]
        while True:
            try:
                message = AES.decrypt(sender['socket'].recv(1024), sender['symkey']).decode('utf-8')
                if message.startswith("connect"):
                    try:
                        receiver = self.clients[message.split()[1]]
                        self.session.insert(0, _from)
                        set_ = AES.encrypt("address?".encode('utf-8'), receiver['symkey'])
                        receiver['socket'].send(set_)
                    except KeyError:
                        sender['socket'].send(AES.encrypt("[server] user doesn't exist!".encode('utf-8'), sender['symkey']))
                elif message.startswith('address'):
                    self.clients[self.session[-1]]['socket'].send(
                        AES.encrypt(
                            f"{_from} {message.split()[1]}".encode('utf-8'), 
                            self.clients[self.session[-1]]['symkey']
                        )
                    )
                    self.session.pop()

            except Exception as e:
                del self.clients[_from]
                sender['socket'].close()
                print(f'{_from} is offline')
                break


    def run(self):

        print('Faucet initialized...')


        certauth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        certauth.connect(("127.0.0.1", 59002))

        # Asymmetric public key exchange
        ca_pubkey = certauth.recv(2048)
        certauth.send(self.pem_pubkey)
        
        csr = self.csr_obj.build(self.private_key)
        csr_pem = self.csr_obj.as_pem(csr)
        certauth.send(csr_pem)
        certificate = certauth.recv(2048)

        while True:
            try:
                client, address = self.server.accept()
                client.send(certificate)
                symkey = RSA.decrypt(self.private_key, client.recv(1024))
                client.send(AES.encrypt(b'alias?', symkey))
                alias = AES.decrypt(client.recv(1024), symkey).decode('utf-8')
                print(f"{alias} is online")
                client.send(AES.encrypt('[faucet] you are now connected!'.encode('utf-8'), symkey))
                self.clients[alias] = {
                    'socket': client, 
                    'symkey': symkey
                }
                thread = threading.Thread(target=self.handler, args=(alias,))
                thread.start()
            except KeyboardInterrupt:
                break

Faucet().run()