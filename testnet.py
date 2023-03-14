import threading
import socket

from typing import Dict, List

from utils.asymmetric import RSA
from utils.symmetric import AES


class Testnet:

    def __init__(self) -> None:
            
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", 59003))
        self.server.listen()

        self.nodes : Dict[socket.socket, bytes] = dict()

        self.private_key = RSA.load_mem_private_key()
        self.public_key = RSA.load_mem_public_key(self.private_key)
        self.pem_pubkey = RSA.ret_pem_public_key(self.public_key)

    def handler(self, node):

        while True:
            try:
                block = AES.decrypt(node.recv(1024), self.nodes[node])
                self.blockchain.append(block.decode())
                for key in self.nodes.keys():
                    key.send(AES.encrypt(block, self.nodes[key]))

            except Exception as e:
                node.close()
                del self.nodes[node]
                break


    def run(self):

        print('Testnet initialized...')

        while True:
            try:
                node, _ = self.server.accept()
                node.send(self.pem_pubkey)
                symkey = RSA.decrypt(self.private_key, node.recv(1024))
                self.nodes[node] = symkey
                thread = threading.Thread(target=self.handler, args=(node,))
                thread.start()
            except KeyboardInterrupt:
                break

Testnet().run()