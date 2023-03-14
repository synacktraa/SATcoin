import decimal
import hashlib
import json
import re
from socket import (
    socket, 
    AF_INET, 
    SOCK_STREAM
)
from typing import List, Dict

import ecdsa

from asymmetric import RSA
from symmetric import AES 

class Wallet:

    reduce = lambda x: x.rstrip('0').rstrip('.') if '.' in x else x

    def __init__(self, symkey) -> None:

        self.symkey = symkey
        self.signing_key = ecdsa.SigningKey.generate(
            curve=ecdsa.SECP256k1
        )
        self.verifying_key = self.signing_key.verifying_key

        self.balance = "0"
        self.nonce = 0
        keccak = hashlib.new('sha3_256')
        keccak.update(self.verifying_key.to_string())
        self.address = f"0x{keccak.digest()[-20:].hex()}"

        # self.tn_socket = socket(AF_INET, SOCK_STREAM)
        # self.tn_socket.connect(("127.0.0.1", 59003))
        # self.tn_pubkey = RSA.load_mem_public_key(self.tn_socket.recv(1024))
        # self.tn_socket.send(RSA.encrypt(self.tn_pubkey, self.symkey))
        
        self.portfolio: List[Dict[str,str]] = list()

    def sign(self, message: bytes):
        return self.signing_key.sign(message)

    def check(self):
        return f"{self.balance} SAT"

    def update(self, satCoins: str) -> bool:

        # check = False if satCoins.split('-')[0] == "-" else True
        satCoins = Wallet.reduce(satCoins)
        precision = max(len(self.balance), len(satCoins.split('-')[-1]))

        decimal.getcontext().prec = precision
        cache = Wallet.reduce(
            str(decimal.Decimal(self.balance) + decimal.Decimal(satCoins))
        )

        if not re.match(r"^(?:0|-.*)$", cache): #checks if balance is 0 or less
            self.balance = cache
            return True  
        else: 
            # print("[wallet] not sufficient funds!")
            return False

    def fetch_latest_funds(self):
        while True:
            block = json.loads(
                AES.decrypt(
                    self.tn_socket.recv(2048), self.symkey
                ).decode()
            )
            if block['receiver'] == self.address:
                self.update(block['funds'])


    @staticmethod
    def load_verifying_key(verifying_key):
        return ecdsa.VerifyingKey.from_string(verifying_key, curve=ecdsa.SECP256k1)


wallet = Wallet("symkey")
print(wallet.check())
wallet.update("1.444")
print(wallet.check())
wallet.update("-0.300")
print(wallet.check())
wallet.update("-1.146")
print(wallet.check())
wallet.update("0.23")
print(wallet.check())
wallet.update("-1.375")
print(wallet.check())
