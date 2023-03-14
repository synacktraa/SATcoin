import threading
import socket, re, time

from typing import Tuple

from utils.asymmetric import RSA
from utils.symmetric import AES
from utils.cert import Certificate, InvalidSignature
from utils.wallet import Wallet


class Client(Wallet):

    def __init__(self) -> None:

        self.symkey = AES.gen_key()

        self.prikey = RSA.load_mem_private_key()
        self.pubkey = RSA.load_mem_public_key(self.prikey)
        self.pubkey_pem = RSA.ret_pem_public_key(self.pubkey)

        super().__init__(self.symkey)

    def parse(self, message: str) -> dict | None:

        regex = r"^(transfer) (0x[0-9a-fA-F]{20}):([0-9]+(?:[.][0-9]+)?)$"
        match = re.match(regex, message)
        if match:
            if match.group(2) == self.address:
                print("[wallet] self transfer not allowed.")
                return None
            
            return {
                f"{match.group(1)}": {
                    'address': match.group(2), 
                    'coins': match.group(3)
                }
            }

        return None

    def transact(self, address: Tuple[str, int]):
        
        CHUNKS = 100
        transaction = f"{self.address} -> {process['address']}: {process['coins']}".encode('utf-8')
        signature = RSA.sign(private_key=self.prikey, message=transaction)

        miner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        miner.connect(("127.0.0.1", 59001))
        miner.send(self.pubkey_pem)
        miner_pubkey = RSA.load_mem_public_key(miner.recv(1024))
        miner.send(RSA.encrypt(miner_pubkey, transaction))

        for i in range(0, len(signature), CHUNKS):
            chunk = RSA.encrypt(miner_pubkey, signature[i:i+CHUNKS])
            time.sleep(0.5)
            miner.send(chunk)

        transaction_state = miner.recv(1024).decode('utf-8')
        if transaction_state == "True":
                peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer.connect(address)
                peer.send(f'{self.address}: {process["coins"]}'.encode('utf-8'))
        else:
            print(transaction_state)

    def handler() -> None:

        global mapped_address
        while True:
            try:
                enc = server.recv(1024)
                message = AES.decrypt(enc, symkey).decode('utf-8')
                if message == "alias?":
                    server.send(AES.encrypt(alias.encode('utf-8'), symkey))
                elif message == "address?":
                    server.send(AES.encrypt(f"address {address[0]}:{address[1]}".encode('utf-8'), symkey))
                else:
                    if message.startswith("[server]"):
                        print(message)
                    else:
                        var = message.split()
                        addr = var[1].split(':')
                        with lock:
                            mapped_address[var[0]] = (addr[0], int(addr[1]))
                        transact(mapped_address[var[0]])

            except Exception as exc:
                print(exc)
                server.close()
                break



    def query() -> None:

        global process
        while True:
            message = input().strip()
            with lock:
                process = parse(message=message)
            if process != None:
                server.send(AES.encrypt(f"connect: {process['name']}".encode('utf-8'), symkey))

                
                

    send_thread = threading.Thread(target=query)
    receive_thread = threading.Thread(target=handler)
    send_thread.start()
    receive_thread.start()

