#!/usr/bin/env python3
"""Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection"""

from Crypto.Random.random import getrandbits

from m09 import pkcs7, de_pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc
from m28 import SHA1
from m33 import DHPeer

class DHProtocolPeer(DHPeer):

    def __init__(self, p: int, g: int, peer: "DHProtocolPeer" = None) -> None:
        super().__init__(p, g)
        self.peer: "DHProtocolPeer" = peer
        self.A = self.public_key()
        self._B: int = None
        self.received_cyphertext: bytes = None
        self.received_message: bytes = None

    def init_peer(self) -> "DHProtocolPeer":
        self.peer = self.__class__(self.p, self.g, self)
        return self.peer

    def swap_peer(self, peer: "DHProtocolPeer") -> None:
        self.peer = peer
        self.receive_pubkey(peer.A)

    def send_pubkey(self) -> None:
        self.peer.receive_pubkey(self.A)

    def receive_pubkey(self, B: int) -> None:
        self._B = B

    def _aes_key(self) -> bytes:
        s = self.session_key(self._B)
        return SHA1(s.to_bytes(s.bit_length() // 8 + 1, "big")).digest()[:16]

    def send_message(self, message: bytes) -> None:
        iv = bytes(getrandbits(8) for i in range(16))
        cyphertext = encrypt_aes_cbc(self._aes_key(), iv, pkcs7(message))
        self.peer.receive_message(cyphertext + iv)

    def receive_message(self, cyphertext: bytes) -> None:
        self.received_cyphertext = cyphertext
        iv = cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(self._aes_key(), iv,
                                           cyphertext[:-16]))
        self.received_message = message

    def reply(self) -> None:
        self.send_message(self.received_message)

    def forward_and_decrypt(self, key: bytes) -> bytes:
        key = SHA1(key).digest()[:16]
        iv = self.received_cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(key, iv,
                                           self.received_cyphertext[:-16]))
        self.peer.receive_message(self.received_cyphertext)
        return message

def dh_protocol(p: int, g: int, message: bytes) -> bytes:
    alice = DHProtocolPeer(p, g)
    bob = alice.init_peer()
    alice.send_pubkey()
    bob.send_pubkey()

    alice.send_message(message)
    bob.reply()

    return alice.received_message

def dh_parameter_injection(p: int, g: int, message: bytes) -> bytes:
    alice = DHProtocolPeer(p, g)
    mallory = alice.init_peer()
    alice.send_pubkey()
    mallory.A = mallory.p  # parameter injection
    mallory.send_pubkey()

    bob = mallory.init_peer()
    mallory.send_pubkey()
    bob.send_pubkey()

    intercepted = []
    alice.send_message(message)
    mallory_key = bytes(1)  # p^a % p = 0
    intercepted.append(mallory.forward_and_decrypt(mallory_key))

    bob.reply()
    mallory.swap_peer(alice)
    intercepted.append(mallory.forward_and_decrypt(mallory_key))

    intercepted_set = set(intercepted)
    if len(intercepted_set) != 1:
        raise RuntimeError("Messages are not identical")
    return intercepted_set.pop()

def main() -> None:
    with open("data/33.txt", "r", encoding="ascii") as fd:
        p = int(fd.read().replace("\n", ""), 16)
    g = 2

    message = b"Attack at dawn"
    received_message = dh_protocol(p, g, message)
    assert received_message == message

    intercepted = dh_parameter_injection(p, g, message)

    assert intercepted == message
    print(message.decode())

if __name__ == "__main__":
    main()
