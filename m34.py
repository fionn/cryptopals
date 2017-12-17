#!/usr/bin/env python3
# Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

from Crypto.Random.random import getrandbits
from m09 import pkcs7, de_pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc
from m28 import SHA1
from m33 import DHPeer

class DHProtocolPeer(DHPeer):

    def __init__(self, p, g, peer = None):
        super().__init__(p, g)
        self.peer = peer or self.__class__
        self.A = self.public_key()
        self._B = None
        self.received_cyphertext = None
        self.received_message = None

    def init_peer(self):
        self.peer = self.peer(self.p, self.g, self)
        self.send_pubkey()
        return self.peer

    def new_peer(self, peer = None):
        if not peer:
            self.peer = self.__class__
        else:
            self.peer = peer

    def send_pubkey(self):
        self.peer.receive_pubkey(self.A)

    def receive_pubkey(self, B):
        self._B = B

    def aes_key(self):
        s = self.session_key(self._B)
        return SHA1(s.to_bytes(s.bit_length() // 8 + 1, "big")).digest()[:16]

    def send_message(self, message):
        iv = bytes(getrandbits(8) for i in range(16))
        cyphertext = encrypt_aes_cbc(pkcs7(message), self.aes_key(), iv)
        self.peer.receive_message(cyphertext + iv)

    def receive_message(self, cyphertext):
        self.received_cyphertext = cyphertext
        iv = cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(cyphertext[:-16], self.aes_key(), iv))
        self.received_message = message

    def reply(self):
        self.send_message(self.received_message)

    def forward_and_decrypt(self, key):
        key = SHA1(key).digest()[:16]
        iv = self.received_cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(self.received_cyphertext[:-16], key, iv))
        self.peer.receive_message(self.received_cyphertext)
        return message

def dh_protocol(p, g):
    alice = DHProtocolPeer(p, g)
    bob = alice.init_peer()
    bob.send_pubkey()

    message = b"foo"
    alice.send_message(b"foo")
    bob.reply()

    assert alice.received_message == message

def dh_parameter_injection(p, g):
    alice = DHProtocolPeer(p, g)

    mallory = alice.init_peer()
    mallory.A = mallory.p
    mallory.new_peer()

    bob = mallory.init_peer()
    # this sets mallory._B = bob.A
    bob.send_pubkey()

    mallory.new_peer(alice)
    # this sets alice._B = mallory.p
    mallory.send_pubkey()

    intercepted = []
    alice.send_message(b"Attack at dawn")
    mallory.new_peer(bob)
    mallory_key = bytes(1) # p^a % p = 0
    intercepted.append(mallory.forward_and_decrypt(mallory_key))

    bob.reply()
    mallory.new_peer(alice)
    intercepted.append(mallory.forward_and_decrypt(mallory_key))

    return set(intercepted), alice.received_message

if __name__ == "__main__":
    p = int(open("data/33.txt", "r").read().replace("\n", ""), 16)
    g = 2

    dh_protocol(p, g)

    intercepted, message = dh_parameter_injection(p, g)

    assert len(intercepted) == 1
    assert intercepted.pop() == message
    print(message.decode())

