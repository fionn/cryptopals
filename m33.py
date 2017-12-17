#!/usr/bin/env python3
# Implement Diffie-Hellman

from Crypto.Random.random import randrange

class DHPeer:

    def __init__(self, p, g):
        self.p = p
        self.g = g
        self._a = randrange(p)

    def public_key(self):
        return pow(self.g, self._a, self.p)

    def session_key(self, B):
        return pow(B, self._a, self.p)

def dh_key_exchange(p, g):
    alice = DHPeer(p, g)
    bob = DHPeer(p, g)

    A = alice.public_key()
    B = bob.public_key()

    s_a = alice.session_key(B)
    s_b = bob.session_key(A)

    return s_a, s_b

if __name__ == "__main__":
    p = int(open("data/33.txt", "r").read().replace("\n", ""), 16)
    g = 2

    s_a, s_b = dh_key_exchange(p, g)
    assert s_a == s_b
    print(s_a)

