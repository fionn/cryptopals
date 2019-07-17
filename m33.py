#!/usr/bin/env python3
"""Implement Diffie-Hellman"""

from typing import Tuple

from Crypto.Random.random import randrange

class DHPeer:

    def __init__(self, p: int, g: int) -> None:
        self.p = p
        self.g = g
        self._a = randrange(p)

    def public_key(self) -> int:
        return pow(self.g, self._a, self.p)

    def session_key(self, B: int) -> int:
        return pow(B, self._a, self.p)

def dh_key_exchange(p: int, g: int) -> Tuple[int, int]:
    alice = DHPeer(p, g)
    bob = DHPeer(p, g)

    A = alice.public_key()
    B = bob.public_key()

    s_a = alice.session_key(B)
    s_b = bob.session_key(A)

    return s_a, s_b

def main() -> None:
    with open("data/33.txt", "r") as p_file:
        p = int(p_file.read().replace("\n", ""), 16)
    g = 2

    s_a, s_b = dh_key_exchange(p, g)
    assert s_a == s_b
    print(s_a)

if __name__ == "__main__":
    main()
