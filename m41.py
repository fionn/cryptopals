#!/usr/bin/env python3
"""Implement unpadded message recovery oracle"""

import time

from Crypto.Random.random import randint

import m39

# pylint: disable=too-few-public-methods
class DecryptionServer:

    def __init__(self, size: int = 1024, e: int = 3) -> None:
        self.decrypted: set[int] = set()
        self.public_key, self._private_key = m39.keygen(size, e)

    def decrypt(self, c: int) -> bytes:
        if hash(c) not in self.decrypted:
            self.decrypted.add(hash(c))
            return m39.decrypt(c, self._private_key)
        raise RuntimeError("Already decrypted given ciphertext")

def recover_message(c: int, server: DecryptionServer) -> bytes:
    """Recover plaintext via homeomorphic transformation"""
    e, n = server.public_key
    # We use a random number so we can perform repeated decryptions
    s = randint(2, 4096)

    c_prime = pow(s, e, n) * c % n
    p_prime = m39.to_int(server.decrypt(c_prime))

    s_inverse = m39.invmod(s, n)
    p = p_prime * s_inverse % n

    return m39.to_bytes(p)

def main() -> None:
    server = DecryptionServer()
    m_map = {"time": int(time.time()), "social": "555-55-5555"}
    m = str(m_map).encode()

    # Generate ciphertext and taint it so the server
    # won't decrypt it again.
    c = m39.encrypt(m, server.public_key)
    server.decrypt(c)

    m_prime = recover_message(c, server)
    print(m_prime.decode())
    assert m == m_prime

if __name__ == "__main__":
    main()
