#!/usr/bin/env python3
"""RSA parity oracle"""

import base64

import m39

class RSAParityOracle:

    def __init__(self, size: int = 1024, e: int = 3) -> None:
        keypair = m39.keygen(size, e)
        self.pubkey = keypair.public
        self._private_key = keypair.private

    def is_even(self, c: int) -> bool:
        """Parity of plaintext"""
        return m39.decrypt_int(c, self._private_key) % 2 == 0

def parity_oracle_attack(c: int, oracle: RSAParityOracle) -> bytes:
    """Binary search to decrypt via parity oracle"""
    n = oracle.pubkey.modulus
    coefficient = m39.encrypt_int(2, oracle.pubkey)
    a, b = 0, 1

    # We operate in the interval [0, 1] instead of [0, n] to avoid
    # dealing with large floating point division.

    for i in range(1, n.bit_length() + 1):
        c = (coefficient * c) % n
        interval_width = b - a
        a *= 2
        b *= 2
        if not oracle.is_even(c):
            a += interval_width
        else:
            b -= interval_width
        print(m39.to_bytes(n * b // 2 ** i))

    return m39.to_bytes(n * b // 2 ** n.bit_length())

def main() -> None:
    with open("data/46.txt") as fd:
        m = base64.b64decode(fd.read())

    oracle = RSAParityOracle()
    c = m39.encrypt(m, oracle.pubkey)

    assert m == parity_oracle_attack(c, oracle)

if __name__ == "__main__":
    main()
