#!/usr/bin/env python3
"""Recover the key from CBC with IV = Key"""

from typing import Optional

from Crypto.Random.random import getrandbits

from m02 import fixed_xor
from m09 import pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def ascii_compliant(plaintext: bytes) -> bool:
    for b in plaintext:
        if b > 127:
            return False
    return True

def oracle(cyphertext: bytes) -> Optional[bytes]:
    key = RANDOM_KEY
    plaintext = decrypt_aes_cbc(key, iv=key, cyphertext=cyphertext)
    if not ascii_compliant(plaintext):
        return plaintext
    return None

def bad_cbc_encryption(plaintext: bytes) -> bytes:
    key = RANDOM_KEY
    return encrypt_aes_cbc(key, iv=key, plaintext=pkcs7(plaintext))

def cbc_iv_key(cyphertext: bytes) -> Optional[bytes]:
    c_prime = cyphertext[:16] + bytes(16) + cyphertext[:16]
    p_prime = oracle(c_prime)
    if p_prime:
        return fixed_xor(p_prime[0:16], p_prime[32:48])
    return None

def main() -> None:
    plaintext = 3 * b"Attack at dawn! "
    cyphertext = bad_cbc_encryption(plaintext)
    key = cbc_iv_key(cyphertext)
    assert key == RANDOM_KEY
    print(key)

if __name__ == "__main__":
    main()
