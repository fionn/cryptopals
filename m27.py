#!/usr/bin/env python3
# Recover the key from CBC with IV = Key

from Crypto.Random.random import getrandbits
from m02 import fixed_xor
from m09 import pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def ascii_compliant(plaintext):
    for b in plaintext:
        if b > 127:
            return False
    return True

def oracle(cyphertext, k = RANDOM_KEY):
    plaintext = decrypt_aes_cbc(cyphertext, k, iv = k)
    if not ascii_compliant(plaintext):
        return plaintext
    return None

def bad_cbc_encryption(plaintext, k = RANDOM_KEY):
    return encrypt_aes_cbc(pkcs7(plaintext), k, iv = k)

def cbc_iv_key(cyphertext):
    c_prime = cyphertext[:16] + bytes(16) + cyphertext[:16]
    p_prime = oracle(c_prime)
    if p_prime:
        return fixed_xor(p_prime[0:16], p_prime[32:48])
    return None

if __name__ == "__main__":
    plaintext = b'Attack at dawn! ' * 3
    cyphertext = bad_cbc_encryption(plaintext)
    key = cbc_iv_key(cyphertext)
    assert key == RANDOM_KEY
    print(key)

