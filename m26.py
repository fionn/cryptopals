#!/usr/bin/env python3
# CTR bitflipping

from Crypto.Random.random import getrandbits
from m09 import pkcs7
from m18 import aes_ctr

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(userdata, k = RANDOM_KEY):
    prefix = b'comment1=cooking%20MCs;userdata='
    postfix = b';comment2=%20like%20a%20pound%20of%20bacon'
    userdata = userdata.replace(";", "").replace("=", "")
    plaintext = pkcs7(prefix + bytes(userdata, "ascii") + postfix)
    return aes_ctr(plaintext, k)

def is_admin(cyphertext, k = RANDOM_KEY):
    plaintext = aes_ctr(cyphertext, k)
    plaintext = plaintext.decode(errors = "replace")
    return "admin=true" in plaintext

if __name__ == "__main__":
    plaintext = '0' * 5 + ':admin<true'
    cyphertext = bytearray(oracle(plaintext))

    cyphertext[37] ^= 1
    cyphertext[43] ^= 1

    print(is_admin(cyphertext))

