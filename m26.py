#!/usr/bin/env python3
# CTR bitflipping

from Crypto.Random.random import getrandbits
from m09 import pkcs7
from m18 import aes_ctr

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(userdata, k = RANDOM_KEY):
    prefix = b'comment1=cooking%20MCs;userdata='
    postfix = b';comment2=%20like%20a%20pound%20of%20bacon'
    userdata = userdata.replace(b";", b"").replace(b"=", b"")
    plaintext = pkcs7(prefix + userdata + postfix)
    return aes_ctr(plaintext, k)

def is_admin(cyphertext, k = RANDOM_KEY):
    plaintext = aes_ctr(cyphertext, k)
    plaintext = plaintext.decode(errors = "replace")
    return "admin=true" in plaintext

def ctr_bitflip(cyphertext):
    cyphertext[37] ^= 1
    cyphertext[43] ^= 1
    return cyphertext

if __name__ == "__main__":
    plaintext = bytes(5) + b':admin<true'
    cyphertext = bytearray(oracle(plaintext))
    cyphertext = ctr_bitflip(cyphertext)
    print(is_admin(cyphertext))

