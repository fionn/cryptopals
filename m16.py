#!/usr/bin/env python3
# CBC bitflipping attacks

from Crypto.Random.random import getrandbits
from m09 import pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(userdata, k = RANDOM_KEY):
    prefix = b'comment1=cooking%20MCs;userdata='
    postfix = b';comment2=%20like%20a%20pound%20of%20bacon' 
    userdata = userdata.replace(";", "").replace("=", "")
    plaintext = pkcs7(prefix + bytes(userdata, "ascii") + postfix)
    return encrypt_aes_cbc(plaintext, k, iv = bytes(16))

def is_admin(cyphertext, k = RANDOM_KEY):
    plaintext = decrypt_aes_cbc(cyphertext, k, iv = bytes(16))
    plaintext = plaintext.decode(errors = "replace")
    return "admin=true" in plaintext

if __name__ == "__main__":
    plaintext = '0' * 16 + '00000:admin<true'
    cyphertext = bytearray(oracle(plaintext))

    cyphertext[37] = cyphertext[37] ^ 1
    cyphertext[43] = cyphertext[43] ^ 1

    cyphertext = bytes(cyphertext)
    print(is_admin(cyphertext))

