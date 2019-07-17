#!/usr/bin/env python3
"""CTR bitflipping"""

from Crypto.Random.random import getrandbits

from m09 import pkcs7
from m18 import aes_ctr

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(userdata: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    userdata = userdata.replace(b";", b"").replace(b"=", b"")
    plaintext = pkcs7(prefix + userdata + postfix)
    return aes_ctr(plaintext, RANDOM_KEY)

def is_admin(cyphertext: bytes) -> bool:
    plaintext = aes_ctr(cyphertext, RANDOM_KEY)
    return "admin=true" in plaintext.decode(errors="replace")

def ctr_bitflip(cyphertext: bytes) -> bytes:
    cyphertext_array = bytearray(cyphertext)
    cyphertext_array[37] ^= 1
    cyphertext_array[43] ^= 1
    return bytes(cyphertext_array)

def main() -> None:
    plaintext = bytes(5) + b":admin<true"
    cyphertext = oracle(plaintext)
    cyphertext = ctr_bitflip(cyphertext)
    print(is_admin(cyphertext))

if __name__ == "__main__":
    main()
