#!/usr/bin/env python3
"""CTR bitflipping"""

from Crypto.Random import get_random_bytes

from m09 import pkcs7
from m16 import cbc_bitflip as ctr_bitflip
from m18 import aes_ctr

RANDOM_KEY = get_random_bytes(16)

def oracle(userdata: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    userdata = userdata.replace(b";", b"").replace(b"=", b"")
    plaintext = pkcs7(prefix + userdata + postfix)
    return aes_ctr(plaintext, RANDOM_KEY)

def is_admin(cyphertext: bytes) -> bool:
    plaintext = aes_ctr(cyphertext, RANDOM_KEY)
    return "admin=true" in plaintext.decode(errors="replace")

def main() -> None:
    plaintext = bytes(5) + b":admin<true"
    cyphertext = oracle(plaintext)
    cyphertext = ctr_bitflip(cyphertext)
    print(is_admin(cyphertext))

if __name__ == "__main__":
    main()
