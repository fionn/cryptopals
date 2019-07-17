#!/usr/bin/env python3
"""CBC bitflipping attacks"""

from Crypto.Random.random import getrandbits

from m09 import pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(userdata: bytes) -> bytes:
    key = RANDOM_KEY
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    userdata = userdata.replace(b";", b"").replace(b"=", b"")
    plaintext = pkcs7(prefix + userdata + postfix)
    return encrypt_aes_cbc(plaintext, key, iv=bytes(16))

def is_admin(cyphertext: bytes, key: bytes = RANDOM_KEY) -> bool:
    plaintext = decrypt_aes_cbc(cyphertext, key, iv=bytes(16))
    plaintext_str = plaintext.decode(errors="replace")
    return "admin=true" in plaintext_str

def cbc_bitflip(cyphertext: bytes) -> bytes:
    cyphertext_array = bytearray(cyphertext)
    cyphertext_array[37] ^= 1
    cyphertext_array[43] ^= 1
    return bytes(cyphertext_array)

def main() -> None:
    plaintext = bytes(16) + b"00000:admin<true"
    cyphertext = oracle(plaintext)
    cyphertext = cbc_bitflip(cyphertext)
    print(is_admin(cyphertext))

if __name__ == "__main__":
    main()
