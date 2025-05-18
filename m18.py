#!/usr/bin/env python3
"""Implement CTR, the stream cipher mode"""
# "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby"

from struct import pack
from base64 import b64decode

from Crypto.Cipher import AES

from m02 import fixed_xor

def aes_ctr(cyphertext: bytes, key: bytes, nonce: int = 0) -> bytes:
    c = [cyphertext[16 * i:16 * (i + 1)]
         for i in range(len(cyphertext) // 16 + 1)]

    cypher = AES.new(key, AES.MODE_ECB)

    message = b""
    for ctr, block in enumerate(c):
        keystream = pack("<Qq", nonce, ctr)
        message += fixed_xor(cypher.encrypt(keystream)[:len(block)], block)
    return message

def main() -> None:
    with open("data/18.txt") as data_fd:
        cyphertext = b64decode(data_fd.read().strip())

    key = b"YELLOW SUBMARINE"

    print(aes_ctr(cyphertext, key).decode())

if __name__ == "__main__":
    main()
