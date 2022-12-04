#!/usr/bin/env python3
"""An ECB/CBC detection oracle"""
# MEANINGLESS JIBBER JABBER

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange

from m08 import ecb_score
from m09 import pkcs7
from m10 import encrypt_aes_cbc

def encryption_oracle(plaintext: bytes) -> bytes:
    plaintext = bytes(randrange(5, 11)) + plaintext + bytes(randrange(5, 11))
    plaintext = pkcs7(plaintext)

    key = get_random_bytes(16)

    if randrange(2) == 0:
        iv = get_random_bytes(16)
        return encrypt_aes_cbc(key, iv, plaintext)

    cypher = AES.new(key, AES.MODE_ECB)
    return cypher.encrypt(plaintext)

def detect_ecb(cyphertext: bytes) -> int:
    return ecb_score(cyphertext, 16) > 0

def main() -> None:
    plaintext = 3 * b"YELLOW SUBMARINE"
    cyphertext = encryption_oracle(plaintext)

    if detect_ecb(cyphertext):
        print("ECB")
    else:
        print("CBC")

if __name__ == "__main__":
    main()
