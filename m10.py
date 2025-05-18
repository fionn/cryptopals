#!/usr/bin/env python3
"""Implement CBC mode"""

from base64 import b64decode

from Crypto.Cipher import AES

from m02 import fixed_xor
from m09 import de_pkcs7

def encrypt_aes_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cypher = AES.new(key, AES.MODE_ECB)
    blocks = [plaintext[i:i + len(key)]
              for i in range(0, len(plaintext), len(key))]

    vector = iv
    cyphertext = b""
    for block in blocks:
        block = fixed_xor(block, vector)
        block = cypher.encrypt(block)
        cyphertext += block
        vector = block

    return cyphertext

def decrypt_aes_cbc(key: bytes, iv: bytes, cyphertext: bytes) -> bytes:
    cypher = AES.new(key, AES.MODE_ECB)
    blocks = [cyphertext[i:i + len(key)]
              for i in range(0, len(cyphertext), len(key))]

    vector = iv
    plaintext = b""
    for aesblock in blocks:
        block = cypher.decrypt(aesblock)
        plaintext += fixed_xor(block, vector)
        vector = aesblock

    return plaintext

def main() -> None:
    with open("data/10.txt") as data:
        cyphertext = b64decode(data.read())

    key = b"YELLOW SUBMARINE"
    iv = bytes(len(key))

    plaintext = de_pkcs7(decrypt_aes_cbc(key, iv, cyphertext))
    print(plaintext.decode())

if __name__ == "__main__":
    main()
