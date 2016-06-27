#!/usr/bin/env python3
# Implement CBC mode

from base64 import b64decode
from Crypto.Cipher import AES
from m02 import fixed_xor

def decrypt_aes_cbc(cyphertext, key, iv):
    cypher = AES.new(key, AES.MODE_ECB)
    blocks = [cyphertext[i:i + len(key)] for i in range(0, len(cyphertext), len(key))]

    vector = iv
    plaintext = bytearray()

    for aesblock in blocks:
        block = cypher.decrypt(aesblock)
        plaintext += fixed_xor(block, vector)
        vector = aesblock

    return plaintext

if __name__ == "__main__":
    cyphertext = b64decode(open("data/10.txt", "r").read())
    
    key = bytes("YELLOW SUBMARINE", "utf8")
    iv = len(key) * bytes([0])

    plaintext = decrypt_aes_cbc(cyphertext, key, iv)
    print(plaintext.decode())

