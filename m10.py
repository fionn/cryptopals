#!/usr/bin/env python3
# Implement CBC mode

from base64 import b64decode
from Crypto.Cipher import AES
from m02 import fixed_xor
from m09 import de_pkcs7

def encrypt_aes_cbc(plaintext, key, iv):
    cypher = AES.new(key, AES.MODE_ECB)
    blocks = [plaintext[i:i + len(key)] for i in range(0, len(plaintext), len(key))]

    vector = iv
    cyphertext = b''
    for block in blocks:
        block = fixed_xor(block, vector)
        block = cypher.encrypt(block)
        cyphertext += block
        vector = block

    return cyphertext

def decrypt_aes_cbc(cyphertext, key, iv):
    cypher = AES.new(key, AES.MODE_ECB)
    blocks = [cyphertext[i:i + len(key)] for i in range(0, len(cyphertext), len(key))]

    vector = iv
    plaintext = b''
    for aesblock in blocks:
        block = cypher.decrypt(aesblock)
        plaintext += fixed_xor(block, vector)
        vector = aesblock

    return de_pkcs7(plaintext)

if __name__ == "__main__":
    cyphertext = b64decode(open("data/10.txt", "r").read())
    
    key = bytes("YELLOW SUBMARINE", "utf8")
    iv = bytes(len(key))

    plaintext = decrypt_aes_cbc(cyphertext, key, iv)
    print(plaintext.decode())

