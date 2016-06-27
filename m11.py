#!/usr/bin/env python3
# An ECB/CBC detection oracle

from Crypto.Random.random import randrange, getrandbits
from Crypto.Cipher import AES
from m08 import ecb_score
from m09 import pkcs7
from m10 import encrypt_aes_cbc

def encryption_oracle(plaintext):
    plaintext = bytes(randrange(5, 11)) + plaintext + bytes(randrange(5, 11))
    plaintext = pkcs7(plaintext, 16)

    key = bytes(getrandbits(8) for i in range(16))

    if randrange(0,2) == 0:
        iv = bytes(getrandbits(8) for i in range(16))
        cyphertext = encrypt_aes_cbc(plaintext, key, iv)
        #print("CBC")
    else:
        cypher = AES.new(key, AES.MODE_ECB)
        cyphertext = cypher.encrypt(plaintext)
        #print("ECB")

    return cyphertext

def detect_ecb_or_cbc(cyphertext):
    if ecb_score(cyphertext, 16) > 0:
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":
    plaintext = bytes("YELLOW SUBMARINE", "utf8") * 3
    cyphertext = encryption_oracle(plaintext)

    print(detect_ecb_or_cbc(cyphertext))
    
