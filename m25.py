#!/usr/bin/env python3
# Break "random access read/write" AES CTR

from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits
from m02 import fixed_xor
from m18 import aes_ctr

def edit(cyphertext, key, offset, newtext):
    plaintext = aes_ctr(cyphertext, key)
    plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    return aes_ctr(plaintext, key)

def break_rarw(cyphertext):
    edited_cyphertext = edit(cyphertext, key, 0, bytes(len(cyphertext)))
    return fixed_xor(cyphertext, edited_cyphertext)

if __name__ == "__main__":
    c = b64decode(open("data/25.txt", "r").read())
    k = bytes("YELLOW SUBMARINE", "ascii")
    cypher = AES.new(k, AES.MODE_ECB)
    plaintext = cypher.decrypt(c)

    key = bytes(getrandbits(8) for i in range(16))
    cyphertext = aes_ctr(plaintext, key)

    rarw_plaintext = break_rarw(cyphertext)
    assert rarw_plaintext == plaintext
    print(rarw_plaintext.decode())

