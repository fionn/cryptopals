#!/usr/bin/env python3
# AES in ECB mode

from base64 import b64decode
from Crypto.Cipher import AES

if __name__ == "__main__":
    cyphertext = b64decode(open("data/07.txt", "r").read())
    key = bytes("YELLOW SUBMARINE", "utf8")

    cypher = AES.new(key, AES.MODE_ECB)
    cleartext = cypher.decrypt(cyphertext)

    print(cleartext.decode())

