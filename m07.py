#!/usr/bin/env python3
"""AES in ECB mode"""

from base64 import b64decode

from Crypto.Cipher import AES

def main() -> None:
    with open("data/07.txt") as data:
        cyphertext = b64decode(data.read())

    key = b"YELLOW SUBMARINE"

    cypher = AES.new(key, AES.MODE_ECB)
    cleartext = cypher.decrypt(cyphertext)

    print(cleartext.decode())

if __name__ == "__main__":
    main()
