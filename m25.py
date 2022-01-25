#!/usr/bin/env python3
"""Break "random access read/write" AES CTR"""

from base64 import b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from m02 import fixed_xor
from m18 import aes_ctr

RANDOM_KEY = get_random_bytes(16)

def edit(cyphertext: bytes, key: bytes, offset: int, new_text: bytes) -> bytes:
    plaintext = aes_ctr(cyphertext, key)
    plaintext = plaintext[:offset] + new_text \
                + plaintext[offset + len(new_text):]
    return aes_ctr(plaintext, key)

def break_rarw(cyphertext: bytes) -> bytes:
    edited_cyphertext = edit(cyphertext, RANDOM_KEY, 0, bytes(len(cyphertext)))
    return fixed_xor(cyphertext, edited_cyphertext)

def main() -> None:
    with open("data/25.txt", "r") as f:
        c = b64decode(f.read())
    k = b"YELLOW SUBMARINE"
    cypher = AES.new(k, AES.MODE_ECB)
    plaintext = cypher.decrypt(c)
    cyphertext = aes_ctr(plaintext, RANDOM_KEY)

    rarw_plaintext = break_rarw(cyphertext)
    assert rarw_plaintext == plaintext
    print(rarw_plaintext.decode())

if __name__ == "__main__":
    main()
