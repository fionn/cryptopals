#!/usr/bin/env python3
"""Byte-at-a-time ECB decryption (harder)"""

from base64 import b64decode
from typing import Callable

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange

from m09 import pkcs7, de_pkcs7
from m11 import detect_ecb
from m12 import blocksize, len_string

RANDOM_KEY = get_random_bytes(16)
RANDOM_PREFIX = get_random_bytes(randrange(16))

def oracle(plaintext: bytes) -> bytes:
    prefix = RANDOM_PREFIX
    with open("data/12.txt") as data_fd:
        unknown_string = b64decode(data_fd.read())
    plaintext = pkcs7(prefix + plaintext + unknown_string, 16)
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cypher.encrypt(plaintext)

def decrypt(cyphertext: bytes) -> bytes:
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return de_pkcs7(cypher.decrypt(cyphertext))

# pylint: disable=redefined-outer-name
def len_prefix(oracle: Callable[[bytes], bytes]) -> int:
    for i in range(32, 48):
        c = oracle(i * b"A")
        for b in range(len(c) // 16 - 1):
            if c[(b + 1) * 16:(b + 2) * 16] == c[(b + 2) * 16:(b + 3) * 16]:
                return 48 - i + 16 * b
    return 0

def break_ecb(oracle: Callable[[bytes], bytes]) -> bytes:
    bs = blocksize(oracle)
    l = len(oracle(b""))
    prefix_length = len_prefix(oracle)
    string_length = len_string(oracle) - prefix_length

    plaintext = b""
    uc = (l + bs - prefix_length - 1) * b"A"
    while len(plaintext) <= string_length:
        oracle_input = oracle(uc)
        for i in range(127):
            test = uc + plaintext + bytes([i])
            if oracle(test)[l:l + bs] == oracle_input[l:l + bs]:
                uc = uc[1:]
                plaintext += bytes([i])
                break

    return de_pkcs7(plaintext)

def main() -> None:
    assert detect_ecb(oracle(48 * b"A")), "Not ECB"
    print(break_ecb(oracle).decode())

if __name__ == "__main__":
    main()
