#!/usr/bin/env python3
"""Byte-at-a-time ECB decryption (simple)"""

# pylint: disable=redefined-outer-name

from base64 import b64decode
from typing import Callable

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from m09 import pkcs7, de_pkcs7
from m11 import detect_ecb

RANDOM_KEY = get_random_bytes(16)

def oracle(plaintext: bytes) -> bytes:
    with open("data/12.txt", "r") as data_handle:
        unknown_string = b64decode(data_handle.read())
    plaintext = pkcs7(plaintext + unknown_string, 16)
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cypher.encrypt(plaintext)

def blocksize(oracle: Callable[[bytes], bytes]) -> int:
    smallest = len(oracle(b""))
    for i in range(256):
        test = i * b"A"
        if len(oracle(test)) - smallest > 0:
            return len(oracle(test)) - smallest
    raise RuntimeError("Can't find oracle blocksize")

def len_string(oracle: Callable[[bytes], bytes]) -> int:
    l = len(oracle(b""))
    bs = blocksize(oracle)
    for i in range(1, bs + 1):
        if l < len(oracle(i * b"A")):
            return l - i
    raise RuntimeError("Can't find oracle string length")

def break_ecb(oracle: Callable[[bytes], bytes]) -> bytes:
    bs = blocksize(oracle)
    l = len(oracle(b""))
    string_length = len_string(oracle)

    plaintext = b""
    prefix = (l + bs - 1) * b"A"
    while len(plaintext) <= string_length:
        oracle_prefix = oracle(prefix)
        for i in range(127):
            test = prefix + plaintext + bytes([i])
            if oracle(test)[l:l + bs] == oracle_prefix[l:l + bs]:
                prefix = prefix[1:]
                plaintext += bytes([i])
                break

    return de_pkcs7(plaintext)

def main() -> None:
    if not detect_ecb(oracle(64 * b"A")):
        print("Not ECB")
        raise SystemExit

    print(break_ecb(oracle).decode())

if __name__ == "__main__":
    main()
