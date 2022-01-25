#!/usr/bin/env python3
"""Break repeating-key XOR"""
# "Terminator X: Bring the noise"

import base64

from m02 import fixed_xor
from m03 import break_single_byte_xor
from m05 import repeating_key_xor

def hamming_distance(s1: bytes, s2: bytes) -> int:
    if len(s1) != len(s2):
        raise IndexError("Arguments must be the same size")
    return sum([bin(s1[i] ^ s2[i]).count("1") for i in range(len(s1))])

def find_keysize(cyphertext: bytes) -> int:
    bound = float("inf")
    for k in range(2, 41):
        normal_distance = 0.0
        n_max = int(len(cyphertext) / k) - 2
        for n in range(0, n_max):
            b1 = cyphertext[k * n:k * (n + 1)]
            b2 = cyphertext[k * (n + 1):k * (n + 2)]
            normal_distance += hamming_distance(b1, b2) / (k * n_max)
        if normal_distance < bound:
            bound = normal_distance
            keysize = k
    return keysize

def key(cyphertext: bytes) -> bytes:
    keysize = find_keysize(cyphertext)
    blocks = [cyphertext[i:i + keysize]
              for i in range(0, len(cyphertext), keysize)]
    blocks = [bytes(x) for x in zip(*blocks[0:-1], strict=True)]
    plaintext = bytes([break_single_byte_xor(x)[0] for x in blocks])
    return fixed_xor(plaintext, cyphertext[:len(plaintext)])

def break_repeating_key_xor(cyphertext: bytes) -> bytes:
    return repeating_key_xor(key(cyphertext), cyphertext)

def main() -> None:
    with open("data/06.txt", "r") as data:
        cyphertext = base64.b64decode(data.read())
    print(break_repeating_key_xor(cyphertext).decode())

if __name__ == "__main__":
    main()
