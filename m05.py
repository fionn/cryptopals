#!/usr/bin/env python3
# Implement repeating-key XOR

from binascii import hexlify
from sys import argv
import textwrap
from m02 import fixed_xor

def repeating_key_xor(key, message):
    key = (key * (int(len(message) / len(key)) + 1))[:len(message)]
    return fixed_xor(key, message)

if __name__ == "__main__":

    if len(argv) != 1:
        f = argv[1]
    else:
        f = open("data/05.txt", "r").read().rstrip()

    k = "ICE"

    k, f = bytes(k, "utf8"), bytes(f, "utf8")
    c = repeating_key_xor(k, f)

    print(textwrap.fill(hexlify(c).decode(), 75))

