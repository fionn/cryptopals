#!/usr/bin/env python3
"""Implement repeating-key XOR"""

import textwrap

from m02 import fixed_xor

def repeating_key_xor(key: bytes, message: bytes) -> bytes:
    key = (key * (int(len(message) / len(key)) + 1))[:len(message)]
    return fixed_xor(key, message)

def main() -> None:
    with open("data/05.txt") as file_handle:
        data = file_handle.read().rstrip()

    key = b"ICE"
    message = bytes(data, "utf8")
    cyphertext = repeating_key_xor(key, message)

    print(textwrap.fill(cyphertext.hex(), 75))

if __name__ == "__main__":
    main()
