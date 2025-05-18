#!/usr/bin/env python3
"""Detect single-character XOR"""
# "Now that the party is jumping"

from m03 import break_single_byte_xor, most_probable

def find_xored_message(cyphertext: list[bytes]) -> bytes:
    """Detect and decrypt single-character xored message"""
    candidates = []
    for line in cyphertext:
        line = break_single_byte_xor(line)
        if line:
            candidates.append(line)
    return most_probable(candidates)

def main() -> None:
    with open("data/04.txt") as f:
        data = [bytes.fromhex(line) for line in f.read().splitlines()]

    print(find_xored_message(data).decode())

if __name__ == "__main__":
    main()
