#!/usr/bin/env python3
"""Detect single-character XOR"""
# "Now that the party is jumping"

from m03 import break_single_byte_xor, mostprobable

def findxoredstring(cyphertext: list[bytes]) -> bytes:
    candidates = []
    for line in cyphertext:
        line = break_single_byte_xor(line)
        if line:
            candidates.append(line)
    return mostprobable(candidates)

def main() -> None:
    with open("data/04.txt", "r") as f:
        data = [bytes.fromhex(line) for line in f.read().splitlines()]

    print(findxoredstring(data).decode())

if __name__ == "__main__":
    main()
