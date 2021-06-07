#!/usr/bin/env python3
"""Detect AES in ECB mode"""

from typing import Optional

def ecb_score(cyphertext: bytes, k: int) -> int:
    duplicates = 0
    blocks = [cyphertext[i:i + k] for i in range(0, len(cyphertext), k)]
    for i in range(0, len(blocks)):  # pylint: disable=consider-using-enumerate
        for j in range(i + 1, len(blocks)):
            if blocks[i] == blocks[j]:
                duplicates += 1
    return duplicates

def detect_ecb(candidates: list[bytes], blocksize: int) -> Optional[bytes]:
    ecb_candidate = None
    bound = 0
    for cyphertext in candidates:
        if ecb_score(cyphertext, blocksize) > bound:
            bound = ecb_score(cyphertext, blocksize)
            ecb_candidate = cyphertext
    return ecb_candidate

def main() -> None:
    with open("data/08.txt", "r") as f:
        data = [bytes.fromhex(ct) for ct in f.read().splitlines()]

    blocksize = 16
    ecb_encrypted = detect_ecb(data, blocksize)

    if ecb_encrypted:
        index = data.index(ecb_encrypted)
        print("element", str(index) + ":")
        print(ecb_encrypted.hex())

if __name__ == "__main__":
    main()
