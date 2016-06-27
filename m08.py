#!/usr/bin/env python3
# Detect AES in ECB mode

from binascii import hexlify

def ecb_score(cyphertext, k):
    duplicates = 0
    blocks = [cyphertext[i:i + k] for i in range(0, len(cyphertext), k)]
    for i in range(0, len(blocks)):
        for j in range(i + 1, len(blocks)):
            if blocks[i] == blocks[j]:
                duplicates += 1
    return duplicates

def detect_ecb(candidates, blocksize):
    ecb_candidate = None
    bound = 0
    for cyphertext in candidates:
        if ecb_score(cyphertext, blocksize) > bound:
            bound = ecb_score(cyphertext, blocksize)
            ecb_candidate = cyphertext
    return ecb_candidate

if __name__ == "__main__":
    f = open("data/08.txt", "r").read().splitlines()
    f = [bytes.fromhex(cyphertext) for cyphertext in f]

    blocksize = 16

    ecb_encrypted = detect_ecb(f, blocksize)
    index = f.index(ecb_encrypted)
   
    print("element", str(index) + ":")
    print(hexlify(ecb_encrypted).decode())

