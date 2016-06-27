#!/usr/bin/env python3
# Detect single-character XOR -- "Now that the party is jumping"

from m03 import break_single_byte_xor, mostprobable

def findxoredstring(cyphertext):
    candidates = []
    for line in cyphertext:
        line = break_single_byte_xor(line)
        #if line != None:
        candidates.append(line)
    return mostprobable(candidates)

if __name__ == "__main__":

    f = open("data/04.txt", "r").read().splitlines()
    f = [bytes.fromhex(line) for line in f]

    print(findxoredstring(f).decode())
