#!/usr/bin/env python3
# Detect single-character XOR -- "Now that the party is jumping"

from m03 import break_single_byte_xor, mostprobable

if __name__ == "__main__":

    f = open("data/04.txt", "r").read().splitlines()

    candidates = []
    for line in f:
        line = break_single_byte_xor(line)
        if line != None:
            candidates.append(line)

    print(mostprobable(candidates))

