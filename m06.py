#!/usr/bin/env python3
# Break repeating-key XOR -- "Terminator X: Bring the noise"

import base64
import m02 # fixed_xor
import m03 # break_single_byte_xor
import m05 # repeating_key_xor

def d_H(s1, s2):
    assert len(s1) == len(s2)
    return sum([bin(s1[i] ^ s2[i]).count("1") for i in range(len(s1))])

def findkeysize(cyphertext):
    bound = float("inf")
    for k in range(2, 41):
        normaldistance = 0
        n_max = int(len(cyphertext) / k) - 2
        for n in range(0, n_max):
            b1, b2 = cyphertext[k * n:k * (n + 1)], cyphertext[k * (n + 1):k * (n + 2)]
            normaldistance += d_H(b1, b2) / (k * n_max)
        if normaldistance < bound:
            bound = normaldistance
            keysize = k
    return keysize

def key(cyphertext):
    keysize = findkeysize(cyphertext)
    blocks = [cyphertext[i:i + keysize] for i in range(0, len(cyphertext), keysize)]
    blocks = [bytes(x) for x in list(zip(*blocks[0:-1]))]
    cleartext = bytes([m03.break_single_byte_xor(x)[0] for x in blocks])
    key = m02.fixed_xor(cleartext, cyphertext)
    return key

def break_repeating_key_xor(cyphertext):
    return m05.repeating_key_xor(key(cyphertext), cyphertext)

if __name__ == "__main__":
    cyphertext = base64.b64decode(open("data/06.txt", "r").read())
    print(break_repeating_key_xor(cyphertext).decode())

