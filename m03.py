#!/usr/bin/env python3
# Single-byte XOR cipher -- "Cooking MC's like a pound of bacon"

import binascii
from string import ascii_lowercase as alphabet
from collections import Counter

def xor_everything(s):
    s_bytes = bytes.fromhex(s).decode()

    cypher = []
    for k in range(256):
        xor = ""
        for j in (s_bytes):
            xor += hex(ord(j) ^ (k))[2:].zfill(2)  # hex drops leading 0
        #print(k, chr(k), hex(k), "\t", len(xor), "\t", xor)
        cypher.append([k, binascii.unhexlify(xor)])

    return cypher

def printable(stack):
    for pair in stack[:]:  # a copy of the list
        for character in pair[1]:
            if(character < 32 or character > 126):
                stack.remove(pair)
                break
    return stack

def distribution():
    # From en.algoritmy.net/article/40379/Letter-frequency-English
    f = open("data/frequency.txt", "r").read().strip().split()
    f = dict(zip(f[0::2], f[1::2]))
    f[" "] = 19

    for letter in f:
        f[letter] = float(f[letter])

    return f

def score(sentence):
    count = Counter(sentence.lower())
    var = 0
    for letter in list(alphabet + " "):
        count[letter] = count[letter] * 100 / len(sentence)  #sum(count.values())
        var += abs(count[letter] * count[letter] - \
                 distribution()[letter] * distribution()[letter])
    return var

def plaintext(sentences):
    bound = float("inf")
    for sentence in sentences:
        sentence = sentence[1].decode()
        if score(sentence) < bound:
            bound = score(sentence)
            thisisit = sentence
    return thisisit


if __name__ == "__main__":

    s = open("data/03.txt", "r").read().strip()
    
    candidates = xor_everything(s)
    candidates = printable(candidates)

    print(plaintext(candidates))

