#!/usr/bin/env python3
# Single-byte XOR cipher -- "Cooking MC's like a pound of bacon"

from string import ascii_lowercase
from collections import Counter
from m02 import fixed_xor

def xor_everything(s):
    s_bytes = bytes.fromhex(s)

    cypher = []
    for k in range(256):
        xor = fixed_xor(bytes([k] * len(s_bytes)), s_bytes)
        cypher.append(xor)

    return cypher

def printable(stack):
    for binary in stack[:]:  # a copy of the list
        for character in binary:
            if(character < 10 or character > 126):  # need < 32 for m04
                stack.remove(binary)
                break
    return stack

def distribution():
    f = open("data/frequency.txt", "r").read().strip().split()
    f = dict(zip(f[0::2], f[1::2]))
    f[" "] = 19

    for letter in f:
        f[letter] = float(f[letter])

    return f

def score(sentence):
    count = Counter(sentence.lower())
    var = 0
    for letter in list(ascii_lowercase + " "):
        count[letter] = count[letter] * 100 / len(sentence)  #sum(count.values())
        var += abs(count[letter] * count[letter] - \
                   distribution()[letter] * distribution()[letter])
    return var

def mostprobable(sentences):
    bound = float("inf")
    thisisit = None
    for sentence in sentences:
        if isinstance(sentence, bytearray):  # I want to be able to reuse this
            sentence = sentence.decode()     # function on text as well
        if score(sentence) < bound:
            bound = score(sentence)
            thisisit = sentence
    return thisisit

def break_single_byte_xor(s):
    candidates = xor_everything(s)
    candidates = printable(candidates)
    return mostprobable(candidates)


if __name__ == "__main__":

    s = open("data/03.txt", "r").read().strip()

    print(break_single_byte_xor(s))

