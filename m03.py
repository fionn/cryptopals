#!/usr/bin/env python3
# Single-byte XOR cipher -- "Cooking MC's like a pound of bacon"

from math import inf as infinity
from m02 import fixed_xor
from frequency import frequency

def expectation(k, length, t = 0.01):
    if chr(k).lower() in frequency:
        return frequency[chr(k).lower()] * length

    return t * length # roughly how likely we expect to find a
                      # non-alphabetical character

def score(sentence):
    chi_sq = 0

    for k in sentence:
        if k < 10 or k > 126:
            return infinity
        else:
            mu = expectation(k, len(sentence))
            sqrt_numerator = sentence.count(k) - mu
            chi_sq += sqrt_numerator * sqrt_numerator / mu

    return chi_sq

def xor_everything(s):
    return [fixed_xor(bytes([k] * len(s)), s) for k in range(256)]

def mostprobable(sentences):
    lowscore = infinity
    thisisit = bytes()
    for sentence in sentences:
        if score(sentence) < lowscore:
            lowscore = score(sentence)
            thisisit = sentence
    return thisisit

def break_single_byte_xor(s):
    return mostprobable(xor_everything(s))

if __name__ == "__main__":

    cyphertext = open("data/03.txt", "r").read().strip()
    cyphertext = bytes.fromhex(cyphertext)

    print(break_single_byte_xor(cyphertext).decode())

