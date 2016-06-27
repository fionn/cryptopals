#!/usr/bin/env python3
# Single-byte XOR cipher -- "Cooking MC's like a pound of bacon"

from m02 import fixed_xor
from frequency import frequency

def xor_everything(s):
    return [fixed_xor(bytes([k] * len(s)), s) for k in range(256)]

def score(sentence):
    score = 0
    for character in sentence:
        if(character < 10 or character > 126):
            return 0    # printable characters; m04 needs "\n"
        c = chr(character).lower()
        if c in frequency:
            score += frequency[c]
    return score

def mostprobable(sentences):
    highscore = -1
    for sentence in sentences:
        if score(sentence) > highscore:
            highscore = score(sentence)
            thisisit = sentence
    return bytes(thisisit)

def break_single_byte_xor(s):
    return mostprobable(xor_everything(s))

if __name__ == "__main__":

    cyphertext = open("data/03.txt", "r").read().strip()
    cyphertext = bytes.fromhex(cyphertext)
    
    print(break_single_byte_xor(cyphertext).decode())

