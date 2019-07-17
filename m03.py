#!/usr/bin/env python3
"""Single-byte XOR cipher"""
# "Cooking MC's like a pound of bacon"

from typing import List

from m02 import fixed_xor
from data.frequency import frequency

def expectation(k: int, length: int, t: float = 0.01) -> float:
    if chr(k).lower() in frequency:
        return frequency[chr(k).lower()] * length

    return t * length  # roughly how likely we expect to find a
                       # non-alphabetical character

def score(sentence: bytes) -> float:
    chi_sq = 0.0

    for k in sentence:
        if k < 10 or k > 126:
            return float("inf")
        mu = expectation(k, len(sentence))
        sqrt_numerator = sentence.count(k) - mu
        chi_sq += sqrt_numerator * sqrt_numerator / mu

    return chi_sq

def xor_everything(s: bytes) -> List[bytes]:
    return [fixed_xor(bytes([k] * len(s)), s) for k in range(256)]

def mostprobable(sentences: list) -> bytes:
    lowscore = float("inf")
    solution = b""
    for sentence in sentences:
        if score(sentence) < lowscore:
            lowscore = score(sentence)
            solution = sentence
    return solution

def break_single_byte_xor(s: bytes) -> bytes:
    return mostprobable(xor_everything(s))

def main() -> None:
    with open("data/03.txt", "r") as data:
        cyphertext = bytes.fromhex(data.read().strip())

    print(break_single_byte_xor(cyphertext).decode())

if __name__ == "__main__":
    main()
