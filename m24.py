#!/usr/bin/env python3
# MT19937 Stream Cipher

from Crypto.Random.random import randint, getrandbits
from m21 import MT19937

def mt19937_crypt(plaintext, seed = 0xffff):
    x = MT19937(seed)
    cyphertext = b''
    for m in plaintext:
        cyphertext += bytes([m ^ x.random() & 0xff])
    return cyphertext

def verify_mt19937_crypt(m = bytes(10), s = 0xffff):
    cyphertext = mt19937_crypt(m, s)
    plaintext = mt19937_crypt(cyphertext, s)
    assert plaintext == m
    return True

def crack_mt19937(cyphertext):
    plaintext = bytes("A" * len(cyphertext), "ascii")
    
    for seed in range(0xffff):
        if cyphertext[-14:] == mt19937_crypt(plaintext, seed)[-14:]:
            return seed

if __name__ == "__main__":
    seed = getrandbits(16)

    prefix = bytes(getrandbits(8) for i in range(randint(0, 100)))
    plaintext = prefix + bytes("A" * 14, "ascii")

    verify_mt19937_crypt()

    cyphertext = mt19937_crypt(plaintext, seed)
    found_seed = crack_mt19937(cyphertext)
    assert found_seed == seed
    print(hex(seed))

