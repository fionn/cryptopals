#!/usr/bin/env python3
# Break fixed-nonce CTR statistically
# "Terror in the styles, never error-files"

from base64 import b64decode
from Crypto.Random.random import getrandbits
from m02 import fixed_xor
from m03 import break_single_byte_xor
from m18 import aes_ctr

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def bulk_ctr(f):
    return [aes_ctr(e, RANDOM_KEY) for e in f]

def transpose_bytes(c):  # this is ugly
    #c_T = [bytes(x) for x in list(zip(*c))]
    c_T = []
    for l in range(max(map(len, c))):
        v = bytes()
        for i in c:
            try:
                v += bytes([i[l]])
            except IndexError:
                continue
        c_T.append(v)
    return c_T

def single_byte_xor_key(c):
    c_T = transpose_bytes(c)
    return bytes([fixed_xor(break_single_byte_xor(x), x)[0] for x in c_T])

def break_fixed_nonce_ctr(c):
    k = single_byte_xor_key(c)
    return [fixed_xor(cyphertext, k) for cyphertext in c]

if __name__ == "__main__":
    f = open("data/20.txt", "r").read().splitlines()
    f = [b64decode(e) for e in f]

    c = bulk_ctr(f)
    p = break_fixed_nonce_ctr(c)
    print("\n".join([plaintext.decode() for plaintext in p]))

