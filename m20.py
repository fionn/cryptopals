#!/usr/bin/env python3
"""Break fixed-nonce CTR statistically"""
# "Terror in the styles, never error-files"

from base64 import b64decode

from Crypto.Random.random import getrandbits

from m02 import fixed_xor
from m03 import break_single_byte_xor
from m18 import aes_ctr

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def bulk_ctr(cyphertexts: list[bytes]) -> list[bytes]:
    return [aes_ctr(e, RANDOM_KEY) for e in cyphertexts]

def transpose_bytes(c: list[bytes]) -> list[bytes]:  # this is ugly
    #c_T = [bytes(x) for x in list(zip(*c))]
    c_t = []
    for l in range(max(map(len, c))):
        v = b""
        for i in c:
            try:
                v += bytes([i[l]])
            except IndexError:
                continue
        c_t.append(v)
    return c_t

def single_byte_xor_key(c: list[bytes]) -> bytes:
    c_t = transpose_bytes(c)
    return bytes([fixed_xor(break_single_byte_xor(x), x)[0] for x in c_t])

def break_fixed_nonce_ctr(c: list[bytes]) -> list[bytes]:
    k = single_byte_xor_key(c)
    return [fixed_xor(cyphertext, k[:len(cyphertext)]) for cyphertext in c]

def main() -> None:
    with open("data/20.txt", "r") as f:
        data = [b64decode(e) for e in f.read().splitlines()]

    c = bulk_ctr(data)
    p = break_fixed_nonce_ctr(c)
    print("\n".join([plaintext.decode() for plaintext in p]))

if __name__ == "__main__":
    main()
