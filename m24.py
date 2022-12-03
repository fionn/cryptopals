#!/usr/bin/env python3
"""MT19937 Stream Cipher"""

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange, getrandbits

from m21 import MT19937

def mt19937_crypt(plaintext: bytes, seed: int) -> bytes:
    x = MT19937(seed)
    cyphertext = b""
    for m in plaintext:
        cyphertext += bytes([m ^ x.random() & 0xff])
    return cyphertext

def verify_mt19937_crypt(message: bytes, seed: int) -> bool:
    cyphertext = mt19937_crypt(message, seed)
    plaintext = mt19937_crypt(cyphertext, seed)
    return plaintext == message

def crack_mt19937(cyphertext: bytes) -> int:
    plaintext = b"A" * len(cyphertext)

    for seed in range(0xffff):
        if cyphertext[-14:] == mt19937_crypt(plaintext, seed)[-14:]:
            return seed
    raise RuntimeError("Failed to find MT19937 seed")

def main() -> None:
    seed = getrandbits(16)

    prefix = get_random_bytes(randrange(100))
    plaintext = prefix + b"A" * 14

    if not verify_mt19937_crypt(message=bytes(10), seed=0xffff):
        raise RuntimeError("Failed to verify mt19937_crypt")

    cyphertext = mt19937_crypt(plaintext, seed)
    found_seed = crack_mt19937(cyphertext)
    assert found_seed == seed
    print(hex(seed))

if __name__ == "__main__":
    main()
