#!/usr/bin/env python3
"""DSA key recovery from nonce"""
# "For those that envy a MC it can be hazardous to your health"

import json
from typing import NamedTuple

from Crypto.Random.random import randint

import m28
import m39

DSAKeyPair = NamedTuple("DSAKeyPair", [("y", int), ("x", int)])
DSASignature = NamedTuple("DSASignature", [("r", int), ("s", int)])

def keygen(p: int, q: int, g: int) -> DSAKeyPair:
    """Generate DSA public and pivate keypair"""
    x = randint(1, q - 1)
    y = pow(g, x, p)
    return DSAKeyPair(y=y, x=x)

def sign(m: bytes, x: int, p: int, q: int, g: int) -> DSASignature:
    """Sign message with DSA private key"""
    h_m = m39.to_int(m28.SHA1(m).digest())
    r, s = 0, 0
    while r == 0 or s == 0:
        k = randint(1, q - 1)
        r = pow(g, k, p) % q
        k_inv = m39.invmod(k, q)
        s = (k_inv * (h_m + x * r)) % q

    return DSASignature(r, s)

def verify(m: bytes, signature: DSASignature, y: int,
           p: int, q: int, g: int) -> bool:
    """Verify DSA signature"""
    r, s = signature

    if not 0 < r < q or not 0 < s < q:
        return False

    w = m39.invmod(s, q)
    h_m = m39.to_int(m28.SHA1(m).digest())
    u_1 = h_m * w % q
    u_2 = r * w % q
    v = pow(g, u_1, p) * pow(y, u_2, p) % p % q

    return v == r

def recover_private_key(m: bytes, signature: DSASignature,
                        k: int, q: int) -> int:
    """Recover private key from signature and subkey k"""
    r, s = signature
    h_m = m39.to_int(m28.SHA1(m).digest())
    r_inv = m39.invmod(r, q)
    return r_inv * (s * k - h_m) % q

def brute_force_recover_key(m: bytes, signature: DSASignature, y: int,
                            k_min: int, k_max: int,
                            p: int, q: int, g: int) -> tuple[int, int]:
    """Guess subkeys within a range and return the private key that matches"""
    for k in range(k_min, k_max):
        x = recover_private_key(m, signature, k, q)
        if pow(g, x, p) == y:
            return x, k

    raise RuntimeError

def main() -> None:
    with open("data/43.txt") as data_fd:
        data = json.load(data_fd)

    parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}
    m = data["m"].encode()

    y = int(data["y"], 16)
    r = int(data["r"])
    s = int(data["s"])

    signature = DSASignature(r, s)
    assert verify(m, signature, y, **parameters)

    k_max = 2 ** 16
    x, k = brute_force_recover_key(m, signature, y, 0, k_max, **parameters)
    print(f"{k=}")
    print(f"{x=}")

if __name__ == "__main__":
    main()
