#!/usr/bin/env python3
"""Implement an e = 3 RSA broadcast attack"""

import math

import m39

def generate_key_and_encrypt(m: bytes, size: int = 256) -> tuple[m39.RSAKey, int]:
    pubkey, _ = m39.keygen(size, e=3)
    return pubkey, m39.encrypt(m, pubkey)

def integer_root(a: int, e: int) -> int:
    """eth root via Newton-Rhapson method"""
    if a == 0 and e != 0:
        return 0
    x_i, x_j = a + 1, a
    while x_j < x_i:
        x_i = x_j
        x_j = ((e - 1) * x_i + a // pow(x_i, e - 1)) // e
    return x_i

def crt(a: list[int], n: list[int]) -> int:
    """
    Given lists a_1, ..., a_k and n_1, ..., n_k, solve the
    system x = a_i mod n_i for all i such that 0 <= x < prod(n_i),
    assuming n_i are pairwise coprime.
    """
    if len(a) != len(n):
        raise ValueError("Arguments must be of equal length")

    r = 0
    N = math.prod(n)
    for a_i, n_i in zip(a, n):
        m_s = N // n_i
        r += a_i * m_s * m39.invmod(m_s, n_i)

    return r % N

def broadcast_attack(k: list[m39.RSAKey], c: list[int]) -> int:
    """Use CRT to find m^3 from ciphertext"""
    assert len(k) == len(c) == 3, "Need 3 equations for e = 3 RSA"
    n = [key.modulus for key in k]
    return integer_root(crt(c, n), 3)

def main() -> None:
    m = b"I am a JavaScript programmer"

    k = []
    c = []
    for _ in range(3):
        k_i, c_i = generate_key_and_encrypt(m)
        k.append(k_i)
        c.append(c_i)

    m_prime = m39.to_bytes(broadcast_attack(k, c))
    assert m == m_prime
    print(m_prime.decode())

if __name__ == "__main__":
    main()
