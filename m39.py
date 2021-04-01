#!/usr/bin/env python3
"""Implement RSA"""

from typing import NamedTuple

from Crypto.Util.number import getPrime as get_prime

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                31, 37, 41, 43, 47, 53, 59, 61, 67, 71]

RSAKey = NamedTuple("RSAKey", [("exponent", int), ("modulus", int)])

RSAKeyPair = NamedTuple("RSAKeyPair",
                        [("public", RSAKey), ("private", RSAKey)])

def gcd(a: int, b: int) -> int:
    """Euclidean GCD"""
    while b != 0:
        a, b = b, a % b
    return abs(a)

def lcm(a: int, b: int) -> int:
    """LCM using Euclidean GCD"""
    try:
        return abs(a // gcd(a, b) * b)
    except ZeroDivisionError:
        return 0

def invmod(a: int, n: int) -> int:
    """Modular multiplicative inverse via xGCD"""
    # Inefficient compared to native pow(a, -1, n).
    t, t_prime = 0, 1
    r, r_prime = n, a

    while r_prime != 0:
        q = r // r_prime
        t, t_prime = t_prime, t - q * t_prime
        r, r_prime = r_prime, r - q * r_prime

    if r > 1:
        raise ValueError(f"{a} is not invertible over {n}")
    while t < 0:
        t += n

    return t

def keygen(size: int = 1024, e: int = 3) -> RSAKeyPair:
    """Generate RSA public and private key pair"""
    # e, phi(n) must be coprime for unique decryption.
    # n might be one bit short if both primes are on the small side.
    n, phi_n = 0, 0
    while gcd(e, phi_n) != 1 or n.bit_length() != size:
        # We don't choose strong primes here, just normal ones.
        # Different sizes to guarantee distinct values and make factoring harder.
        p, q = get_prime(size // 2 - 1), get_prime(size // 2 + 1)
        phi_n = lcm(p - 1, q - 1)  # Carmichael's totient function
        n = p * q

    d = invmod(e, phi_n)

    assert gcd(d, phi_n) == 1
    return RSAKeyPair(public=RSAKey(e, n), private=RSAKey(d, n))

def encrypt_int(m: int, public_key: RSAKey) -> int:
    """Encrypt integer with RSA public key"""
    if m >= public_key.modulus:
        raise ValueError("Message must be smaller than modulus")
    return pow(m, *public_key)

def decrypt_int(c: int, private_key: RSAKey) -> int:
    """Decrypt RSA message to integer"""
    return pow(c, *private_key)

def encrypt(m: bytes, public_key: RSAKey) -> int:
    """Encrypt binary with RSA public key"""
    return encrypt_int(int.from_bytes(m, "big"), public_key)

def decrypt(c: int, private_key: RSAKey) -> bytes:
    """Decrypt RSA message to binary"""
    m = decrypt_int(c, private_key)
    return m.to_bytes((m.bit_length() + 7) // 8, "big")

def main() -> None:
    """Entry point"""
    public_key, private_key = keygen()

    m = b"IT'S ALL GREEK TO ME"  # Julius Caesar, I, ii, 288, paraphrased
    c = encrypt(m, public_key)
    m_prime = decrypt(c, private_key)

    print(m_prime.decode())
    assert m == m_prime

if __name__ == "__main__":
    main()
