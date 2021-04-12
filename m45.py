#!/usr/bin/env python3
"""DSA parameter tampering"""

from Crypto.Random.random import randint

import m28
import m39
import m43
import m44

def sign_relaxed(m: bytes, x: int, p: int, q: int, g: int) -> m43.DSASignature:
    """Sign message without checking constraints on r, s"""
    # The original implementation checks this and falls into
    # an infinite loop.
    h_m = m39.to_int(m28.SHA1(m).digest())
    k = randint(1, q - 1)
    k_inv = m39.invmod(k, q)

    r = pow(g, k, p) % q
    s = (k_inv * (h_m + x * r)) % q

    return m43.DSASignature(r, s)

def verify_relaxed(m: bytes, signature: m43.DSASignature, y: int,
                   p: int, q: int, g: int) -> bool:
    """Verify DSA signature without checking constraints on r, s"""
    r, s = signature

    w = m39.invmod(s, q)
    h_m = m39.to_int(m28.SHA1(m).digest())
    u_1 = h_m * w % q
    u_2 = r * w % q
    v = pow(g, u_1, p) * pow(y, u_2, p) % p % q

    return v == r

def magic_signature_generator(y: int, p: int, q: int) -> m43.DSASignature:
    """Generate a magic signature, assuming verification with g = 1 mod p"""

    # See https://infoscience.epfl.ch/record/99390/files/Vau96c.ps §4.
    #
    # The trick is to realise at what point we assume g = 1 mod p. Here, it's
    # after key generation but before validation, i,e. the value of g changes
    # mid-way. This means we have to work with some given public key y != 1.
    #
    # The last validation calculation is v = g^u_1 y^u_2 mod p mod q. At this
    # point, g = 1 mod p so this reduces to
    #
    #    v = g^u_1 y^u_2 mod p mod q
    #      = y^u_2 mod p mod q
    #      = y^(rw) mod p mod q
    #      = y^(r / s) mod p mod q.
    #
    # Since validation requires r = v, we solve
    #
    #    r = y^(r / s) mod p mod q.
    #
    # Note that r necessarily depends on y. r = y^z mod p mod q and
    # s = r / z mod q is a solution, for arbitrary z != 0 mod q.

    z = randint(1, q - 1)
    z_inv = m39.invmod(z, q)

    r = pow(y, z, p) % q
    s = z_inv * r % q

    return m43.DSASignature(r, s)

def main() -> None:
    parameters = m44.get_parameters()
    p, q, _ = parameters.values()

    m_1 = b"Hello, world"
    m_2 = b"Goodbye, world"

    # Using bad generator g = 0 mod p, we get y = 0. This sets r = 0
    # for all signatures. Verifiers that don't check r > 0 will
    # return false positives for all message and signature pairs.

    g = 0

    keypair = m43.keygen(p, q, g)

    signature_1 = sign_relaxed(m_1, keypair.x, p, q, g)
    signature_2 = sign_relaxed(m_2, keypair.x, p, q, g)

    assert verify_relaxed(m_1, signature_1, keypair.y, p, q, g)
    assert verify_relaxed(m_2, signature_2, keypair.y, p, q, g)

    assert verify_relaxed(m_1, signature_2, keypair.y, p, q, g)
    assert verify_relaxed(m_2, signature_1, keypair.y, p, q, g)

    # Using bad generator g = 1 mod p, we get y = 1. This sets r = 1
    # for all signatures. The last validation step is calculating
    # v = g^u_1 g^u_2 mod p mod q, but if g mod p = 1 then v = 1.
    # Thus v = r and the signature passes validation.

    g = p + 1

    keypair = m43.keygen(p, q, g)

    signature_1 = m43.sign(m_1, keypair.x, p, q, g)
    signature_2 = m43.sign(m_2, keypair.x, p, q, g)

    assert m43.verify(m_1, signature_1, keypair.y, p, q, g)
    assert m43.verify(m_2, signature_2, keypair.y, p, q, g)

    assert m43.verify(m_1, signature_2, keypair.y, p, q, g)
    assert m43.verify(m_2, signature_1, keypair.y, p, q, g)

    assert m43.verify(b"Ice ice baby", signature_1, keypair.y, p, q, g)

    # Previous signatures were generated for public key y = 1.
    # Given an arbitrary public key y, we can generate validating
    # signatures for any message assuming validation occurs with
    # g = 1 mod p.

    keypair = m43.keygen(**parameters)

    magic_signature = magic_signature_generator(keypair.y, p, q)

    assert m43.verify(m_1, magic_signature, keypair.y, p, q, g)
    assert m43.verify(m_2, magic_signature, keypair.y, p, q, g)

    print(magic_signature)

if __name__ == "__main__":
    main()
