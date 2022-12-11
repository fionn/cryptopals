#!/usr/bin/env python3
"""Kelsey and Schneier's Expandable Messages"""
# Second Preimages on n-bit Hash Functions for Much Less than 2ⁿ Work
# https://www.schneier.com/academic/paperfiles/paper-preimages.pdf

from collections.abc import Iterator, Sequence

from m02 import fixed_xor
import m52
from m52 import md, pad, HashCollision, Chain, CheapHash as Hash

def find_collision(k: int, h: bytes) -> Iterator[HashCollision]:
    """Find colliding blocks of length 1 and length 2ᵏ⁻¹ + 1"""
    # This is FindCollision(α, h_in) in §3.2.
    q = bytes(Hash.block_size * 2 ** (k - 1))  # dummy blocks
    h_q = md(q, h)
    for m, m_prime in m52.all_possible_block_pairs(len(h)):
        h_next = md(m, h)
        if h_next == md(m_prime, h_q):
            # We Merkle-pad m, m_prime to match the input to md, even though
            # it'll produce padding of the wrong length-encoding. We don't care,
            # because it won't be an ending block. We could equally zero-pad,
            # but we'd have to be consistent and it makes no difference anyway.
            yield HashCollision((pad(m), q + pad(m_prime)), Chain(h, h_next))

def make_expandable_message(k: int, h: bytes) -> Iterator[HashCollision]:
    """Make a (k, k + 2ᵏ - 1)-expandable message"""
    for i in range(k, 0, -1):
        try:
            collision = next(find_collision(i, h))
            h = collision.hash.out
            yield collision
        except StopIteration as ex:
            raise RuntimeError(f"Failed to find collision for k = {i} "
                               f"on {h.hex()}") from ex

def produce_message(c: Sequence[HashCollision], k: int, l: int) -> bytes:
    """Produce a message of length l blocks from an expandable message"""
    if l > 2 ** k + k - 1 or l < k:
        raise ValueError(f"{l=} must be between {k} and {2 ** k + k - 1}")

    s = [int(t) for t in bin(l - k)[2:].zfill(k)]

    m = b""
    for i, collision in enumerate(c):
        m += collision.messages[s[i]]

    assert len(m) // Hash.block_size == l
    return m

def generate_intermediate_states(m: bytes, h: bytes) -> Iterator[bytes]:
    """md function that yields its internal state on each iteration"""
    for block in m52.blocks(pad(m), Hash.block_size):
        h = fixed_xor(m52.aes_compressor(block, h)[:Hash.digest_size], h)
        yield h

def second_preimage_attack(m: bytes) -> bytes:
    """Find the second preimage of m"""
    # This is LongMessageAttack(M_target) in §4.2.
    k = (len(m) // Hash.block_size).bit_length() - 1  # m has 2ᵏ blocks

    intermediate_states = list(generate_intermediate_states(m, Hash.register))
    c = list(make_expandable_message(k, Hash.register))
    h_exp = c[-1].hash.out

    for m_int in range(2 ** (8 * Hash.digest_size)):
        m_link = m_int.to_bytes(Hash.digest_size, "big")
        h_prime = md(m_link, h_exp)
        if h_prime in intermediate_states:
            j = intermediate_states.index(h_prime)
            break
    else:
        raise RuntimeError(f"Failed to find message bridge for {h_exp.hex()}")

    m_prime = produce_message(c, k, j - 1)
    assert md(m_prime, Hash.register) == h_exp
    assert md(m_prime + pad(m_link), Hash.register) == h_prime

    m_remaining = m[Hash.block_size * (j + 1):]
    assert md(m_remaining, h_prime) == md(m, Hash.register)
    return m_prime + pad(m_link) + m_remaining

def main() -> None:
    """Entry point"""
    h, k = Hash.register, 6

    m = bytes(Hash.block_size * 2 ** k)
    h_m = md(m, h)
    m_prime = second_preimage_attack(m)

    assert m != m_prime
    assert md(m_prime, h) == h_m

    print("m =", m.hex())
    print("m′=", m_prime.hex())
    print("h =", h_m.hex())

    collision = HashCollision((m, m_prime), Chain(h, h_m))
    assert m52.verify_collision(collision)

if __name__ == "__main__":
    main()
