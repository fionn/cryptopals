#!/usr/bin/env python3
"""Iterated Hash Function Multicollisions"""
# https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf

from collections.abc import Iterator, Callable
from typing import NamedTuple
from functools import cache
from copy import copy

from Crypto.Cipher import AES

from m02 import fixed_xor
from m28 import HashBase, merkle_pad

BLOCKSIZE = 16

Chain = NamedTuple("Chain", [("input", bytes), ("out", bytes)])

HashCollision = NamedTuple("HashCollision",
                           [("messages", tuple[bytes, ...]), ("hash", Chain)])

class MDHash(HashBase):
    """Abstract HashBase with register property"""
    name = "abstracthash"
    block_size = BLOCKSIZE
    digest_size = 20
    register = bytes(digest_size)

    def __init__(self, data: bytes = b"") -> None:
        self._h = self.register
        self.update(data)

    def copy(self) -> "MDHash":
        return copy(self)

    def update(self, data: bytes) -> None:
        self._h = md(data, self._h, aes_compressor)

    def digest(self) -> bytes:
        return self._h

    def hexdigest(self) -> str:
        return self._h.hex()

class CheapHash(MDHash):
    """Cheap MD hash"""
    digest_size = 2
    name = "cheaphash"
    register = bytes(digest_size)

class ExpensiveHash(MDHash):
    """Less cheap MD hash"""
    digest_size = 4
    name = "expensivehash"
    register = bytes(digest_size)

def cascade_hash(message: bytes) -> bytes:
    """Super secure collision-resistant cascading hash function"""
    return CheapHash(message).digest() + ExpensiveHash(message).digest()

def blocks(m: bytes, blocksize: int = BLOCKSIZE) -> list[bytes]:
    """Split m into blocks"""
    assert len(m) % blocksize == 0
    return [m[i:i + blocksize] for i in range(0, len(m), blocksize)]

def pad(m: bytes) -> bytes:
    """Merkle-pad idempotently"""
    # We don't pad if we already fit the block size because we want to share
    # the md function between both the MDHash instances (which don't require
    # idempotency) and the attacker (which does).
    if len(m) % BLOCKSIZE == 0:
        return m
    return merkle_pad(m, BLOCKSIZE, "big", 4)

def aes_compressor(m: bytes, h: bytes) -> bytes:
    """Compress with AES-ECB-128"""
    assert len(m) == BLOCKSIZE
    return AES.new(pad(h), AES.MODE_ECB).encrypt(m)

@cache
def md(m: bytes, h: bytes,
       c: Callable[[bytes, bytes], bytes] = aes_compressor) -> bytes:
    """Generic Merkle–Damgård compression function"""
    digest_size = len(h)
    for block in blocks(pad(m)):
        h = fixed_xor(c(block, h)[:digest_size], h)
    return h

def all_possible_block_pairs(byte_length: int) -> Iterator[tuple[bytes, bytes]]:
    """All unique block pairs of a given length"""
    bit_length = 8 * byte_length
    for m1_int in range(2 ** bit_length):
        for m2_int in range(m1_int + 1, 2 ** bit_length):
            yield m1_int.to_bytes(byte_length, "big"), \
                  m2_int.to_bytes(byte_length, "big")

def verify_collision(collision: HashCollision) -> bool:
    """Verify collisions for a single MD-style compression function"""
    target_hashes = set()
    for m in collision.messages:
        target_hashes.add(md(m, collision.hash.input))
    return len(target_hashes) == 1 and target_hashes.pop() == collision.hash.out

def generate_colliding_pairs(n: int, h: bytes) -> Iterator[HashCollision]:
    """Yield colliding pairs for a sequence of states"""
    for _ in range(n):
        for m, m_prime in all_possible_block_pairs(len(h)):
            h_next = md(m, h)
            if h_next == md(m_prime, h):
                collision = HashCollision((m, m_prime), Chain(h, h_next))
                break
        h = collision.hash.out
        yield collision

def generate_multicollision(n: int, hasher: type[MDHash]) -> HashCollision:
    """Return 2ⁿ multicollisions"""
    h = hasher.register
    messages = [b""]
    for collision in generate_colliding_pairs(n, h):
        assert verify_collision(collision)
        h_out = collision.hash.out
        for message in copy(messages):
            messages.remove(message)
            messages += [message + pad(collision.messages[i]) for i in range(2)]

    return HashCollision(tuple(messages), Chain(h, h_out))

def find_cascading_hash_collision(limit: int = 20) -> HashCollision:
    """Find a collision in the cascading hash function"""
    for n in range(1, limit):
        print(f"Adding {2 ** n} hashes to the pool")
        xh_map: dict[bytes, bytes] = {}
        multicollision = generate_multicollision(n, CheapHash)
        for m in multicollision.messages:
            xh = ExpensiveHash(m).digest()
            if xh in xh_map:
                return HashCollision((m, xh_map[xh]),
                                     Chain(None, multicollision.hash.out + xh))
            xh_map[xh] = m

    raise RuntimeError("Failed to find a collision")

def main() -> None:
    """Entry point"""
    collision = find_cascading_hash_collision(limit=20)

    target_hashes = set()
    for m in collision.messages:
        target_hashes.add(cascade_hash(m))

    assert len(target_hashes) == 1
    assert len(set(collision.messages)) == 2
    assert target_hashes.pop() == collision.hash.out

    print("m₀ =", collision.messages[0].hex())
    print("m₁ =", collision.messages[1].hex())
    print("h =", collision.hash.out.hex())

if __name__ == "__main__":
    main()
