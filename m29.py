#!/usr/bin/env python3
"""Break a SHA-1 keyed MAC using length extension"""

from typing import Generator

from Crypto.Random.random import getrandbits, randint

from m28 import SHA1, sha1_mac, Register

def sha1_state_from_hex(d: str) -> Register:
    return tuple(int(d[8 * i:8 * (i + 1)], 16) for i in range(5))

def sha1_state_from_binary(d: bytes) -> Register:
    h = [d[4 * i:4 * (i + 1)] for i in range(5)]
    return tuple(map(lambda x: int.from_bytes(x, "big"), h))

def sha1_state_from_object(d: SHA1) -> Register:
    return d._current_register  # pylint: disable=protected-access

def verify_sha1_mac(d: SHA1, message: bytes, key: bytes) -> bool:
    return d.digest() == sha1_mac(message, key).digest()

def md_padding(data: bytes) -> bytes:
    return SHA1.pad_message(data)[len(data):]

def extend_sha1(d: SHA1, z: bytes) -> Generator[SHA1, None, None]:
    register = sha1_state_from_hex(d.hexdigest())
    padding = z + md_padding(z)

    for n in range(1, 100):
        data_int = 8 * (64 * n + len(z))
        data_bits = data_int.to_bytes(8, "big")
        padding = padding[:-8] + data_bits

        q = SHA1()
        # pylint: disable=protected-access
        q._current_register = register
        q._update_register(padding)

        yield q

def main() -> None:
    m = b"comment1=cooking%20MCs;userdata=foo;" \
        b"comment2=%20like%20a%20pound%20of%20bacon"
    k = bytes(getrandbits(8) for _ in range(randint(0, 50)))
    z = b";admin=true"

    # server-side
    d = sha1_mac(m, k)
    m_prime = m + bytearray(md_padding(k + m)) + z

    # client-side
    for q in extend_sha1(d, z):
        if verify_sha1_mac(q, m_prime, k):
            print(q.hexdigest())
            break

if __name__ == "__main__":
    main()
