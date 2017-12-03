#!/usr/bin/env python3
# Break a SHA-1 keyed MAC using length extension

from Crypto.Random.random import getrandbits, randint
from m28 import SHA1, sha1_mac

def sha1_state_from_hex(d):
    return [int(d[8 * i : 8 * (i + 1)], 16) for i in range(5)]

def sha1_state_from_binary(d):
    h = [d[4 * i : 4 * (i + 1)] for i in range(5)]
    return list(map(lambda x: int.from_bytes(x, "big"), h))

def sha1_state_from_object(d):
    return d._current_register

def verify_sha1_mac(d, m, k):
    return d.digest() == sha1_mac(m, k).digest()

def md_padding(data):
    return SHA1.pad_message(data)[len(data):]

def extend_sha1(d, z):
    register = sha1_state_from_hex(d.hexdigest())
    padding = z + md_padding(z)

    for n in range(1, 100):
        data_bits = 8 * (64 * n + len(z))
        data_bits = data_bits.to_bytes(8, "big")
        padding = padding[:-8] + data_bits

        q = SHA1()
        q._current_register = register
        q._update_register(padding)

        yield q

if __name__ == "__main__":
    m = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    k = bytes(getrandbits(8) for i in range(randint(0, 50)))
    z = b";admin=true"

    # server-side
    d = sha1_mac(m, k)
    m_prime = m + bytearray(md_padding(k + m)) + z

    # client-side
    for q in extend_sha1(d, z):
        if verify_sha1_mac(q, m_prime, k):
            print(q.hexdigest())
            break

