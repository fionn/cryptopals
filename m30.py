#!/usr/bin/env python3
# Break an MD4 keyed MAC using length extension

import struct
from copy import copy
from Crypto.Random.random import getrandbits, randint

class MD4:
    name = "md4"
    blocksize = 64
    digest_size = 16
    register = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

    def __init__(self, data = bytes()):
        self._register = MD4.register
        self.data = bytes()
        self._vandercorput = [self._binaryreverse(x) for x in range(16)]
        self.update(data)

    def copy(self):
        return copy(self)

    def update(self, data):
        self._register = MD4.register
        self.data += data
        for chunk in self._chunks():
            self._compress(chunk)
        return self

    def new(self, data = bytes()):
        self.data = bytes()
        self.update(data)
        return self

    @staticmethod
    def pad_message(data):
        b = (8 * len(data)).to_bytes(8, "little")
        data += b'\x80'
        data += b'\x00' * ((56 - len(data) % MD4.blocksize) % MD4.blocksize)
        data += b
        assert len(data) % MD4.blocksize == 0
        return data

    def _chunks(self):
        data = self.pad_message(self.data)
        for i in range(0, len(data), MD4.blocksize):
            yield data[i : i + MD4.blocksize]

    @staticmethod
    def _lrot(x, n = 1):
        return x << n | x >> 32 - n

    @staticmethod
    def _binaryreverse(x, n = 4):
        r = 0
        for _ in range(n):
            r = (r << 1) + (x & 1)
            x >>= 1
        return r

    @staticmethod
    def _F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def _G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _H(x, y, z):
        return x ^ y ^ z

    def round_one_op(self, x, a, b, c, d, k, s):
        return self._lrot(a + MD4._F(b, c, d) + x[k] & 0xffffffff, s)

    def round_two_op(self, x, a, b, c, d, k, s):
        return self._lrot(a + MD4._G(b, c, d) + x[k] + 0x5a827999 & 0xffffffff, s)

    def round_three_op(self, x, a, b, c, d, k, s):
        return self._lrot(a + MD4._H(b, c, d) + x[k] + 0x6ed9eba1 & 0xffffffff, s)

    def round_one(self, x, a, b, c, d):
        for k in range(16):
            if k % 4 == 0:
                a = self.round_one_op(x, a, b, c, d, k, 3)
            elif k % 4 == 1:
                d = self.round_one_op(x, d, a, b, c, k, 7)
            elif k % 4 == 2:
                c = self.round_one_op(x, c, d, a, b, k, 11)
            elif k % 4 == 3:
                b = self.round_one_op(x, b, c, d, a, k, 19)

        return a, b, c, d

    def round_two(self, x, a, b, c, d):
        for i in range(16):
            k = (i // 4 + 4 * i) % 16
            if i % 4 == 0:
                a = self.round_two_op(x, a, b, c, d, k, 3)
            elif i % 4 == 1:
                d = self.round_two_op(x, d, a, b, c, k, 5)
            elif i % 4 == 2:
                c = self.round_two_op(x, c, d, a, b, k, 9)
            elif i % 4 == 3:
                b = self.round_two_op(x, b, c, d, a, k, 13)

        return a, b, c, d

    def round_three(self, x, a, b, c, d):
        for i in range(16):
            k = self._vandercorput[i]
            if i % 4 == 0:
                a = self.round_three_op(x, a, b, c, d, k, 3)
            elif i % 4 == 1:
                d = self.round_three_op(x, d, a, b, c, k, 9)
            elif i % 4 == 2:
                c = self.round_three_op(x, c, d, a, b, k, 11)
            elif i % 4 == 3:
                b = self.round_three_op(x, b, c, d, a, k, 15)

        return a, b, c, d

    def _compress(self, chunk):
        X = list(struct.unpack('<16I', chunk))
        A, B, C, D = self._register

        A, B, C, D = self.round_one(X, A, B, C, D)
        A, B, C, D = self.round_two(X, A, B, C, D)
        A, B, C, D = self.round_three(X, A, B, C, D)

        A = (self._register[0] + A) & 0xffffffff
        B = (self._register[1] + B) & 0xffffffff
        C = (self._register[2] + C) & 0xffffffff
        D = (self._register[3] + D) & 0xffffffff

        self._register = (A, B, C, D)

    def hexdigest(self):
        h = list(map(lambda x: x.to_bytes(4, "little"), self._register))
        return ''.join(x.hex() for x in h)

    def digest(self):
        h = list(map(lambda x: x.to_bytes(4, "little"), self._register))
        return b''.join(h)

def md4_mac(m, k):
    return MD4(k + m)

def md4_state_from_hex(d):
    return struct.unpack('<4I', bytes.fromhex(d))

def md4_state_from_binary(d):
    h = [d[4 * i : 4 * (i + 1)] for i in range(4)]
    return tuple(map(lambda x: int.from_bytes(x, "little"), h))

def md4_state_from_object(d):
    return d._register

def verify_md4_mac(d, m, k):
    return d.digest() == md4_mac(m, k).digest()

def md_padding(data):
    return MD4.pad_message(data)[len(data):]

def extend_md4(d, z):
    register = md4_state_from_hex(d.hexdigest())
    padding = z + md_padding(z)

    for n in range(1, 100):
        data_bits = 8 * (64 * n + len(z))
        data_bits = data_bits.to_bytes(8, "little")
        padding = padding[:-8] + data_bits

        q = MD4()
        q._register = register
        q._compress(padding)

        yield q

if __name__ == "__main__":
    m = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    k = bytes(getrandbits(8) for i in range(randint(0, 50)))
    z = b";admin=true"

    # server-side
    mac = md4_mac(m, k)
    m_prime = m + bytearray(md_padding(k + m)) + z

    # client-side
    for q in extend_md4(mac, z):
        if verify_md4_mac(q, m_prime, k):
            print(q.hexdigest())
            break

