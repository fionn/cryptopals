#!/usr/bin/env python3
# Implement a SHA-1 keyed MAC

class SHA1:
    blocksize = 64
    digest_size = 20
    name = "sha1"

    def __init__(self, data = bytes()):
        self.h = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
        self._current_register = self.h
        self.data = bytes()
        self.update(data)

    @staticmethod
    def _leftrotate(b, n = 1):
        return (b << n | b >> 32 - n) & 0xffffffff

    def new(self, data = bytes()):
        self.data = bytes()
        self.update(data)
        return self

    def update(self, data):
        self._current_register = self.h
        self.data += data
        for chunk in self._chunks():
            self._update_register(chunk)
        return self

    def copy(self):
        from copy import copy
        return copy(self)

    @staticmethod
    def pad_message(data):
        data_bits = 8 * len(data)
        data += b'\x80'
        data += b'\x00' * ((56 - len(data) % 64) % 64)
        data += data_bits.to_bytes(8, "big")
        assert len(data) % 64 == 0
        return data

    def _chunks(self):
        data = self.pad_message(self.data)
        for i in range(0, len(data), self.blocksize):
            yield data[i : i + self.blocksize]

    def _update_register(self, chunk):
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(chunk[4 * j : 4 * (j + 1)], "big")

        for j in range(16, 80):
            w[j] = self._leftrotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        h = list(self._current_register)
        a, b, c, d, e = h

        for j in range(80):
            if j in range(20):
                f = d ^ (b & (c ^ d))
                k = 0x5a827999
            elif j in range(20, 40):
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif j in range(40, 60):
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            else:
                f = b ^ c ^ d
                k = 0xca62c1d6

            a, b, c, d, e = (self._leftrotate(a, 5) + f + e + k + w[j] & 0xffffffff,
                             a, self._leftrotate(b, 30), c, d)

        h[0] = h[0] + a & 0xffffffff
        h[1] = h[1] + b & 0xffffffff
        h[2] = h[2] + c & 0xffffffff
        h[3] = h[3] + d & 0xffffffff
        h[4] = h[4] + e & 0xffffffff

        self._current_register = h
        return h

    def hexdigest(self):
        h = list(map(lambda x: x.to_bytes(4, "big"), self._current_register))
        return ''.join(x.hex() for x in h)

    def digest(self):
        h = list(map(lambda x: x.to_bytes(4, "big"), self._current_register))
        return b''.join(h)

def sha1_mac(m, k):
    return SHA1(k + m)

if __name__ == "__main__":
    m = b'Remember when we were young?'
    k = b'ANY COLOUR SUBMARINE'

    h = sha1_mac(m, k)
    print(h.hexdigest())

