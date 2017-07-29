#!/usr/bin/env python3
# Implement a SHA-1 keyed MAC

def leftrotate(b, n = 1):
    return (b << n | b >> 32 - n) & 0xffffffff

def sha1(m):
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    ml = 8 * len(m)
    m += b'\x80'
    m += b'\x00' * ((56 - len(m) % 64) % 64)
    m += ml.to_bytes(8, "big")
    assert len(m) % 64 == 0

    for i in range(0, len(m), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(m[i : i + 64][4 * j : 4 * (j + 1)], "big")

        for j in range(16, 80):
            w[j] = leftrotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        a, b, c, d, e = h[0], h[1], h[2], h[3], h[4]

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

            a, b, c, d, e = (leftrotate(a, 5) + f + e + k + w[j] & 0xffffffff,
                             a, leftrotate(b, 30), c, d)

        h[0] = h[0] + a & 0xffffffff
        h[1] = h[1] + b & 0xffffffff
        h[2] = h[2] + c & 0xffffffff
        h[3] = h[3] + d & 0xffffffff
        h[4] = h[4] + e & 0xffffffff

    h = list(map(lambda x: x.to_bytes(4, "big"), h))

    return ''.join(x.hex() for x in h)

def sha1_mac(m, k):
    return sha1(k + m)

if __name__ == "__main__":
    m = b'Remember when we were young?'
    k = b'ANY COLOUR SUBMARINE'

    h = sha1_mac(m, k)
    print(h)

