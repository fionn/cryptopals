#!/usr/bin/env python3
# Implement CTR, the stream cipher mode
# "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby"

from struct import pack
from Crypto.Cipher import AES
from base64 import b64decode
from m02 import fixed_xor

def aes_ctr(c, k, n = 0):
    c = [c[16*i:16*(i+1)] for i in range(0, len(c) // 16 + 1)]
    cypher = AES.new(k, AES.MODE_ECB)

    m = b''
    ctr = 0
    for block in c:
        keystream = pack('<Qq', n, ctr)
        m += fixed_xor(cypher.encrypt(keystream), block)
        ctr += 1
    return m

if __name__ == "__main__":
    c = b64decode(open("data/18.txt", "r").read().strip())

    key = b'YELLOW SUBMARINE'

    print(aes_ctr(c, key).decode())

