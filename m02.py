#!/usr/bin/env python3
# Fixed XOR -- "hit the bull's eye, the kid don't play"

from binascii import hexlify

def fixed_xor(a, b):
    c, d =  "", bytearray()
    for i, j in zip(a, b):
        d.append(i ^ j)
        #print(hexlify(d).decode())
        #c += hex(i ^ j)[2:].zfill(2)  # to drop "0x" and pad left
    return d

if __name__ == "__main__":
    f = open("data/02.txt", "r").read().splitlines()
    a, b = f[0], f[1]
    
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)

    xor = hexlify(fixed_xor(a_bytes, b_bytes)).decode()
    
    print(xor)

