#!/usr/bin/env python3
# Fixed XOR

def fixed_xor(a, b):
    a_bytes = bytes.fromhex(a).decode()
    b_bytes = bytes.fromhex(b).decode()

    xor = ""
    for i, j in zip(str(a_bytes), str(b_bytes)):
        print(ord(i), ord(j))
        xor += hex(ord(i) ^ ord(j))[2:]  # to drop "0x"

    return xor

if __name__ == "__main__":
    f = open("data/02.txt", "r").read().splitlines()

    a, b = f[0], f[1]

    if(len(a) != len(b)):
        print("Buffers are different sizes:", len(a),"!=", len(b))
    else:
        print(fixed_xor(a, b))

