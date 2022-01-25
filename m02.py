#!/usr/bin/env python3
"""Fixed XOR"""
# "hit the bull's eye, the kid don't play"

def fixed_xor(a: bytes, b: bytes) -> bytes:
    return bytes([i ^ j for i, j in zip(a, b, strict=True)])

def main() -> None:
    with open("data/02.txt", "r") as f:
        f_list = f.read().splitlines()
        a, b = f_list[0], f_list[1]

    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    xor = fixed_xor(a_bytes, b_bytes).hex()
    print(xor)

if __name__ == "__main__":
    main()
