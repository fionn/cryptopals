#!/usr/bin/env python3
# Convert hex to base64

import base64

def hex_to_base64(s):
    s_bytes = bytes.fromhex(s)
    s_64 = base64.b64encode(s_bytes).decode("ascii")  #.decode() just removes the b'.
    return s_64

if __name__ == "__main__":
    s = open("data/01.txt", "r").read().strip()
    print(hex_to_base64(s))

