#!/usr/bin/env python3
"""Break fixed-nonce CTR mode using substitutions"""
# "A terrible beauty is born."

from base64 import b64decode

from m20 import bulk_ctr, break_fixed_nonce_ctr

# I overthought this and accidentally did 20 instead.
def main() -> None:
    with open("data/19.txt", "r") as f:
        data = [b64decode(e) for e in f.read().splitlines()]

    c = bulk_ctr(data)
    p = break_fixed_nonce_ctr(c)
    print("\n".join([plaintext.decode() for plaintext in p]))

if __name__ == "__main__":
    main()
