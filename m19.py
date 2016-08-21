#!/usr/bin/env python3
# Break fixed-nonce CTR mode using substitutions
# "A terrible beauty is born."

from base64 import b64decode
# I overthought this and accidentally did 20 instead.
from m20 import bulk_ctr, break_fixed_nonce_ctr

if __name__ == "__main__":
    f = open("data/19.txt", "r").read().splitlines()
    f = [b64decode(e) for e in f]

    c = bulk_ctr(f)
    p = break_fixed_nonce_ctr(c)
    print("\n".join([plaintext.decode() for plaintext in p]))

