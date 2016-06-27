#!/usr/bin/env python3
# Implement PKCS#7 padding

def pkcs7(plaintext, blocksize):
    # https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
    pad = blocksize - (len(plaintext) % blocksize)
    assert pad < 256
    if pad != 0:
        return plaintext + pad * bytes([pad])
    else:
        return plaintext + blocksize * bytes([blocksize])

if __name__ == "__main__":
    plaintext = bytes("YELLOW SUBMARINE", "utf8")
    blocksize = 20

    print(pkcs7(plaintext, blocksize))

