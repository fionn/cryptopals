#!/usr/bin/env python3
# Implement PKCS#7 padding

def pkcs7(plaintext, blocksize):
    pad = blocksize - (len(plaintext) % blocksize)
    assert pad < 256
    if pad != 0:
        return plaintext + pad * bytes([pad])
    else:
        return plaintext + blocksize * bytes([blocksize])

def de_pkcs7(plaintext):
    plaintext = plaintext[:len(plaintext) - plaintext[-1]]
    return plaintext

if __name__ == "__main__":
    plaintext = bytes("YELLOW SUBMARINE", "utf8")
    blocksize = 20

    print(pkcs7(plaintext, blocksize))

