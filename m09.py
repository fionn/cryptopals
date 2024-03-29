#!/usr/bin/env python3
"""Implement PKCS#7 padding"""

class PKCS7PaddingError(Exception):
    """Raised for PKCS7 padding errors"""

def pkcs7(plaintext: bytes, blocksize: int = 16) -> bytes:
    pad = blocksize - (len(plaintext) % blocksize)
    if pad > 255:
        raise PKCS7PaddingError(f"Padding to {pad} but can't pad beyond 255")
    return plaintext + pad * bytes([pad])

def de_pkcs7(plaintext: bytes) -> bytes:
    return plaintext[:len(plaintext) - plaintext[-1]]

def main() -> None:
    plaintext = b"YELLOW SUBMARINE"
    blocksize = 20

    assert de_pkcs7(pkcs7(plaintext, blocksize)) == plaintext
    print(pkcs7(plaintext, blocksize))

if __name__ == "__main__":
    main()
