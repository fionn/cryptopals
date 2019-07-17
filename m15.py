#!/usr/bin/env python3
"""PKCS#7 padding validation"""

import m09

class PKCS7PaddingError(m09.PKCS7Error):
    """Raised for PKCS7 padding errors"""

def pkcs7(plaintext: bytes, blocksize: int = 16) -> bytes:
    return m09.pkcs7(plaintext, blocksize)

def de_pkcs7(plaintext: bytes) -> bytes:
    pad_length = plaintext[-1]
    if not pad_length * bytes([pad_length]) == plaintext[-pad_length:]:
        raise PKCS7PaddingError(f"Expected {pad_length} bytes of padding")
    return plaintext[:-pad_length]

def main() -> None:
    s1 = b"ICE ICE BABY\x04\x04\x04\x04"
    s2 = b"ICE ICE BABY\x05\x05\x05\x05"
    s3 = b"ICE ICE BABY\x01\x02\x03\x04"

    print(de_pkcs7(s1))
    try:
        print(de_pkcs7(s2))
    except PKCS7PaddingError:
        pass
    try:
        print(de_pkcs7(s3))
    except PKCS7PaddingError:
        pass

if __name__ == "__main__":
    main()
