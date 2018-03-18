#!/usr/bin/env python3
# PKCS#7 padding validation

class PKCS7PaddingError(ValueError):
    pass

def de_pkcs7(plaintext):
    pad_length = plaintext[-1]
    if not pad_length * bytes([pad_length]) == plaintext[- pad_length:]:
        raise PKCS7PaddingError
    return plaintext[:-pad_length]

if __name__ == "__main__":
    s1 = b"ICE ICE BABY\x04\x04\x04\x04"
    s2 = b"ICE ICE BABY\x05\x05\x05\x05"
    s3 = b"ICE ICE BABY\x01\x02\x03\x04"

    print(de_pkcs7(s1))
