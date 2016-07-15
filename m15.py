#!/usr/bin/env python3
# PKCS#7 padding validation

def de_pkcs7(plaintext):
    try:
        pad_length = plaintext[-1]
        assert pad_length * bytes([pad_length]) == plaintext[- pad_length:]
        return plaintext[:-pad_length]
    except Exception:
        print("invalid padding")
        raise SystemExit

if __name__ == "__main__":
    s1 = b"ICE ICE BABY\x04\x04\x04\x04"
    s2 = b"ICE ICE BABY\x05\x05\x05\x05"
    s3 = b"ICE ICE BABY\x01\x02\x03\x04"

    print(de_pkcs7(s1))
