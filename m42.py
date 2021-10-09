#!/usr/bin/env python3
"""Bleichenbacher's e=3 RSA attack"""

import re
import hmac
import hashlib

import m39
import m40

# RFC 3447 9.2 EMSA-PKCS1-v1_5 Note 1
#ASN1_SHA256 = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01" \
#              b"\x65\x03\x04\x02\x01\x05\x00\x04\x20"
# We don't use it because we need to forge signatures over 1024-bit RSA and
# the ASN.1 block makes our message too long.
ASN1_SHA256 = b""

def pkcs1v15_pad(data: bytes, bits: int, block_type: int = 1) -> bytes:
    """Generate PKCS#1 v1.5 message block"""
    if block_type not in range(3):
        raise ValueError("block_type must be 0, 1 or 2")

    octets = (bits + 7) // 8

    if octets <= len(data) + 10:
        raise ValueError("size is too small or data is too large")

    bt = block_type.to_bytes(1, "big")
    ps = b"\xff" * (octets - len(data) - 3)
    return b"\x00" + bt + ps + b"\x00" + data

def sign(m: bytes, private_key: m39.RSAKey) -> int:
    """Sign message with RSA private key via PKCS#1 v1.5"""
    digest = hashlib.sha256(m).digest()
    size = private_key.modulus.bit_length()
    block = pkcs1v15_pad(ASN1_SHA256 + digest, size)
    return m39.encrypt(block, private_key)

def verify(m: bytes, signature: int, public_key: m39.RSAKey) -> bool:
    """Insecure RSA signature verification"""
    block = b"\x00" + m39.decrypt(signature, public_key)

    # Insecure PKCS#1 v1.5 padding validation.
    # Assuming SHA-256 here (for ASN.1 and HASH blocks).
    r = re.compile(b"\x00\x01\xff+?\x00" + ASN1_SHA256 + b"(.{32})", re.DOTALL)
    match = r.match(block)
    if not match:
        return False

    return hmac.compare_digest(hashlib.sha256(m).digest(), match.group(1))

def forge_signature(m: bytes, bits: int) -> int:
    """BB'06 via cube root"""
    digest = hashlib.sha256(m).digest()
    block = b"\x00\x01\xff\x00" + ASN1_SHA256 + digest \
            + bytes((bits + 7) // 8 - len(digest) - 4 - len(ASN1_SHA256))

    block_int = m39.to_int(block)
    cube_root = m40.integer_root(block_int, 3)

    return cube_root + 1

def main() -> None:
    m = b"hi mom"
    keypair = m39.keygen(bits=1024)

    s = sign(m, keypair.private)
    assert verify(m, s, keypair.public)

    forgery = forge_signature(m, keypair.public.modulus.bit_length())
    print(hex(forgery))
    assert verify(m, forgery, keypair.public)

if __name__ == "__main__":
    main()
