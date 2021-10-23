#!/usr/bin/env python3
"""Hashing with CBC-MAC"""

from m09 import pkcs7
from m10 import decrypt_aes_cbc
from m49 import cbc_mac

BLOCKSIZE = 16

def forge_hash(m: bytes, m_prime: bytes, key: bytes, iv: bytes) -> bytes:
    t = cbc_mac(key, iv, pkcs7(m))
    t_prime = cbc_mac(key, iv, m_prime)

    # We need to find m'' such that E_k(m'' xor t') = t
    # by solving D_k(t) xor t' = m''.

    m_prime_suffix = decrypt_aes_cbc(key, t_prime, t)
    return m_prime + m_prime_suffix

def main() -> None:
    m = b"alert('MZA who was that?');\n"
    key = b"YELLOW SUBMARINE"
    iv = bytes(16)

    # No padding because it aligns with the blocksize.
    m_prime = b"alert('Ayo, the Wu is back!');//"
    forgery = forge_hash(m, m_prime, key, iv)

    assert cbc_mac(key, iv, pkcs7(m)) == cbc_mac(key, iv, forgery)
    print(forgery)

if __name__ == "__main__":
    main()
