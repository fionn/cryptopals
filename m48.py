#!/usr/bin/env python3
"""Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)"""

import m39
import m42
import m47

def main() -> None:
    oracle = m47.RSAPaddingOracle(size=768)
    m = m42.pkcs1v15_pad(data=b"kick it, CC",
                         bits=oracle.pubkey.modulus.bit_length(),
                         block_type=2)
    c = m39.encrypt(m, oracle.pubkey)

    m_int = m47.attack(oracle, c)
    m_prime = b"\x00" + m39.to_bytes(m_int)
    print(m47.pkcs1v15_unpad(m_prime))
    assert m == m_prime

if __name__ == "__main__":
    main()
