#!/usr/bin/env python3
"""Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)"""

import m39
import m42

class RSAPaddingOracle:

    def __init__(self, size: int = 256, e: int = 3) -> None:
        keypair = m39.keygen(size, e)
        self.pubkey = keypair.public
        self._private_key = keypair.private

    def padding_ok(self, c: int) -> bool:
        """Check if ciphertext is PKCS#1 v1.5 conforming"""
        m = m39.decrypt(c, self._private_key)
        # We can't check for leading zero byte because it gets lost in integer
        # conversion, so we check length of message is one less than the modulus.
        return self.pubkey.modulus.bit_length() // 8 == len(m) + 1 and m[0] == 2

def pkcs1v15_unpad(m: bytes) -> bytes:
    """Remove PKCS#1 v1.5 padding without validation"""
    return m[2:].split(b"\x00")[1]

def smallest_coefficient(oracle: RSAPaddingOracle, c: int, B: int) -> int:
    """2a: Find smallest integer s_1 corresponding to valid c_0(s_1)^e mod n"""
    n = oracle.pubkey.modulus
    e = oracle.pubkey.exponent

    s = (n + (3 * B) - 1) // (3 * B)

    while True:
        c_prime = (c * pow(s, e, n)) % n
        if oracle.padding_ok(c_prime):
            return s
        s += 1

def s_from_multiple_intervals(oracle: RSAPaddingOracle, c: int, s: int) -> int:
    """2b: Searching with more than one interval left"""
    n = oracle.pubkey.modulus
    e = oracle.pubkey.exponent

    while True:
        s += 1
        c_prime = (c * pow(s, e, n)) % n
        if oracle.padding_ok(c_prime):
            return s

def s_from_interval(oracle: RSAPaddingOracle, c: int, s: int,
                    M_i: set[range], B: int) -> int:
    """2c: Searching with one interval left"""
    assert len(M_i) == 1
    n = oracle.pubkey.modulus
    e = oracle.pubkey.exponent

    interval = next(iter(M_i))
    a, b = interval.start, interval.stop
    r = (2 * (b * s - 2 * B) + n - 1) // n

    while True:
        s_lower = (2 * B + r * n + b - 1) // b
        s_upper = (3 * B + r * n + a - 1) // a
        for s_i in range(s_lower, s_upper):  # + 1?
            c_prime = (c * pow(s_i, e, n)) % n
            if oracle.padding_ok(c_prime):
                return s_i
        r += 1

def intervals(n: int, s: int, M: set[range], B: int) -> set[range]:
    """3: Narrow the set of solutions"""
    M_next: set[range] = set()
    for interval in M:
        a, b = interval.start, interval.stop

        r_lower = (a * s - 3 * B + n) // n
        r_upper = (b * s - 2 * B) // n
        if r_upper < r_lower and M_next:
            return M_next

        for r in range(r_lower, r_upper + 1):
            a_prime = max(a, (2 * B + r * n + s - 1) // s)
            b_prime = min(b, (3 * B - 1 + r * n) // s)
            assert a_prime <= b_prime
            # We add intervals carelessly.
            M_next.add(range(a_prime, b_prime))

    if not M_next:
        raise Exception("Interval is empty")
    return M_next

def attack(oracle: RSAPaddingOracle, c_0: int) -> int:
    """Bleichenbacher attack on PKCS#1 v1.5"""
    # Step 1.
    # We skip blinding since we already have a PKCS conforming c.
    assert oracle.padding_ok(c_0)
    # We don't set s_0 = 1 since we jump straight to s_1 in step 2a.
    k = oracle.pubkey.modulus.bit_length() // 8
    B = 2 ** (8 * (k - 2))
    M_prev = {range(2 * B, 3 * B - 1)}
    i = 1

    while True:
        # Step 2.
        if i == 1:
            # Step 2a.
            s_i = smallest_coefficient(oracle, c_0, B)
        elif i > 1 and len(M_prev) > 1:
            # Step 2b.
            s_i = s_from_multiple_intervals(oracle, c_0, s_i)
        else:
            # Step 2c.
            s_i = s_from_interval(oracle, c_0, s_i, M_prev, B)

        # Step 3.
        M_i = intervals(oracle.pubkey.modulus, s_i, M_prev, B)
        M_prev = M_i

        # Step 4.
        if len(M_i) == 1:
            interval = next(iter(M_i))
            if interval.start == interval.stop:
                # Since we skip blinding, s_0 = 1 so m_0 = m = a.
                return interval.start % oracle.pubkey.modulus
        i += 1

def main() -> None:
    oracle = RSAPaddingOracle()
    m = m42.pkcs1v15_pad(data=b"kick it, CC",
                         bits=oracle.pubkey.modulus.bit_length(),
                         block_type=2)
    c = m39.encrypt(m, oracle.pubkey)

    m_int = attack(oracle, c)
    m_prime = b"\x00" + m39.to_bytes(m_int)
    print(pkcs1v15_unpad(m_prime))
    assert m == m_prime

if __name__ == "__main__":
    main()
