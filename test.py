#!/usr/bin/env python3
"""Cryptopals tests"""

import gc
import io
import hmac
import time
import math
import json
import base64
import hashlib
import unittest
from unittest import mock
from functools import cache

from Crypto.Hash import MD4
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange, getrandbits

import m01
import m02
import m03
import m04
import m05
import m06
import m08
import m09
import m10
import m11
import m12
import m13
import m14
import m15
import m16
import m17
import m18
import m21
import m22
import m23
import m24
import m25
import m26
import m27
import m28
import m29
import m30
import m31
import m32
import m33
import m34
import m35
import m36
import m37
import m38
import m39
import m40
import m41
import m42
import m43
import m44
import m45
import m46
import m47
import m49
import m50
import m51
import m52
import m53
import m54

KEY = b"YELLOW SUBMARINE"
IV = bytes(len(KEY))
MESSAGE = b"Attack at dawn"
BLOCKSIZE = 16
PRIME = 197
G = 2

class Test01(unittest.TestCase):
    """Convert hex to base64"""

    def test_hex_to_base64_sanity(self) -> None:
        """hex_to_base64 should pass 0 --> 0"""
        self.assertEqual(m01.hex_to_base64("00"), "AA==")

class Test02(unittest.TestCase):
    """Fixed XOR"""

    def test_fixed_xor_sanity(self) -> None:
        """a xor a = 0, a xor 0 = a"""
        for i in range(256):
            self.assertEqual(m02.fixed_xor(bytes([i]), bytes([i])), b"\x00")
            self.assertEqual(m02.fixed_xor(bytes([i]), b"\x00"), bytes([i]))

    def test_fixed_xor_out_of_range(self) -> None:
        """fixed_xor(x) should fail when x !in [0, 255]"""
        self.assertRaises(ValueError,
                          lambda: m02.fixed_xor(bytes([256]), b"\x00"))

    def test_fixed_xor_different_lengths(self) -> None:
        """xor a and b of differing lengths"""
        with self.assertRaises(ValueError):
            m02.fixed_xor(b"0", b"01")

class Test03(unittest.TestCase):
    """Single-byte XOR cipher"""

    def test_xor_everything_sanity(self) -> None:
        """xor_everything on 0x00 produces [0x00, ..., 0xff]"""
        x = m03.xor_everything(b"\x00")
        self.assertEqual(len(x), 256)
        for i in range(256):
            self.assertEqual(x[i], bytes([i]))

    def test_score_empty_input(self) -> None:
        """score zero for zero-length input"""
        self.assertEqual(m03.score(b""), 0)

class Test04(unittest.TestCase):
    """Detect single-character XOR"""

    def test_find_xored_string(self) -> None:
        """find_xored_string"""
        with open("data/04.txt", "r") as f:
            data = [bytes.fromhex(line) for line in f.read().splitlines()]
        xored_message = b"Now that the party is jumping\n"
        self.assertEqual(m04.find_xored_message(data), xored_message)

class Test05(unittest.TestCase):
    """Implement repeating-key XOR"""

    def test_repeating_key_xor(self) -> None:
        """repeating_key_xor"""
        with open("data/05.txt", "r") as f:
            message = bytes(f.read().rstrip(), "ascii")
        key = b"ICE"
        c = m05.repeating_key_xor(key, message)
        self.assertEqual(c.hex(), "0b3637272a2b2e63622c2e69692a23693a2a3"
                                  "c6324202d623d63343c2a2622632427276527"
                                  "2a282b2f20430a652e2c652a3124333a653e2"
                                  "b2027630c692b20283165286326302e27282f")

class Test06(unittest.TestCase):
    """Break repeating-key XOR"""

    def test_hamming_distance(self) -> None:
        """Hamming distance matches known value"""
        s1, s2 = b"this is a test", b"wokka wokka!!!"
        self.assertEqual(m06.hamming_distance(s1, s2), 37)
        self.assertEqual(m06.hamming_distance(s2, s2), 0)

    def test_hamming_distance_wrong_size(self) -> None:
        """Hamming distance raises on different sizes"""
        s1 = b"different"
        s2 = b"sizes"
        with self.assertRaises(ValueError):
            m06.hamming_distance(s1, s2)

    def test_key(self) -> None:
        """Generate key"""
        with open("data/06.txt", "r") as f:
            cyphertext = base64.b64decode(f.read())
        self.assertEqual(m06.key(cyphertext), b"Terminator X: Bring the noise")

    def test_break_repeating_key_xor(self) -> None:
        """Break repeating key xor"""
        with open("data/06.txt", "r") as f:
            cyphertext = base64.b64decode(f.read())
        self.assertEqual(m06.break_repeating_key_xor(cyphertext)[:33],
                         b"I'm back and I'm ringin' the bell")

class Test08(unittest.TestCase):
    """Detect AES in ECB mode"""

    def test_ecb_score(self) -> None:
        """Trivial values for ecb_score"""
        self.assertEqual(m08.ecb_score(bytes(BLOCKSIZE), BLOCKSIZE), 0)
        self.assertEqual(m08.ecb_score(bytes(2 * BLOCKSIZE), BLOCKSIZE), 1)

    def test_detct_ecb(self) -> None:
        """Detect ECB"""
        with open("data/08.txt", "r") as f:
            g = [bytes.fromhex(cyphertext) for cyphertext in f.read().splitlines()]
        ecb_encrypted = m08.detect_ecb(g, BLOCKSIZE)
        self.assertIsNot(ecb_encrypted, None)
        index = g.index(ecb_encrypted)
        self.assertEqual(index, 132)

class Test09(unittest.TestCase):
    """Implement PKCS#7 padding"""

    def test_de_pkcs7_inverts_pkcs7(self) -> None:
        """de_pkcs7 inverts pkcs7"""
        message = m09.de_pkcs7(m09.pkcs7(MESSAGE))
        self.assertEqual(message, MESSAGE)

    def test_zero_padding(self) -> None:
        """PKCS7 with zero padding"""
        zero_pad_message = b"YELLOW SUBMARINE"
        message = m09.de_pkcs7(m09.pkcs7(zero_pad_message))
        self.assertEqual(message, zero_pad_message)

    def test_pad_big_block(self) -> None:
        """PKCS7 with blocksize too large"""
        blocksize = 256 + len(MESSAGE)
        with self.assertRaises(m09.PKCS7PaddingError):
            m09.pkcs7(MESSAGE, blocksize)

class Test10(unittest.TestCase):
    """Implement CBC mode"""

    def test_aes_cbc_encrypt(self) -> None:
        """encrypt_aes_cbc matches Crypto.Cipher.AES"""
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_cyphertext = cypher.encrypt(m09.pkcs7(MESSAGE))
        cyphertext = m10.encrypt_aes_cbc(KEY, IV, m09.pkcs7(MESSAGE))
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_aes_cbc_decrypt(self) -> None:
        """decrypt_aes_cbc matches Crypto.Cipher.AES"""
        cyphertext = b"x\x9b\xdb\xf8\x93\xae[x\x9a%\xb7\xffT\x1fc\xd5"
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_plaintext = cypher.decrypt(cyphertext)
        plaintext = m10.decrypt_aes_cbc(KEY, IV, cyphertext)
        self.assertEqual(plaintext, crypto_plaintext)

    def test_aes_cbc_symmetry(self) -> None:
        """decrypt_aes_cbc inverts encrypt_aes_cbc"""
        m = m09.pkcs7(MESSAGE)
        cyphertext = m10.encrypt_aes_cbc(KEY, IV, m)
        plaintext = m10.decrypt_aes_cbc(KEY, IV, cyphertext)
        self.assertEqual(m, plaintext)

class Test11(unittest.TestCase):
    """An ECB/CBC detection oracle"""

    def test_detect_ecb(self) -> None:
        """Detect ECB"""
        for _ in range(10):
            cyphertext = m11.encryption_oracle(MESSAGE * 3)
            self.assertIn(m11.detect_ecb(cyphertext), [True, False])

class Test12(unittest.TestCase):
    """Byte-at-a-time ECB decryption (Simple)"""

    def test_blocksize(self) -> None:
        """Detect blocksize"""
        self.assertEqual(m12.blocksize(m12.oracle), 16)

    def test_len_string(self) -> None:
        """Detect string length"""
        self.assertEqual(m12.len_string(m12.oracle), 138)

    def test_break_ecb(self) -> None:
        """Break ECB"""
        self.assertEqual(m12.break_ecb(m12.oracle).split(b"\n")[0],
                         b"Rollin' in my 5.0")

class Test13(unittest.TestCase):
    """ECB cut-and-paste"""

    def test_ecb_cut_and_paste_end_to_end(self) -> None:
        """Forge cookie with ECB cut-and-paste"""
        email = "fake@mail.com"
        admin_cookie = m13.rewrite_cookie(email)
        profile = m13.decrypt_oracle(admin_cookie)
        self.assertEqual(profile["email"], email)
        self.assertEqual(profile["role"], "admin")

class Test14(unittest.TestCase):
    """Byte-at-a-time ECB decryption (Harder)"""

    def test_byte_at_a_time_ecb_decryption_attack(self) -> None:
        """End-to-end byte-at-a-time ECB decryption (harder)"""
        self.assertTrue(m14.break_ecb(m14.oracle))

class Test15(unittest.TestCase):
    """PKCS#7 padding validation"""

    def test_equal_pkcs7_padding(self) -> None:
        """pkcs7 pads correctly"""
        message = b"ICE ICE BABY"
        self.assertEqual(m09.pkcs7(message), m15.pkcs7(message))

    def test_valid_pkcs7_padding(self) -> None:
        """de_pkcs7 validates for correct padding"""
        s = b"ICE ICE BABY"
        s_pad = m09.pkcs7(s)
        self.assertEqual(s, m15.de_pkcs7(s_pad))

    def test_invalid_pkcs7_padding(self) -> None:
        """de_pkcs7 throws for incorrect padding"""
        s_pad = b"ICE ICE BABY\x01\x02\x03\x04"
        self.assertRaises(m09.PKCS7PaddingError, m15.de_pkcs7, s_pad)
        s_pad = b"ICE ICE BABY\x05\x05\x05\x05"
        self.assertRaises(m09.PKCS7PaddingError, m15.de_pkcs7, s_pad)

class Test16(unittest.TestCase):
    """CBC bitflipping attacks"""

    def test_cbc_bitflipping_attack(self) -> None:
        """End-to-end CBC bitflipping attack"""
        plaintext = bytes(16) + b"00000:admin<true"
        cyphertext = m16.oracle(plaintext)
        cyphertext = m16.cbc_bitflip(cyphertext)
        self.assertTrue(m16.is_admin(cyphertext))

class Test17(unittest.TestCase):
    """The CBC padding oracle"""

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_cbc_padding_oracle_attack(self, _: io.StringIO) -> None:
        """End-to-end attack on the CBC padding oracle"""
        c = m17.cbc_oracle()
        m = m17.attack(c)
        self.assertTrue(m)

class Test18(unittest.TestCase):
    """Implement CTR, the stream cipher mode"""

    def test_aes_ctr(self) -> None:
        """aes_ctr matches Crypto.Cipher.AES"""
        ctr = Counter.new(128, initial_value=0)
        cypher = AES.new(KEY, mode=AES.MODE_CTR, counter=ctr)
        crypto_cyphertext = cypher.encrypt(MESSAGE)
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_aes_ctr_symmetry(self) -> None:
        """aes_ctr is symmetric"""
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        plaintext = m18.aes_ctr(cyphertext, KEY)
        self.assertEqual(plaintext, MESSAGE)

class Test21(unittest.TestCase):
    """Implement the MT19937 Mersenne Twister RNG"""

    def test_mersenne_twister(self) -> None:
        """MT19937 returns a known good value"""
        # https://oeis.org/A221557
        mt = m21.MT19937(5489)
        self.assertEqual(mt.random(), 3499211612)

class Test22(unittest.TestCase):
    """Crack an MT19937 seed"""

    @unittest.skip("Extremely long test")
    def test_crack_mt19937_seed(self) -> None:
        """Crack an MT19937 seed, end-to-end"""
        r = m22.sleep_mersenne()
        seed = m22.crack_seed(r)
        clone = m21.MT19937(seed)
        self.assertEqual(clone.random(), r)

    def test_crack_artificial_mt19937_seed(self) -> None:
        """Crack an artificial MT19937 seed"""
        seed = int(time.time()) - 1
        r = m21.MT19937(seed).random()
        seed_candidate = m22.crack_seed(r)
        self.assertEqual(seed, seed_candidate)

class Test23(unittest.TestCase):
    """Clone an MT19937 RNG from its output"""

    def test_clone_mt(self) -> None:
        """mt_clone clones an MT19937 instance"""
        mt = m21.MT19937(5489)
        mt_clone = m23.clone_mt(mt)
        self.assertEqual(mt.random(), mt_clone.random())

class Test24(unittest.TestCase):
    """Create the MT19937 stream cipher and break it"""

    def test_verify_mt19937_crypt(self) -> None:
        """Verify MT19937 steam cipher encryption"""
        self.assertTrue(m24.verify_mt19937_crypt(bytes(10), 0xffff))

    @unittest.skip("Long test")
    def test_crack_mt19937_crypt(self) -> None:
        """Get MT19937 stream cipher seed"""
        seed = getrandbits(16)
        prefix = get_random_bytes(randrange(100))
        plaintext = prefix + b"A" * 14
        cyphertext = m24.mt19937_crypt(plaintext, seed)
        found_seed = m24.crack_mt19937(cyphertext)
        self.assertEqual(found_seed, seed)

    def test_crack_mt19937_crypt_contrived(self) -> None:
        """Given contrived cyphertext, crack MT19937 stream cypher seed"""
        cyphertext = b"d\xaa\xcd\t"
        seed = m24.crack_mt19937(cyphertext)
        self.assertEqual(seed, 1)

class Test25(unittest.TestCase):
    """Break "random access read/write" AES CTR"""

    def test_aes_ctr_rarw_attack(self) -> None:
        """AES-CTR random access read/write attack"""
        c = m18.aes_ctr(MESSAGE, m25.RANDOM_KEY)
        m_prime = m25.break_rarw(c)
        self.assertEqual(MESSAGE, m_prime)

class Test26(unittest.TestCase):
    """CTR bitflipping"""

    def test_ctr_bitflipping(self) -> None:
        """CTR bitflipping attack"""
        plaintext = bytes(5) + b":admin<true"
        cyphertext = m26.oracle(plaintext)
        cyphertext = m26.ctr_bitflip(cyphertext)
        self.assertTrue(m26.is_admin(cyphertext))

class Test27(unittest.TestCase):
    """Recover the key from CBC with IV = Key"""

    def test_ascii_compliant(self) -> None:
        """Pass ASCII compliance check"""
        self.assertTrue(m27.ascii_compliant(b"abc"))

    def test_oracle_plaintext(self) -> None:
        """Query the oracle with ASCII-compliant plaintext"""
        c = m27.bad_cbc_encryption(MESSAGE)
        self.assertIs(m27.oracle(c), None)

    def test_recover_cbc_key_with_equal_key_iv(self) -> None:
        """CBC key recovery with IV = key"""
        c = m27.bad_cbc_encryption(MESSAGE * 3)
        k = m27.cbc_iv_key(c)
        self.assertEqual(k, m27.RANDOM_KEY)

class Test28(unittest.TestCase):
    """Implement a SHA-1 keyed MAC"""

    def test_sha1(self) -> None:
        """SHA1 matches hashlib.sha1"""
        m = b"digest me" * 512
        h = hashlib.sha1(m).hexdigest()
        h_prime = m28.SHA1(m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_sha1_pep_452(self) -> None:
        """SHA1 conforms to PEP 452"""
        h = hashlib.sha1()
        h_prime = m28.SHA1()
        self.assertEqual(h.digest_size, h_prime.digest_size)
        self.assertEqual(h.block_size, h_prime.block_size)
        self.assertEqual(h.name, h_prime.name)

    def test_sha1_empty_message(self) -> None:
        """SHA1 of empty message matches empty hash"""
        m = b""
        hs = set()

        hs.add(m28.SHA1().hexdigest())
        hs.add(m28.SHA1(m).hexdigest())

        h = m28.SHA1()
        h.update(m)
        hs.add(h.hexdigest())

        h = m28.SHA1(m)
        h.update(m)
        hs.add(h.hexdigest())

        hs.add(hashlib.sha1(m).hexdigest())

        self.assertEqual(hs, set(["da39a3ee5e6b4b0d3255bfef95601890afd80709"]))

    def test_sha1_long_input(self) -> None:
        """SHA1 of variable message length matches hashlib.sha1"""
        for i in range(513):
            m = bytes(i)
            h = hashlib.sha1(m).hexdigest()
            h_prime = m28.SHA1(m).hexdigest()
            self.assertEqual(h, h_prime)

    def test_sha1_mac(self) -> None:
        """sha1_mac matches hashlib.sha1"""
        m = b"digest me" * 512
        k = b"it is authentic"
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_sha1_mac_empty_message(self) -> None:
        """sha1_mac with empty message matches hashlib.sha1"""
        m = b""
        k = b"it is authentic"
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_sha1_mac_empty_key(self) -> None:
        """sha1_mac with empty key matches hashlib.sha1"""
        m = b"not very authenticated"
        k = b""
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_sha1_mac_empty_message_and_key(self) -> None:
        """sha1_mac with empty message and key matches hashlib.sha1"""
        m, k = b"", b""
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_sha1_mac_cascade(self) -> None:
        """sha1_mac cannot be tampered with"""
        m = b"digest me"
        m_prime = b"digest he"
        k = b"it is authentic"
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m_prime, k))

    def test_sha1_mac_different_key(self) -> None:
        """sha1_mac cannot authenticate with different key"""
        m = b"digest me"
        k = b"it is authentic"
        k_prime = b"inauthentic"
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m, k_prime))

    def test_sha1_update(self) -> None:
        """SHA1 updates correctly"""
        m1 = b"A" * 512
        m2 = b"B" * 512
        h = m28.SHA1()
        h.update(m1)
        h.update(m2)
        h_combined = m28.SHA1(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())
        self.assertEqual(h.hexdigest(), hashlib.sha1(m1 + m2).hexdigest())

    def test_sha1_initialisation(self) -> None:
        """SHA1 initialises correctly"""
        m = b"could be anything"
        h1 = m28.SHA1(m)
        h2 = m28.SHA1()
        h2.update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())

    def test_copy(self) -> None:
        """Copy SHA1 object"""
        h = m28.SHA1(MESSAGE)
        h_prime = h.copy()
        self.assertEqual(h.digest(), h_prime.digest())

class Test29(unittest.TestCase):
    """Break a SHA-1 keyed MAC using length extension"""

    def test_get_sha1_state(self) -> None:
        """Get the internal state of a SHA-1 object"""
        h = m28.SHA1()
        self.assertEqual(m29.sha1_state_from_binary(h.digest()),
                         m29.sha1_state_from_object(h))

    def test_break_sha1_mac_length_extension(self) -> None:
        """Break a SHA-1 keyed MAC using length extension"""
        m = b"comment1=cooking%20MCs;userdata=foo;" \
            b"comment2=%20like%20a%20pound%20of%20bacon"
        k = get_random_bytes(randrange(50))
        z = b";admin=true"

        # server-side
        d = m28.sha1_mac(m, k)
        m_prime = m + bytearray(m29.md_padding(k + m)) + z

        # client-side
        for q in m29.extend_sha1(d, z):
            if m29.verify_sha1_mac(q, m_prime, k):
                return
        self.fail("No extended HMAC validated")

class Test30(unittest.TestCase):
    """Break an MD4 keyed MAC using length extension"""

    def test_md4_test_vectors(self) -> None:
        """MD4 digests test vectors correctly (RFC1320)"""
        v = b""
        self.assertEqual(m30.MD4(v).hexdigest(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        v = b"a"
        self.assertEqual(m30.MD4(v).hexdigest(), "bde52cb31de33e46245e05fbdbd6fb24")
        v = b"abc"
        self.assertEqual(m30.MD4(v).hexdigest(), "a448017aaf21d8525fc10ae87aa6729d")
        v = b"message digest"
        self.assertEqual(m30.MD4(v).hexdigest(), "d9130a8164549fe818874806e1c7014b")
        v = b"abcdefghijklmnopqrstuvwxyz"
        self.assertEqual(m30.MD4(v).hexdigest(), "d79e1c308aa5bbcdeea8ed63df412da9")
        v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        self.assertEqual(m30.MD4(v).hexdigest(), "043f8582f241db351ce627e153e7f0e4")
        v = b"1234567890123456789012345678901234567890" \
            b"1234567890123456789012345678901234567890"
        self.assertEqual(m30.MD4(v).hexdigest(), "e33b4ddc9c38f2199c3e7b164fcc0536")

    def test_md4_long_input(self) -> None:
        """MD4 of variable message length matches Crypto.Hash.MD4"""
        for i in range(513):
            m = bytes(i)
            h = m30.MD4(m)
            h_prime = MD4.new(m)
            self.assertEqual(h.digest(), h_prime.digest())

    def test_md4_initialisation(self) -> None:
        """MD4 initialises correctly"""
        m = b"could be anything"
        h1 = m30.MD4(m)
        h2 = m30.MD4()
        h2.update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())

    def test_md4_update(self) -> None:
        """MD4 updates correctly"""
        m1 = b"A" * 512
        m2 = b"B" * 512
        h = m30.MD4()
        h.update(m1)
        h.update(m2)
        h_combined = m30.MD4(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())

    def test_md4_mac(self) -> None:
        """md4_mac matches Crypto.Hash.MD4"""
        m = b"digest me" * 512
        k = b"it is authentic"
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_md4_mac_empty_message(self) -> None:
        """md4_mac with empty message matches Crypto.Hash.MD4"""
        m = b""
        k = b"it is authentic"
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_md4_mac_empty_key(self) -> None:
        """md4_mac with empty key matches Crypto.Hash.MD4"""
        m = b"not very authenticated"
        k = b""
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_md4_mac_empty_message_and_key(self) -> None:
        """md4_mac with empty message and key matches Crypto.Hash.MD4"""
        m, k = b"", b""
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_md4_mac_cascade(self) -> None:
        """md4_mac cannot be tampered with"""
        m = b"digest me"
        m_prime = b"digest he"
        k = b"it is authentic"
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m_prime, k))

    def test_md4_mac_different_key(self) -> None:
        """md4_mac cannot authenticate with different key"""
        m = b"digest me"
        k = b"it is authentic"
        k_prime = b"inauthentic"
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m, k_prime))

    def test_md4_copy(self) -> None:
        """Copy MD4 object"""
        h = m30.MD4(MESSAGE)
        h_prime = h.copy()
        self.assertEqual(h.digest(), h_prime.digest())

    def test_md4_state_from_hex(self) -> None:
        """Extract MD4 register from hex digest"""
        h = m30.MD4(b"fud for thought")
        register = m30.md4_state_from_hex(h.hexdigest())
        self.assertEqual(register, m30.md4_state_from_object(h))

    def test_md4_state_from_binary(self) -> None:
        """Extract MD4 register from binary digest"""
        h = m30.MD4(b"fud for thought")
        register = m30.md4_state_from_binary(h.digest())
        self.assertEqual(register, m30.md4_state_from_object(h))

    def test_verify_md4_mac(self) -> None:
        """Verify MD4 MAC"""
        mac = m30.md4_mac(MESSAGE, KEY)
        self.assertTrue(m30.verify_md4_mac(mac, MESSAGE, KEY))

    def test_md_padding(self) -> None:
        """MD padding"""
        data = b"llllll"
        padding = m30.md_padding(data)
        padding_prime = b"\x80" \
                        + bytes((56 - len(data) - 1 % m30.MD4.block_size)
                                     % m30.MD4.block_size) \
                        + (8 * len(data)).to_bytes(8, "little")
        self.assertEqual(padding, padding_prime)

    def test_extend_md4(self) -> None:
        """Extended MD4 MAC forgery"""
        m = MESSAGE
        k = KEY
        z = b"No, dusk!"

        mac = m30.md4_mac(m, k)
        m_prime = m + bytearray(m30.md_padding(k + m)) + z

        verification = [m30.verify_md4_mac(q, m_prime, k)
                        for q in m30.extend_md4(mac, z)]

        self.assertIn(True, verification)

class Test31(unittest.TestCase):
    """Implement and break HMAC-SHA1 with an artificial timing leak"""

    def test_hmac_sha1(self) -> None:
        """hmac_sha1 matches hmac.new(k, m, sha1)"""
        k = KEY
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_hmac_sha1_large_key(self) -> None:
        """hmac_sha1 with large key"""
        k = 128 * KEY
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_hmac_sha1_equal_sized_key(self) -> None:
        """hmac_sha1 with large key"""
        k = bytes(64)
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_insecure_compare_identical(self) -> None:
        """insecure_compare identifies identical bytes"""
        a = b"identical bytes"
        self.assertTrue(m31.insecure_compare(a, a, 0))

    def test_insecure_compare_different(self) -> None:
        """insecure_compare distinguishes different bytes"""
        a = b"different bytes"
        b = b"different bytez"
        self.assertFalse(m31.insecure_compare(a, b, 0))

    def test_insecure_compare_different_size(self) -> None:
        """insecure_compare raises for different sizes"""
        a = b"different"
        b = b"sizes"
        with self.assertRaises(ValueError):
            m31.insecure_compare(a, b, 0)

    def test_verify_hmac_sha1_hex(self) -> None:
        """verify HMAC"""
        k, m = KEY, MESSAGE
        signature = m31.hmac_sha1(k, m).hexdigest().encode()
        self.assertTrue(m31.verify_hmac_sha1_hex(m, signature, k, 0))

    def test_instantiate_listener(self) -> None:
        """Instantiate listener"""
        local_server = ("localhost", 9131)
        listener = m31.HMACListener(local_server, KEY, delay=0.025)
        self.assertTrue(listener)
        listener.run()
        listener.stop()

    @unittest.skip("Extremely long test")
    def test_hmac_sha1_attack(self) -> None:
        """End-to-end HMAC-SHA1 attack (artificial timing leak)"""
        file_name = b"foo"
        key = get_random_bytes(16)
        local_server = ("localhost", 9131)

        listener = m31.HMACListener(local_server, key, delay=0.025)
        listener.run()

        try:
            hmac_attack = m31.HMACAttack(local_server)
            hex_hmac = hmac_attack.get_sha1_hmac(file_name.decode())
            self.assertEqual(hex_hmac, m31.hmac_sha1(key, file_name).hexdigest())
        finally:
            listener.stop()

class Test32(unittest.TestCase):
    """Break HMAC-SHA1 with a slightly less artificial timing leak"""

    def test_instantiate_attack(self) -> None:
        """Instantiate the attack class"""
        local_server = ("localhost", 9132)
        hmac_attack = m32.HMACAttack(local_server, 10)
        self.assertTrue(hmac_attack)

    @unittest.skip("Extremely long test")
    def test_hmac_sha1_attack(self) -> None:
        """End-to-end HMAC-SHA1 attack (realistic timing leak)"""
        file_name = b"foo"
        key = get_random_bytes(16)
        local_server = ("localhost", 9132)

        listener = m31.HMACListener(local_server, key, delay=0.005)
        hmac_attack = m32.HMACAttack(local_server, 10)
        listener.run()

        try:
            hex_hmac = hmac_attack.get_sha1_hmac(file_name.decode())
            self.assertEqual(hex_hmac, m31.hmac_sha1(key, file_name).hexdigest())
        finally:
            listener.stop()

class Test33(unittest.TestCase):
    """Implement Diffie-Hellman"""

    def test_dh_key_exchange(self) -> None:
        """Diffie-Hellman peers agree on shared secret"""
        s_a, s_b = m33.dh_key_exchange(PRIME, G)
        self.assertEqual(s_a, s_b)

class Test34(unittest.TestCase):
    """Implement a MITM key-fixing attack on Diffie-Hellman
       with parameter injection"""

    def test_dh_protocol(self) -> None:
        """Diffie-Hellman peer receives message"""
        received_message = m34.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(received_message, MESSAGE)

    def test_dh_parameter_injection(self) -> None:
        """Diffie-Hellman parameter injection intercepts message"""
        intercepted = m34.dh_parameter_injection(PRIME, G, MESSAGE)
        self.assertEqual(intercepted, MESSAGE)

class Test35(unittest.TestCase):
    """Implement DH with negotiated groups,
       and break with malicious g parameters"""

    def tearDown(self) -> None:
        gc.collect()

    def test_dh_protocol(self) -> None:
        """Diffie-Hellman TCP peer receives message"""
        plaintext = m35.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(plaintext, MESSAGE)

    def test_dh_malicious_g_is_1(self) -> None:
        """Diffie-Hellman inject malicious parameter g = 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, 1)
        self.assertEqual(plaintext, MESSAGE)

    def test_dh_malicious_g_is_p(self) -> None:
        """Diffie-Hellman inject malicious parameter g = p"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME)
        self.assertEqual(plaintext, MESSAGE)

    def test_dh_malicious_g_is_p_minus_1(self) -> None:
        """Diffie-Hellman inject malicious parameter g = p - 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME - 1)
        self.assertEqual(plaintext, MESSAGE)

class Test36(unittest.TestCase):
    """Implement Secure Remote Password (SRP)"""

    def test_client_pubkey(self) -> None:
        """client-side public key"""
        carol = m36.Client(PRIME, "e@ma.il", "pw", 2, 3)
        carol.pubkey()
        self.assertEqual(carol.A, carol.pubkey())

    def test_server_pubkey(self) -> None:
        """server-side public key"""
        parameters: m36.Parameters = {"N": PRIME,
                                      "g": 2,
                                      "k": 3,
                                      "I": "some@ema.il",
                                      "p": "password"
                                     }
        steve = m36.Server()
        steve.negotiate_receive(parameters)
        steve.verifier()
        steve.pubkey()
        self.assertEqual(steve.B, steve.pubkey())

    def test_bad_email(self) -> None:
        """mismatched emails"""
        parameters: m36.Parameters = {"N": PRIME,
                                      "g": 2,
                                      "k": 3,
                                      "I": "some@ema.il",
                                      "p": "password"
                                     }
        steve = m36.Server()
        steve.negotiate_receive(parameters)
        bad_parameters: m36.EmailPubKey = {"I": "diff@e.mail", "pubkey": 123}
        self.assertRaises(ValueError,
                          lambda: steve.receive_email_pubkey(bad_parameters))

    def test_bad_hmac(self) -> None:
        """hmacs don't match"""
        parameters: m36.Parameters = {"N": PRIME,
                                      "g": 2,
                                      "k": 3,
                                      "I": "some@ema.il",
                                      "p": "password"
                                     }
        steve = m36.Server()
        steve.negotiate_receive(parameters)
        steve.scrambler()
        steve.verifier()
        steve.pubkey()
        steve.A = 123
        steve.gen_K()
        response = steve.receive_hmac("deadbeef")
        self.assertFalse(response)

    def test_srp_protocol(self) -> None:
        """SRP protocol server verification"""
        carol = m36.Client(m36.prime(), email="not@real.email",
                           password="submarines")
        steve = m36.Server()
        result = m36.srp_protocol(carol, steve)
        self.assertTrue(result)

class Test37(unittest.TestCase):
    """Break SRP with a zero key"""

    def test_srp_zero_key(self) -> None:
        """Break SRP with a zero key"""
        carol = m37.CustomKeyClient(m36.prime(), email="not@real.email",
                                    password="submarines")
        steve = m36.Server()
        carol.A = 0
        result = m36.srp_protocol(carol, steve)
        self.assertTrue(result)

    def test_srp_multiple_prime_key(self) -> None:
        """Break SRP with a zero key"""
        prime = m36.prime()
        for i in range(1, 4):
            with self.subTest(i=i):
                carol = m37.CustomKeyClient(prime, email="not@real.email",
                                            password="submarines")
                steve = m36.Server()
                carol.A = i * prime
                result = m36.srp_protocol(carol, steve)
                self.assertTrue(result)

class Test38(unittest.TestCase):
    """Offline dictionary attack on simplified SRP"""

    def test_simple_srp(self) -> None:
        """Implement simple SRP"""
        client = m38.SimpleClient(PRIME, G,
                                  username="srp-client@cryptopals.com",
                                  password="yolo")
        server = m38.SimpleServer(PRIME, G)
        self.assertTrue(m38.simple_srp(client, server))

    @unittest.skip("Requires a wordlist file")
    def test_mitm_simple_srp(self) -> None:
        """Crack simple SRP (with wordlist file)"""
        prime = m36.prime()
        password = "aardvark"
        client = m38.SimpleClient(prime, G,
                                  username="srp-client@cryptopals.com",
                                  password=password)
        evil_server = m38.EvilServer(prime, G)

        candidate_password = m38.mitm_simple_srp(client, evil_server)
        self.assertEqual(candidate_password, password)

    @mock.patch.object(m38.EvilServer, "_words")
    def test_mitm_simple_srp_no_io(self, _words: mock.Mock) -> None:
        """Crack simple SRP"""
        prime = m36.prime()

        password = "aardvark"
        _words.return_value = [password]

        client = m38.SimpleClient(prime, G,
                                  username="srp-client@cryptopals.com",
                                  password=password)
        evil_server = m38.EvilServer(prime, G)

        candidate_password = m38.mitm_simple_srp(client, evil_server)
        self.assertEqual(candidate_password, password)

class Test39(unittest.TestCase):
    """Implement RSA"""

    def test_gcd(self) -> None:
        """Sanity check Euclidean GCD"""
        interval = range(-10, 10)
        for a in interval:
            for b in interval:
                self.assertEqual(m39.gcd(a, b), math.gcd(a, b))

    def test_lcm(self) -> None:
        """Sanity check LCM"""
        interval = range(-10, 10)
        for a in interval:
            for b in interval:
                self.assertEqual(m39.lcm(a, b), math.lcm(a, b))

    def test_modular_inverse(self) -> None:
        """Calculate modular inverse"""
        self.assertEqual(m39.invmod(3, 7), 5)
        self.assertEqual(m39.invmod(17, 3120), 2753)
        self.assertEqual(m39.invmod(17, 3120), pow(17, -1, 3120))

    def test_modular_inverse_does_not_exist(self) -> None:
        """Calculate modular inverse when it doesn't exist"""
        with self.assertRaises(ValueError):
            m39.invmod(3, 3)

    def test_keygen_size(self) -> None:
        """Sanity check keypair for bit size and modulus"""
        e = 3
        size = 128
        public, private = m39.keygen(size, e)
        self.assertEqual(size, public.modulus.bit_length())
        self.assertEqual(public.modulus, private.modulus)
        self.assertEqual(public.exponent, e)
        self.assertGreater(private.exponent, e)

    def test_integer_encryption(self) -> None:
        """RSA encryption and decryption of integer data"""
        public, private = m39.keygen(128)
        m = 42
        c = m39.encrypt_int(m, public)
        m_prime = m39.decrypt_int(c, private)
        self.assertEqual(m, m_prime)

    def test_binary_encryption(self) -> None:
        """RSA encryption and decryption of binary data"""
        public, private = m39.keygen(128)
        m = MESSAGE
        c = m39.encrypt(m, public)
        m_prime = m39.decrypt(c, private)
        self.assertEqual(m, m_prime)

    def test_small_modulus(self) -> None:
        """RSA encryption fails with small modulus"""
        size = 128
        public, _ = m39.keygen(size)
        m = 2 ** size
        with self.assertRaises(ValueError):
            m39.encrypt_int(m, public)

class Test40(unittest.TestCase):
    """Implement an e = 3 RSA broadcast attack"""

    def test_integer_root(self) -> None:
        """Find the integer nth root"""
        x = 4
        e = 6
        self.assertEqual(m40.integer_root(x ** e, e), x)

    def test_integer_root_of_zero(self) -> None:
        """Calculate the integer square root of 0"""
        self.assertEqual(m40.integer_root(0, 2), 0)

    def test_zeroth_root(self) -> None:
        """Calculate the 0th root"""
        with self.assertRaises(ZeroDivisionError):
            m40.integer_root(2, 0)

    def test_crt(self) -> None:
        """Calculate CRT for a simple system"""
        a = [0, 3, 4]
        n = [3, 4, 5]
        self.assertEqual(m40.crt(a, n), 39)

    def test_crt_impossible_system(self) -> None:
        """Calculate CRT when arguments don't define a system"""
        a = [0]
        n = [4, 5]
        with self.assertRaises(ValueError):
            m40.crt(a, n)

    def test_broadcast(self) -> None:
        """Break RSA with Håstad's broadcast attack"""
        k = []
        c = []
        for _ in range(3):
            k_i, c_i = m40.generate_key_and_encrypt(MESSAGE)
            k.append(k_i)
            c.append(c_i)

        m_prime = m39.to_bytes(m40.broadcast_attack(k, c))
        self.assertEqual(MESSAGE, m_prime)

class Test41(unittest.TestCase):
    """Implement unpadded message recovery oracle"""

    def test_repeated_decryption(self) -> None:
        """Try to decrypt multiple times"""
        server = m41.DecryptionServer(size=512)
        c = m39.encrypt(MESSAGE, server.public_key)
        server.decrypt(c)
        with self.assertRaises(RuntimeError):
            server.decrypt(c)

    def test_recover_message(self) -> None:
        """Recover plaintext via transformation"""
        server = m41.DecryptionServer(size=512)
        c = m39.encrypt(MESSAGE, server.public_key)
        server.decrypt(c)
        m = m41.recover_message(c, server)
        self.assertEqual(m, MESSAGE)

class Test42(unittest.TestCase):
    """Bleichenbacher's e = 3 RSA Attack"""

    def test_pkcs1v15_pad(self) -> None:
        """Pad a message with PKCS#1 v1.5"""
        eb = m42.pkcs1v15_pad(MESSAGE, 256)
        self.assertEqual(eb[0], 0)
        self.assertEqual(eb[1], 1)
        for element in eb[2:9]:
            self.assertNotEqual(element, 0)
        self.assertIn(0, eb[10:])

    def test_pkcs1v15_pad_bad_type(self) -> None:
        """Pad a message with non-existent block type"""
        with self.assertRaises(ValueError):
            m42.pkcs1v15_pad(MESSAGE, 256, block_type=3)

    def test_pkcs1v15_pad_message_too_big(self) -> None:
        """Pad a message that's too big for the size"""
        with self.assertRaises(ValueError):
            m42.pkcs1v15_pad(MESSAGE, 128)

    def test_sign_and_verify(self) -> None:
        """Sign a message and verify the signature"""
        keypair = m39.keygen(bits=512)
        s = m42.sign(MESSAGE, keypair.private)
        self.assertTrue(m42.verify(MESSAGE, s, keypair.public))

    def test_verify_no_match(self) -> None:
        """Try to verify an obviously bad signature"""
        keypair = m39.keygen(bits=512)
        fake_signature = 123456789012
        self.assertFalse(m42.verify(MESSAGE, fake_signature, keypair.public))

    def test_forge_signature(self) -> None:
        """BB'06 via cube root"""
        m = MESSAGE
        keypair = m39.keygen(bits=1024)
        s = m42.forge_signature(m, keypair.public.modulus.bit_length())
        self.assertTrue(m42.verify(m, s, keypair.public))

class Test43(unittest.TestCase):
    """DSA key recovery from nonce"""

    @staticmethod
    @cache
    def data() -> dict[str, str]:
        """Load data from file"""
        with open("data/43.txt") as data_fd:
            return json.load(data_fd)  # type: ignore

    def test_verify_dsa_signature(self) -> None:
        """Sign a message and verify the DSA signature"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}

        keypair = m43.keygen(**parameters)
        signature = m43.sign(MESSAGE, keypair.x, **parameters)
        self.assertTrue(m43.verify(MESSAGE, signature,
                                   keypair.y, **parameters))

    def test_test_bad_dsa_signature(self) -> None:
        """Verify a message with a bad signature"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}

        bad_sig = m43.DSASignature(parameters["q"], 0)
        self.assertFalse(m43.verify(MESSAGE, bad_sig, 0, **parameters))
        bad_sig = m43.DSASignature(1, parameters["q"])
        self.assertFalse(m43.verify(MESSAGE, bad_sig, 0, **parameters))

    def test_test_vectors(self) -> None:
        """Check given messages hashes as expected"""
        data = self.data()
        m = data["m"].encode()
        h_m = m39.to_int(m28.SHA1(m).digest())
        self.assertEqual(h_m, 0xd2d0714f014a9784047eaeccf956520045c45265)

    def test_validate_expected_good_signature(self) -> None:
        """Check given message has valid signature"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}
        m = data["m"].encode()
        y = int(data["y"], 16)
        r = int(data["r"])
        s = int(data["s"])

        signature = m43.DSASignature(r, s)
        self.assertTrue(m43.verify(m, signature, y, **parameters))

    @unittest.skip("Long test")
    def test_brute_force_recover_key(self) -> None:
        """Recover private key by guessing random subkey k"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}
        m = data["m"].encode()
        y = int(data["y"], 16)
        r = int(data["r"])
        s = int(data["s"])

        signature = m43.DSASignature(r, s)

        k_max = 2 ** 16
        try:
            x, k = m43.brute_force_recover_key(m, signature, y,
                                               0, k_max, **parameters)
            self.assertEqual(k, 16575)
            self.assertEqual(x, 125489817134406768603130881762531825565433175625)
        except RuntimeError:
            self.fail("Failed to recover private key from DSA signature")

    def test_brute_force_recover_key_with_known_k(self) -> None:
        """Recover private key by providing known subkey k"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}
        m = data["m"].encode()
        y = int(data["y"], 16)
        r = int(data["r"])
        s = int(data["s"])

        signature = m43.DSASignature(r, s)

        k_min = 16574
        k_max = 16576
        try:
            x, k = m43.brute_force_recover_key(m, signature, y,
                                               k_min, k_max, **parameters)
            self.assertEqual(x, 125489817134406768603130881762531825565433175625)
        except RuntimeError:  # pragma: no cover
            self.fail("Failed to recover private key from DSA signature")

    def test_brute_force_recover_key_with_no_valid_k(self) -> None:
        """Try to recover private key without valid k"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}
        m = data["m"].encode()
        y = int(data["y"], 16)
        r = int(data["r"])
        s = int(data["s"])

        signature = m43.DSASignature(r, s)

        with self.assertRaises(RuntimeError):
            m43.brute_force_recover_key(m, signature, y, 0, 1, **parameters)

    def test_known_x(self) -> None:
        """Check x hashes to expected value"""
        x = 125489817134406768603130881762531825565433175625
        h_x = m39.to_int(m28.SHA1(hex(x)[2:].encode()).digest())
        self.assertEqual(h_x, 0x0954edd5e0afe5542a4adf012611a91912a3ec16)

class Test44(unittest.TestCase):
    """DSA nonce recovery from repeated nonce"""

    def test_verify_input(self) -> None:
        """Check input messages have expected hashes"""
        messages = m44.get_messages()
        for message in messages:
            h_m = m39.to_int(m28.SHA1(message["msg"]).digest())
            self.assertEqual(h_m, message["m"])

    def test_signatures_validate(self) -> None:
        """Validate message signatures"""
        y = m44.PUBLIC_KEY
        parameters = m44.get_parameters()
        p, q, g = parameters.values()
        messages = m44.get_messages()

        for message in messages:
            signature = m43.DSASignature(message["r"], message["s"])
            self.assertTrue(m43.verify(message["msg"], signature, y, p, q, g))

    def test_candidate_messages_exist(self) -> None:
        """Check inputs are vulnerable"""
        messages = m44.get_messages()
        message_groups = m44.group_by_repeated_k(messages)
        groups_of_more_than_one = [x for x in message_groups if len(x) > 1]
        self.assertTrue(len(groups_of_more_than_one) > 1)

    def test_recover_private_key(self) -> None:
        """Check x hashes to expected value"""
        messages = m44.get_messages()
        parameters = m44.get_parameters()
        q = parameters["q"]

        message_groups = m44.group_by_repeated_k(messages)
        message_group = [x for x in message_groups if len(x) > 1][0]

        k = m44.recover_k(message_group[0], message_group[1], q)

        message = message_group[0]
        m = message["msg"]
        signature = m43.DSASignature(message["r"], message["s"])
        x = m43.recover_private_key(m, signature, k, q)

        h_x = m39.to_int(m28.SHA1(hex(x)[2:].encode()).digest())
        self.assertEqual(h_x, 0xca8f6f7c66fa362d40760d135b763eb8527d3d52)

    def test_consistent_x(self) -> None:
        """Check x is independent of mesage pair choice"""
        messages = m44.get_messages()
        parameters = m44.get_parameters()
        q = parameters["q"]

        message_groups = m44.group_by_repeated_k(messages)
        message_groups = [x for x in message_groups if len(x) > 1]

        xs = set()

        for message_group in message_groups:
            k = m44.recover_k(message_group[0], message_group[1], q)

            for message in message_group:
                m = message["msg"]
                signature = m43.DSASignature(message["r"], message["s"])
                x = m43.recover_private_key(m, signature, k, q)
                xs.add(x)

        self.assertEqual(len(xs), 1)

    def test_public_key_derives_from_x(self) -> None:
        """Derive the public key y from the recovered private key"""
        messages = m44.get_messages()
        parameters = m44.get_parameters()
        p, q, g = parameters.values()

        message_groups = m44.group_by_repeated_k(messages)
        message_group = [x for x in message_groups if len(x) > 1][0]

        k = m44.recover_k(message_group[0], message_group[1], q)

        message = message_group[0]
        m = message["msg"]
        signature = m43.DSASignature(message["r"], message["s"])
        x = m43.recover_private_key(m, signature, k, q)
        self.assertEqual(m44.PUBLIC_KEY, pow(g, x, p))

class Test45(unittest.TestCase):
    """DSA parameter tampering"""

    def test_g_0(self) -> None:
        """Forge signature with g = 0"""
        p, q, _ = m44.get_parameters().values()
        g = 0

        keypair = m43.keygen(p, q, g)

        m_1 = b"Hello, world"
        m_2 = b"Goodbye, world"

        signature_1 = m45.sign_relaxed(m_1, keypair.x, p, q, g)
        signature_2 = m45.sign_relaxed(m_2, keypair.x, p, q, g)

        self.assertTrue(m45.verify_relaxed(m_1, signature_1, keypair.y, p, q, g))
        self.assertTrue(m45.verify_relaxed(m_2, signature_2, keypair.y, p, q, g))

        self.assertTrue(m45.verify_relaxed(m_1, signature_2, keypair.y, p, q, g))
        self.assertTrue(m45.verify_relaxed(m_2, signature_1, keypair.y, p, q, g))

    def test_g_1(self) -> None:
        """Forge signature with g = 1 mod p"""
        p, q, _ = m44.get_parameters().values()
        g = p + 1

        keypair = m43.keygen(p, q, g)

        m_1 = b"Hello, world"
        m_2 = b"Goodbye, world"

        signature_1 = m43.sign(m_1, keypair.x, p, q, g)
        signature_2 = m43.sign(m_2, keypair.x, p, q, g)

        self.assertTrue(m43.verify(m_1, signature_1, keypair.y, p, q, g))
        self.assertTrue(m43.verify(m_2, signature_2, keypair.y, p, q, g))

        self.assertTrue(m43.verify(m_1, signature_2, keypair.y, p, q, g))
        self.assertTrue(m43.verify(m_2, signature_1, keypair.y, p, q, g))

        self.assertTrue(m43.verify(MESSAGE, signature_1, keypair.y, p, q, g))

    def test_magic_signature(self) -> None:
        """Forge signature with magic"""
        p, q, g = m44.get_parameters().values()

        keypair = m43.keygen(p, q, g)

        m_1 = b"Hello, world"
        m_2 = b"Goodbye, world"

        magic_signature = m45.magic_signature_generator(keypair.y, p, q)

        g = p + 1

        self.assertTrue(m43.verify(m_1, magic_signature, keypair.y, p, q, g))
        self.assertTrue(m43.verify(m_2, magic_signature, keypair.y, p, q, g))

class Test46(unittest.TestCase):
    """RSA parity oracle"""

    def test_parity(self) -> None:
        """Test parity oracle"""
        oracle = m46.RSAParityOracle(32)
        c_even = m39.encrypt_int(2, oracle.pubkey)
        c_odd = m39.encrypt_int(3, oracle.pubkey)
        self.assertTrue(oracle.is_even(c_even))
        self.assertFalse(oracle.is_even(c_odd))

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_attack_parity_oracle(self, _: io.StringIO) -> None:
        """Decrypt via parity oracle"""
        oracle = m46.RSAParityOracle(128)
        c = m39.encrypt(MESSAGE, oracle.pubkey)
        m = m46.parity_oracle_attack(c, oracle)
        self.assertEqual(m, MESSAGE)

class Test47(unittest.TestCase):
    """Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)"""

    @staticmethod
    def static_keygen() -> m39.RSAKeyPair:
        """Generate a key-pair for fast attack"""
        n = 0xb4eaed55a442a4957ed84162c4523e24ec2bc7984fe56690cb8911bf9d687d85
        e = 0x1e27278e460b1b6e3fceb590760db505c7fd0ccbfa74d419835688126e860f2d
        return m39.RSAKeyPair(m39.RSAKey(exponent=3, modulus=n),
                              m39.RSAKey(exponent=e, modulus=n))

    def test_padding_ok(self) -> None:
        """Test oracle padding verification"""
        oracle = m47.RSAPaddingOracle()
        m = m42.pkcs1v15_pad(data=MESSAGE,
                             bits=oracle.pubkey.modulus.bit_length(),
                             block_type=2)
        c = m39.encrypt(m, oracle.pubkey)
        self.assertTrue(oracle.padding_ok(c))

    @unittest.skip("Potentially long test")
    def test_smallest_coefficient(self) -> None:
        """Test step 2a: find smallest s_1"""
        oracle = m47.RSAPaddingOracle()
        n = oracle.pubkey.modulus
        m = m42.pkcs1v15_pad(data=MESSAGE,
                             bits=n.bit_length(),
                             block_type=2)
        c_0 = m39.encrypt(m, oracle.pubkey)

        k = n.bit_length() // 8
        B = 2 ** (8 * (k - 2))
        s_1 = m47.smallest_coefficient(oracle, c_0, B)
        c_1 = (c_0 * pow(s_1, oracle.pubkey.exponent, n)) % n

        self.assertGreater(s_1, n // (3 * B))
        self.assertTrue(oracle.padding_ok(c_1))

    @unittest.skip("Potentially long test")
    def test_bleichenbacker_pkcs_attack(self) -> None:
        """Bleichenbacker's PKCS#1 v1.5 attack"""
        oracle = m47.RSAPaddingOracle()
        m = m42.pkcs1v15_pad(data=MESSAGE,
                             bits=oracle.pubkey.modulus.bit_length(),
                             block_type=2)
        c = m39.encrypt(m, oracle.pubkey)
        m_int = m47.attack(oracle, c)
        m_prime = b"\x00" + m39.to_bytes(m_int)
        self.assertEqual(m_prime, m)

    def test_bleichenbacker_pkcs_fast_attack(self) -> None:
        """Bleichenbacker's PKCS#1 v1.5 attack with fast keypair"""
        fast_keypair = self.static_keygen()
        oracle = m47.RSAPaddingOracle()
        oracle.pubkey = fast_keypair.public
        # pylint: disable=protected-access
        oracle._private_key = fast_keypair.private

        m = m42.pkcs1v15_pad(data=MESSAGE,
                             bits=oracle.pubkey.modulus.bit_length(),
                             block_type=2)
        c = m39.encrypt(m, oracle.pubkey)
        m_int = m47.attack(oracle, c)
        m_prime = b"\x00" + m39.to_bytes(m_int)
        self.assertEqual(m_prime, m)

    def test_unpad_inverse(self) -> None:
        """Compare unpadded PKCS#1 v1.5 message to original"""
        m_padded = m42.pkcs1v15_pad(data=MESSAGE, bits=256, block_type=2)
        self.assertEqual(MESSAGE, m47.pkcs1v15_unpad(m_padded))

class Test49(unittest.TestCase):
    """CBC-MAC Message Forgery"""

    def test_v1_message_validation(self) -> None:
        """Send a message and validate it"""
        from_id = "me"
        client = m49.ClientV1(from_id)
        server = m49.ServerV1()

        parsed_message = {"to_id": "you", "amount": 1000}
        request = client.send(**parsed_message)  # type: ignore

        self.assertTrue(server.validate(request))

    def test_v1_fail_to_validate(self) -> None:
        """Send a bad message v1"""
        client = m49.ClientV1("0001")
        server = m49.ServerV1()
        request = client.send(to_id="0002", amount=100)
        request += b"\x02"
        self.assertFalse(server.validate(request))
        with self.assertRaises(Exception):
            server.process(request)

    def test_v1_attack_variable_iv(self) -> None:
        """Forge a message because the IV isn't fixed"""
        attacker_id = "0001"
        victim_id = "0002"
        forgery = m49.forge_via_variable_iv(attacker_id, victim_id)
        tx = m49.ServerV1.process(forgery)
        self.assertEqual(tx["to"], attacker_id)
        self.assertEqual(tx["from"], victim_id)
        self.assertEqual(tx["amount"], "1000000")

    def test_v2_fail_to_validate(self) -> None:
        """Send a bad message v2"""
        client = m49.ClientV2("1")
        server = m49.ServerV2()
        request = client.send({"2": 100})
        request += b"\x02"
        self.assertFalse(server.validate(request))
        with self.assertRaises(Exception):
            server.process(request)

    def test_v2_attack_via_length_extension(self) -> None:
        """Forge a message by extending CBC-MAC"""
        attacker_id = "1"
        victim_id = "2"
        forgery = m49.forge_via_length_extension(attacker_id, victim_id)
        txs = m49.ServerV2.process(forgery)
        self.assertEqual(txs["from"], victim_id)
        self.assertIn({"to": attacker_id, "amount": 1000000}, txs["tx_list"])

class Test50(unittest.TestCase):
    """Hashing with CBC-MAC"""

    def test_cbc_mac_test_vector(self) -> None:
        """Ensure CBC-MAC returns the expected hash"""
        js = b"alert('MZA who was that?');\n"
        key = b"YELLOW SUBMARINE"
        iv = bytes(16)
        mac = m49.cbc_mac(key, iv, m09.pkcs7(js))
        self.assertEqual(mac.hex(), "296b8d7cb78a243dda4d0a61d33bbdd1")

    def test_forge_hash(self) -> None:
        """Forge a hash over CBC-MAC"""
        m = b"alert('MZA who was that?');\n"

        m_prime = b"alert('Ayo, the Wu is back!');//"
        forgery = m50.forge_hash(m, m_prime, KEY, IV)

        self.assertEqual(m49.cbc_mac(KEY, IV, m09.pkcs7(m)),
                         m49.cbc_mac(KEY, IV, forgery))

class Test51(unittest.TestCase):
    """Compression Ratio Side-Channel Attacks"""

    m51.SESSION_ID = b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_attack_stream_cipher_oracle(self, _: io.StringIO) -> None:
        """CRIME attack on a stream cipher"""
        session_id = m51.attack(m51.ctr_oracle)
        self.assertEqual(session_id, m51.SESSION_ID)

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_attack_block_cipher_oracle(self, _: io.StringIO) -> None:
        """CRIME attack on a block cipher"""
        session_id = m51.attack(m51.cbc_oracle)
        self.assertEqual(session_id, m51.SESSION_ID)

class Test52(unittest.TestCase):
    """Iterated Hash Function Multicollisions"""

    def test_pep_452_mdhash(self) -> None:
        """MDHash decendants conform to PEP 452"""
        xh = m52.ExpensiveHash()
        xh_copy = xh.copy()
        xh_copy.update(b"yolo")
        self.assertNotEqual(xh.hexdigest(), xh_copy.hexdigest())

    def test_block_pairs(self) -> None:
        """Generate all block pairs"""
        self.assertEqual(len(list(m52.all_possible_block_pairs(1))),
                         math.comb(2 ** 8, 2))

    def test_multicollision(self) -> None:
        """Generate 2ⁿ hash multicollisions"""
        n = 2
        multicollision = m52.generate_multicollision(n, m52.CheapHash)
        self.assertEqual(len(multicollision.messages), 2 ** n)
        self.assertTrue(m52.verify_collision(multicollision))

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_cascading_collision_cheap(self, _: io.StringIO) -> None:
        """Find a collision in a cascading hash function"""
        m52.ExpensiveHash.digest_size = 2
        m52.ExpensiveHash.register = bytes(m52.ExpensiveHash.digest_size)
        collision = m52.find_cascading_hash_collision(limit=2)

        target_hashes = set()
        for m in collision.messages:
            target_hashes.add(m52.cascade_hash(m))

        self.assertEqual(len(target_hashes), 1)
        self.assertEqual(len(collision.messages), 2)
        self.assertEqual(target_hashes.pop(), collision.hash.out)

    @unittest.skip("Long test")
    @mock.patch("sys.stdout", _=io.StringIO)
    def test_cascading_collision(self, _: io.StringIO) -> None:
        """Find a collision in a cascading hash function"""
        collision = m52.find_cascading_hash_collision(limit=20)

        target_hashes = set()
        for m in collision.messages:
            target_hashes.add(m52.cascade_hash(m))

        self.assertEqual(len(target_hashes), 1)
        self.assertEqual(len(set(collision.messages)), 2)
        self.assertEqual(target_hashes.pop(), collision.hash.out)

    @mock.patch("sys.stdout", _=io.StringIO)
    def test_cascading_collision_fail(self, _: io.StringIO) -> None:
        """Fail to find a collision in a cascading hash function"""
        m52.ExpensiveHash.digest_size = 3
        m52.ExpensiveHash.register = bytes(m52.ExpensiveHash.digest_size)
        with self.assertRaises(RuntimeError):
            m52.find_cascading_hash_collision(limit=2)

class Test53(unittest.TestCase):
    """Kelsey and Schneier's Expandable Messages"""

    def test_find_collision(self) -> None:
        """Find all collisions of length 1, k"""
        h, k = bytes(1), 6
        for collision in m53.find_collision(k, h):
            self.assertTrue(m52.verify_collision(collision))
            self.assertEqual(len(collision.messages[0]) // m53.Hash.block_size, 1)
            self.assertEqual(len(collision.messages[1]) // m53.Hash.block_size,
                             2 ** (k - 1) + 1)

    def test_expandable_message_length(self) -> None:
        """Sanity check expandable message lengths"""
        h, k = m53.Hash.register, 6
        collision = next(m53.make_expandable_message(k, h))
        self.assertTrue(m52.verify_collision(collision))
        self.assertEqual(len(m52.pad(collision.messages[1])) // 16,
                         2 ** (k - 1) + 1)

    def test_produce_message(self) -> None:
        """Produce a message of a given length"""
        h, k = m53.Hash.register, 3
        for l in range(k, 2 ** k + k):
            c = list(m53.make_expandable_message(k, h))
            m = m53.produce_message(c, k, l)
            self.assertEqual(m52.md(m, h), c[-1].hash.out)
            self.assertEqual(len(m) // m53.Hash.block_size, l)

    def test_produce_message_outside_range(self) -> None:
        """Try to make a message with invalid length"""
        h, k = m53.Hash.register, 2
        with self.assertRaises(ValueError):
            m53.produce_message(list(m53.make_expandable_message(k, h)), k, 1)

    def test_second_preimage_attack(self) -> None:
        """Second preimage attack"""
        h, k = m53.Hash.register, 3
        m = bytes(m53.Hash.block_size * 2 ** k)
        h_m = m52.md(m, h)

        m_prime = m53.second_preimage_attack(m)

        self.assertNotEqual(m, m_prime)
        self.assertEqual(m52.md(m_prime, h), h_m)

        collision = m52.HashCollision((m, m_prime), m52.Chain(h, h_m))
        self.assertTrue(m52.verify_collision(collision))

class Test54(unittest.TestCase):
    """Kelsey and Kohno's Nostradamus Attack"""

    @staticmethod
    @cache
    def build_diamond_structure(k: int) -> m54.Tree:
        return m54.build_diamond_structure(k)

    def test_diamond_structure(self) -> None:
        """Construct the diamond structure"""
        tree = self.build_diamond_structure(2)
        self.assertIs(tree.root.message, None)

    def test_diamond_structure_size(self) -> None:
        """Check that the Merkle tree has the expected size"""
        k = 2
        tree = self.build_diamond_structure(k)

        level_traversed = tree.level_traverse([tree.root])
        # We drop a power of two because of our level -1 source nodes.
        k_prime = int(math.log(len(level_traversed) + 1, 2)) - 2

        self.assertEqual(k, tree.k)
        self.assertEqual(k, tree.height(tree.root) - 1)
        self.assertEqual(k, k_prime)

    def test_diamond_structure_traversal(self) -> None:
        """Traverse the Merkle tree"""
        tree = self.build_diamond_structure(2)
        preorder_traversed_set = set(tree.preorder_traverse(tree.root))
        level_traversed_set = set(tree.level_traverse([tree.root]))
        self.assertEqual(preorder_traversed_set, level_traversed_set)

    def test_diamond_structure_leaves(self) -> None:
        """Check that the loweset level matches the leaves"""
        k = 2
        tree = self.build_diamond_structure(k)
        level_traversed = tree.level_traverse([tree.root])
        lowest_level = level_traversed[2 ** k - 1: 2 ** (k + 1) - 1]
        self.assertEqual(len(tree.leaves), 2 ** k)
        self.assertEqual(tree.leaves, lowest_level)

    def test_validate_root(self) -> None:
        """Validate the root node hash"""
        root = self.build_diamond_structure(2).root

        self.assertEqual(m52.md(root.child.left.message,
                                root.child.left.hash.digest()),
                         root.hash.digest())

        self.assertEqual(m52.md(root.child.right.message,
                                root.child.right.hash.digest()),
                         root.hash.digest())

        h = root.child.left.hash.copy()
        h.update(root.child.left.message)
        self.assertEqual(h.digest(), root.hash.digest())

        h = root.child.right.hash.copy()
        h.update(root.child.right.message)
        self.assertEqual(h.digest(), root.hash.digest())

    def test_path_to_root(self) -> None:
        """Find a path from leaf to root"""
        k = 2
        tree = self.build_diamond_structure(k)
        path = tree.path_to_root(tree.root, tree.leaves[0])
        self.assertEqual(len(path), k + 1)

    def test_guess_spare_blocks(self) -> None:
        """Guess the number of extra blocks we must anticipate"""
        with open("data/54.txt", "rb") as f:
            predictions = [l.strip() for l in f.readlines()]
        self.assertEqual(m54.guess_spare_blocks(predictions), 3)

    def test_chosen_target(self) -> None:
        """Hash in the padding blocks"""
        tree = self.build_diamond_structure(2)
        spare_blocks = 2
        self.assertTrue(m54.chosen_target(tree, spare_blocks))

    def test_nostradamus_attack(self) -> None:
        """The Nostradamus attack"""
        with open("data/54.txt", "rb") as f:
            predictions = [l.strip() for l in f.readlines()]

        tree = m54.build_diamond_structure(2)
        spare_blocks = m54.guess_spare_blocks(predictions)
        commitment = m54.chosen_target(tree, spare_blocks)

        forced_prefix = m54.pad(predictions[0])

        link_message, leaf = m54.find_linking_message(forced_prefix, tree)
        message = forced_prefix + link_message
        self.assertEqual(leaf.hash.digest(), m52.md(message, leaf.hash.register))

        path = tree.path_to_root(tree.root, leaf)
        for i, node in enumerate(path[:-1]):
            message += node.message
            self.assertEqual(m52.md(message, node.hash.register),
                             path[i + 1].hash.digest())

        self.assertEqual(m52.md(message, tree.root.hash.register),
                         tree.root.hash.digest())

        padded_message = m54.pad(message)
        self.assertEqual(m52.md(padded_message, tree.root.hash.register),
                         commitment.digest())


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
