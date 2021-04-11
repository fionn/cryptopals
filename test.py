#!/usr/bin/env python3

import gc
import hmac
import time
import math
import json
import base64
import hashlib
import unittest
import functools
from unittest import mock

from Crypto.Hash import MD4
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random.random import randint, getrandbits

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

KEY = b"YELLOW SUBMARINE"
IV = bytes(len(KEY))
MESSAGE = b"Attack at dawn"
BLOCKSIZE = 16
PRIME = 197
G = 2

class Test01(unittest.TestCase):

    def test_m01_sanity(self) -> None:
        """hex_to_base64 should pass 0 --> 0"""
        self.assertEqual(m01.hex_to_base64("00"), "AA==")

class Test02(unittest.TestCase):

    def test_m02_sanity(self) -> None:
        """a xor a = 0, a xor 0 = a"""
        for i in range(256):
            self.assertEqual(m02.fixed_xor(bytes([i]), bytes([i])), b"\x00")
            self.assertEqual(m02.fixed_xor(bytes([i]), b"\x00"), bytes([i]))

    def test_m02_out_of_range(self) -> None:
        """fixed_xor(x) should fail when x !in [0, 255]"""
        self.assertRaises(ValueError,
                          lambda: m02.fixed_xor(bytes([256]), b"\x00"))

class Test03(unittest.TestCase):

    def test_m03_xor_everything_sanity(self) -> None:
        """xor_everything on \\x00 produces [\\x00, ..., \\xff]"""
        x = m03.xor_everything(b"\x00")
        self.assertEqual(len(x), 256)
        for i in range(256):
            self.assertEqual(x[i], bytes([i]))

    def test_m03_score_empty_input(self) -> None:
        """score zero for zero-length input"""
        self.assertEqual(m03.score(b""), 0)

class Test04(unittest.TestCase):

    def test_m04_find_xored_string(self) -> None:
        """find_xored_string"""
        with open("data/04.txt", "r") as f:
            data = [bytes.fromhex(line) for line in f.read().splitlines()]
        xored_string = b"Now that the party is jumping\n"
        self.assertEqual(m04.findxoredstring(data), xored_string)

class Test05(unittest.TestCase):

    def test_m05_repeating_key_xor(self) -> None:
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

    def test_m06_hamming_distance(self) -> None:
        """Hamming distance matches known value"""
        s1, s2 = b"this is a test", b"wokka wokka!!!"
        self.assertEqual(m06.hamming_distance(s1, s2), 37)
        self.assertEqual(m06.hamming_distance(s2, s2), 0)

    def test_m06_hamming_distance_wrong_size(self) -> None:
        """Hamming distance raises on different sizes"""
        s1 = b"different"
        s2 = b"sizes"
        with self.assertRaises(IndexError):
            m06.hamming_distance(s1, s2)

    def test_m06_key(self) -> None:
        """Generate key"""
        with open("data/06.txt", "r") as f:
            cyphertext = base64.b64decode(f.read())
        self.assertEqual(m06.key(cyphertext), b"Terminator X: Bring the noise")

    def test_m06_break_repeating_key_xor(self) -> None:
        """Break repeating key xor"""
        with open("data/06.txt", "r") as f:
            cyphertext = base64.b64decode(f.read())
        self.assertEqual(m06.break_repeating_key_xor(cyphertext)[:33],
                         b"I'm back and I'm ringin' the bell")

class Test08(unittest.TestCase):

    def test_m08_ecb_score(self) -> None:
        """Trivial values for ecb_score"""
        self.assertEqual(m08.ecb_score(bytes(BLOCKSIZE), BLOCKSIZE), 0)
        self.assertEqual(m08.ecb_score(bytes(2 * BLOCKSIZE), BLOCKSIZE), 1)

    def test_m08_detct_ecb(self) -> None:
        """Detect ECB"""
        with open("data/08.txt", "r") as f:
            g = [bytes.fromhex(cyphertext) for cyphertext in f.read().splitlines()]
        ecb_encrypted = m08.detect_ecb(g, BLOCKSIZE)
        self.assertIsNot(ecb_encrypted, None)
        index = g.index(ecb_encrypted)
        self.assertEqual(index, 132)

class Test09(unittest.TestCase):

    def test_m09_de_pkcs7_inverts_pkcs7(self) -> None:
        """de_pkcs7 inverts pkcs7"""
        message = m09.de_pkcs7(m09.pkcs7(MESSAGE))
        self.assertEqual(message, MESSAGE)

    def test_m09_zero_padding(self) -> None:
        """PKCS7 with zero padding"""
        zero_pad_message = b"YELLOW SUBMARINE"
        message = m09.de_pkcs7(m09.pkcs7(zero_pad_message))
        self.assertEqual(message, zero_pad_message)

class Test10(unittest.TestCase):

    def test_m10_aes_cbc_encrypt(self) -> None:
        """encrypt_aes_cbc matches Crypto.Cipher.AES"""
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_cyphertext = cypher.encrypt(m09.pkcs7(MESSAGE))
        cyphertext = m10.encrypt_aes_cbc(m09.pkcs7(MESSAGE), KEY, IV)
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_m10_aes_cbc_decrypt(self) -> None:
        """decrypt_aes_cbc matches Crypto.Cipher.AES"""
        cyphertext = b"x\x9b\xdb\xf8\x93\xae[x\x9a%\xb7\xffT\x1fc\xd5"
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_plaintext = cypher.decrypt(cyphertext)
        plaintext = m10.decrypt_aes_cbc(cyphertext, KEY, IV)
        self.assertEqual(plaintext, crypto_plaintext)

    def test_m10_aes_cbc_symmetry(self) -> None:
        """decrypt_aes_cbc inverts encrypt_aes_cbc"""
        m = m09.pkcs7(MESSAGE)
        cyphertext = m10.encrypt_aes_cbc(m, KEY, IV)
        plaintext = m10.decrypt_aes_cbc(cyphertext, KEY, IV)
        self.assertEqual(m, plaintext)

class Test11(unittest.TestCase):

    def test_m11_detect_ecb(self) -> None:
        """Detect ECB"""
        for _ in range(10):
            cyphertext = m11.encryption_oracle(MESSAGE * 3)
            self.assertIn(m11.detect_ecb(cyphertext), [True, False])

class Test12(unittest.TestCase):

    def test_m12_blocksize(self) -> None:
        """Detect blocksize"""
        self.assertEqual(m12.blocksize(m12.oracle), 16)

    def test_m12_len_string(self) -> None:
        """Detect string length"""
        self.assertEqual(m12.len_string(m12.oracle), 138)

    def test_m12_break_ecb(self) -> None:
        """Break ECB"""
        self.assertEqual(m12.break_ecb(m12.oracle).split(b"\n")[0],
                         b"Rollin' in my 5.0")

class Test13(unittest.TestCase):

    def test_m13_end_to_end(self) -> None:
        """ECB cut-and-paste"""
        email = "fake@mail.com"
        admin_cookie = m13.rewrite_cookie(email)
        profile = m13.decrypt_oracle(admin_cookie)
        self.assertEqual(profile["email"], email)
        self.assertEqual(profile["role"], "admin")

class Test14(unittest.TestCase):

    def test_m14_end_to_end(self) -> None:
        """Byte-at-a-time ECB decryption (harder)"""
        self.assertTrue(m14.break_ecb(m14.oracle))

class Test15(unittest.TestCase):

    def test_m15_equal_pkcs7_padding(self) -> None:
        """pkcs7 pads correctly"""
        message = b"ICE ICE BABY"
        self.assertEqual(m09.pkcs7(message), m15.pkcs7(message))

    def test_m15_valid_pkcs7_padding(self) -> None:
        """de_pkcs7 validates for correct padding"""
        s = b"ICE ICE BABY"
        s_pad = m09.pkcs7(s)
        self.assertEqual(s, m15.de_pkcs7(s_pad))

    def test_m15_invalid_pkcs7_padding(self) -> None:
        """de_pkcs7 throws for incorrect padding"""
        s_pad = b"ICE ICE BABY\x01\x02\x03\x04"
        self.assertRaises(m15.PKCS7PaddingError, m15.de_pkcs7, s_pad)
        s_pad = b"ICE ICE BABY\x05\x05\x05\x05"
        self.assertRaises(m15.PKCS7PaddingError, m15.de_pkcs7, s_pad)

class Test16(unittest.TestCase):

    def test_m16_cbc_bitflipping_attack(self) -> None:
        """CBC bitflipping attack"""
        plaintext = bytes(16) + b"00000:admin<true"
        cyphertext = m16.oracle(plaintext)
        cyphertext = m16.cbc_bitflip(cyphertext)
        self.assertTrue(m16.is_admin(cyphertext))

class Test17(unittest.TestCase):

    def test_m17_end_to_end(self) -> None:
        """The CBC padding oracle"""
        c = m17.cbc_oracle()
        m = m17.attack(c)
        self.assertTrue(m)

class Test18(unittest.TestCase):

    def test_m18_aes_ctr(self) -> None:
        """aes_ctr matches Crypto.Cipher.AES"""
        ctr = Counter.new(128, initial_value=0)
        cypher = AES.new(KEY, mode=AES.MODE_CTR, counter=ctr)
        crypto_cyphertext = cypher.encrypt(MESSAGE)
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_m18_aes_ctr_symmetry(self) -> None:
        """aes_ctr is symmetric"""
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        plaintext = m18.aes_ctr(cyphertext, KEY)
        self.assertEqual(plaintext, MESSAGE)

class Test21(unittest.TestCase):

    def test_m21_mersenne_twister(self) -> None:
        """MT19937 returns a known good value"""
        # https://oeis.org/A221557
        mt = m21.MT19937(5489)
        self.assertEqual(mt.random(), 3499211612)

class Test22(unittest.TestCase):

    @unittest.skip("Extremely long test")
    def test_m22_end_to_end(self) -> None:
        """Crack an MT19937 seed"""
        r = m22.sleep_mersenne()
        seed = m22.crack_seed(r)
        clone = m21.MT19937(seed)
        self.assertEqual(clone.random(), r)

    def test_m22_crack_artificial_seed(self) -> None:
        """Crack an artificial MT19937 seed"""
        seed = int(time.time())
        r = m21.MT19937(seed).random()
        seed_candidate = m22.crack_seed(r)
        self.assertEqual(seed, seed_candidate)

class Test23(unittest.TestCase):

    def test_m23_clone_mt(self) -> None:
        """mt_clone clones an MT19937 instance"""
        mt = m21.MT19937(5489)
        mt_clone = m23.clone_mt(mt)
        self.assertEqual(mt.random(), mt_clone.random())

class Test24(unittest.TestCase):

    def test_m24_verify_mt19937_crypt(self) -> None:
        """verify_mt19937_crypt"""
        self.assertTrue(m24.verify_mt19937_crypt(bytes(10), 0xffff))

    @unittest.skip("Long test")
    def test_m24_crack_mt19937(self) -> None:
        """Get MT19937 stream cypher seed"""
        seed = getrandbits(16)
        prefix = bytes(getrandbits(8) for i in range(randint(0, 100)))
        plaintext = prefix + b"A" * 14
        cyphertext = m24.mt19937_crypt(plaintext, seed)
        found_seed = m24.crack_mt19937(cyphertext)
        self.assertEqual(found_seed, seed)

    def test_m24_crack_mt19937_contrived(self) -> None:
        """Given contrived cyphertext, crack MT19937 stream cypher seed"""
        cyphertext = b"d\xaa\xcd\t"
        seed = m24.crack_mt19937(cyphertext)
        self.assertEqual(seed, 1)

class Test25(unittest.TestCase):

    def test_m25_end_to_end(self) -> None:
        """Break "random access read/write" AES CTR"""
        c = m18.aes_ctr(MESSAGE, m25.RANDOM_KEY)
        m_prime = m25.break_rarw(c)
        self.assertEqual(MESSAGE, m_prime)

class Test26(unittest.TestCase):

    def test_m26_ctr_bitflipping(self) -> None:
        """CTR bitflipping attack"""
        plaintext = bytes(5) + b":admin<true"
        cyphertext = m26.oracle(plaintext)
        cyphertext = m26.ctr_bitflip(cyphertext)
        self.assertTrue(m26.is_admin(cyphertext))

class Test27(unittest.TestCase):

    def test_m27_end_to_end(self) -> None:
        """Recover the key from CBC with IV = Key"""
        c = m27.bad_cbc_encryption(MESSAGE * 3)
        k = m27.cbc_iv_key(c)
        self.assertEqual(k, m27.RANDOM_KEY)

class Test28(unittest.TestCase):

    def test_m28_sha1(self) -> None:
        """SHA1 matches hashlib.sha1"""
        m = b"digest me" * 512
        h = hashlib.sha1(m).hexdigest()
        h_prime = m28.SHA1().new(m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_empty_message(self) -> None:
        """SHA1 of empty message matches empty hash"""
        m = b""
        h = []

        h.append(m28.SHA1().new().hexdigest())
        h.append(m28.SHA1().new(m).hexdigest())
        h.append(m28.SHA1(m).new().hexdigest())
        h.append(m28.SHA1(m).new(m).hexdigest())

        h.append(m28.SHA1().update(m).hexdigest())
        h.append(m28.SHA1(m).update(m).hexdigest())

        h.append(m28.SHA1().new().update(m).hexdigest())
        h.append(m28.SHA1().new(m).update(m).hexdigest())
        h.append(m28.SHA1(m).new().update(m).hexdigest())
        h.append(m28.SHA1(m).new(m).update(m).hexdigest())

        self.assertEqual(set(h), set(["da39a3ee5e6b4b0d3255bfef95601890afd80709"]))

    def test_m28_sha1_long_input(self) -> None:
        """SHA1 of variable message length matches hashlib.sha1"""
        for i in range(513):
            m = bytes(i)
            h = hashlib.sha1(m).hexdigest()
            h_prime = m28.SHA1().new(m).hexdigest()
            self.assertEqual(h, h_prime)

    def test_m28_sha1_mac(self) -> None:
        """sha1_mac matches hashlib.sha1"""
        m = b"digest me" * 512
        k = b"it is authentic"
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_message(self) -> None:
        """sha1_mac with empty message matches hashlib.sha1"""
        m = b""
        k = b"it is authentic"
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_key(self) -> None:
        """sha1_mac with empty key matches hashlib.sha1"""
        m = b"not very authenticated"
        k = b""
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_message_and_key(self) -> None:
        """sha1_mac with empty message and key matches hashlib.sha1"""
        m, k = b"", b""
        h = hashlib.sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_cascade(self) -> None:
        """sha1_mac cannot be tampered with"""
        m = b"digest me"
        m_prime = b"digest he"
        k = b"it is authentic"
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m_prime, k))

    def test_m28_sha1_mac_different_key(self) -> None:
        """sha1_mac cannot authenticate with different key"""
        m = b"digest me"
        k = b"it is authentic"
        k_prime = b"inauthentic"
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m, k_prime))

    def test_m28_sha1_update(self) -> None:
        """SHA1 updates correctly"""
        m1 = b"A" * 512
        m2 = b"B" * 512
        h = m28.SHA1().new()
        h.update(m1)
        h.update(m2)
        h_combined = m28.SHA1().new(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())
        self.assertEqual(h.hexdigest(), hashlib.sha1(m1 + m2).hexdigest())

    def test_m28_sha1_initialisation(self) -> None:
        """SHA1 initialises correctly"""
        m = b"could be anything"
        h1 = m28.SHA1(m)
        h2 = m28.SHA1().new(m)
        h3 = m28.SHA1().update(m)
        h4 = m28.SHA1().new().update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())
        self.assertEqual(h2.hexdigest(), h3.hexdigest())
        self.assertEqual(h3.hexdigest(), h4.hexdigest())

    def test_m28_copy(self) -> None:
        """Copy SHA1 object"""
        h = m28.SHA1(MESSAGE)
        h_prime = h.copy()
        self.assertEqual(h.digest(), h_prime.digest())

class Test29(unittest.TestCase):

    def test_m29_end_to_end(self) -> None:
        """Break a SHA-1 keyed MAC using length extension"""
        m = b"comment1=cooking%20MCs;userdata=foo;" \
            b"comment2=%20like%20a%20pound%20of%20bacon"
        k = bytes(getrandbits(8) for _ in range(randint(0, 50)))
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

    def test_m30_md4_test_vectors(self) -> None:
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

    def test_m30_md4_long_input(self) -> None:
        """MD4 of variable message length matches Crypto.Hash.MD4"""
        for i in range(513):
            m = bytes(i)
            h = m30.MD4(m)
            h_prime = MD4.new(m)
            self.assertEqual(h.digest(), h_prime.digest())

    def test_m30_md4_initialisation(self) -> None:
        """MD4 initialises correctly"""
        m = b"could be anything"
        h1 = m30.MD4(m)
        h2 = m30.MD4().new(m)
        h3 = m30.MD4().update(m)
        h4 = m30.MD4().new().update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())
        self.assertEqual(h2.hexdigest(), h3.hexdigest())
        self.assertEqual(h3.hexdigest(), h4.hexdigest())

    def test_m30_md4_update(self) -> None:
        """MD4 updates correctly"""
        m1 = b"A" * 512
        m2 = b"B" * 512
        h = m30.MD4().new()
        h.update(m1)
        h.update(m2)
        h_combined = m30.MD4().new(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())

    def test_m30_md4_mac(self) -> None:
        """md4_mac matches Crypto.Hash.MD4"""
        m = b"digest me" * 512
        k = b"it is authentic"
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_message(self) -> None:
        """md4_mac with empty message matches Crypto.Hash.MD4"""
        m = b""
        k = b"it is authentic"
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_key(self) -> None:
        """md4_mac with empty key matches Crypto.Hash.MD4"""
        m = b"not very authenticated"
        k = b""
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_message_and_key(self) -> None:
        """md4_mac with empty message and key matches Crypto.Hash.MD4"""
        m, k = b"", b""
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_cascade(self) -> None:
        """md4_mac cannot be tampered with"""
        m = b"digest me"
        m_prime = b"digest he"
        k = b"it is authentic"
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m_prime, k))

    def test_m30_md4_mac_different_key(self) -> None:
        """md4_mac cannot authenticate with different key"""
        m = b"digest me"
        k = b"it is authentic"
        k_prime = b"inauthentic"
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m, k_prime))

    def test_m30_copy(self) -> None:
        """Copy MD4 object"""
        h = m30.MD4(MESSAGE)
        h_prime = h.copy()
        self.assertEqual(h.digest(), h_prime.digest())

    def test_m30_state_from_hex(self) -> None:
        """Extract MD4 register from hex digest"""
        h = m30.MD4(b"fud for thought")
        register = m30.md4_state_from_hex(h.hexdigest())
        self.assertEqual(register, m30.md4_state_from_object(h))

    def test_m30_state_from_binary(self) -> None:
        """Extract MD4 register from binary digest"""
        h = m30.MD4(b"fud for thought")
        register = m30.md4_state_from_binary(h.digest())
        self.assertEqual(register, m30.md4_state_from_object(h))

    def test_m30_verify_md4_mac(self) -> None:
        """Verify MD4 MAC"""
        mac = m30.md4_mac(MESSAGE, KEY)
        self.assertTrue(m30.verify_md4_mac(mac, MESSAGE, KEY))

    def test_m30_md_padding(self) -> None:
        """MD padding"""
        data = b"llllll"
        padding = m30.md_padding(data)
        padding_prime = b"\x80" \
                        + b"\x00" * ((56 - len(data) - 1 % m30.MD4.block_size)
                                     % m30.MD4.block_size) \
                        + (8 * len(data)).to_bytes(8, "little")
        self.assertEqual(padding, padding_prime)

    def test_m30_extend_md4(self) -> None:
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

    def test_m31_hmac_sha1(self) -> None:
        """hmac_sha1 matches hmac.new(k, m, sha1)"""
        k = KEY
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_m31_hmac_sha1_large_key(self) -> None:
        """hmac_sha1 with large key"""
        k = 128 * KEY
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_m31_hmac_sha1_equal_sized_key(self) -> None:
        """hmac_sha1 with large key"""
        k = bytes(64)
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, hashlib.sha1)
        self.assertEqual(h.digest(), h_prime.digest())

    def test_m31_insecure_compare_identical(self) -> None:
        """insecure_compare identifies identical bytes"""
        a = b"identical bytes"
        self.assertTrue(m31.insecure_compare(a, a, 0))

    def test_m31_insecure_compare_different(self) -> None:
        """insecure_compare distinguishes different bytes"""
        a = b"different bytes"
        b = b"different bytez"
        self.assertFalse(m31.insecure_compare(a, b, 0))

    def test_m31_insecure_compare_different_size(self) -> None:
        """insecure_compare raises for different sizes"""
        a = b"different"
        b = b"sizes"
        with self.assertRaises(IndexError):
            m31.insecure_compare(a, b, 0)

    def test_m31_verify_hmac_sha1_hex(self) -> None:
        """verify HMAC"""
        k, m = KEY, MESSAGE
        signature = m31.hmac_sha1(k, m).hexdigest().encode()
        self.assertTrue(m31.verify_hmac_sha1_hex(m, signature, k, 0))

class Test33(unittest.TestCase):

    def test_m33_dh_key_exchange(self) -> None:
        """Diffie-Hellman peers agree on shared secret"""
        s_a, s_b = m33.dh_key_exchange(PRIME, G)
        self.assertEqual(s_a, s_b)

class Test34(unittest.TestCase):

    def test_m34_dh_protocol(self) -> None:
        """Diffie-Hellman peer receives message"""
        received_message = m34.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(received_message, MESSAGE)

    def test_m34_dh_parameter_injection(self) -> None:
        """Diffie-Hellman parameter injection intercepts message"""
        intercepted = m34.dh_parameter_injection(PRIME, G, MESSAGE)
        self.assertEqual(intercepted, MESSAGE)

class Test35(unittest.TestCase):

    @staticmethod
    def tearDown() -> None:
        gc.collect()

    def test_m35_dh_protocol(self) -> None:
        """Diffie-Hellman TCP peer receives message"""
        plaintext = m35.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_1(self) -> None:
        """Diffie-Hellman inject malicious parameter g = 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, 1)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_p(self) -> None:
        """Diffie-Hellman inject malicious parameter g = p"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_p_minus_1(self) -> None:
        """Diffie-Hellman inject malicious parameter g = p - 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME - 1)
        self.assertEqual(plaintext, MESSAGE)

class Test36(unittest.TestCase):

    def test_m36_client_pubkey(self) -> None:
        """client-side public key"""
        carol = m36.Client(PRIME, "e@ma.il", "pw", 2, 3)
        carol.pubkey()
        self.assertEqual(carol.A, carol.pubkey())

    def test_m36_server_pubkey(self) -> None:
        """server-side public key"""
        parameters = {"N": PRIME,
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

    def test_m36_bad_email(self) -> None:
        """mismatched emails"""
        parameters = {"N": PRIME,
                      "g": 2,
                      "k": 3,
                      "I": "some@ema.il",
                      "p": "password"
                     }
        steve = m36.Server()
        steve.negotiate_receive(parameters)
        bad_parameters = {"I": "diff@e.mail", "pubkey": 123}
        self.assertRaises(ValueError,
                          lambda: steve.receive_email_pubkey(bad_parameters))

    def test_m36_bad_hmac(self) -> None:
        """hmacs don't match"""
        parameters = {"N": PRIME,
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

    def test_m36_srp_protocol(self) -> None:
        """SRP protocol server verification"""
        carol = m36.Client(m36.prime(), email="not@real.email",
                           password="submarines")
        steve = m36.Server()
        result = m36.srp_protocol(carol, steve)
        self.assertTrue(result)

class Test37(unittest.TestCase):

    def test_m37_srp_zero_key(self) -> None:
        """Break SRP with a zero key"""
        carol = m37.CustomKeyClient(m36.prime(), email="not@real.email",
                                    password="submarines")
        steve = m36.Server()
        carol.A = 0
        result = m36.srp_protocol(carol, steve)
        self.assertTrue(result)

    def test_m37_srp_multiple_prime_key(self) -> None:
        """Break SRP with a zero key"""
        prime = m36.prime()
        for i in range(1, 4):
            carol = m37.CustomKeyClient(prime, email="not@real.email",
                                        password="submarines")
            steve = m36.Server()
            carol.A = i * prime
            result = m36.srp_protocol(carol, steve)
            self.assertTrue(result)

class Test38(unittest.TestCase):

    def test_m38_simple_srp(self) -> None:
        """Implement simple SRP"""
        client = m38.SimpleClient(PRIME, G,
                                  username="srp-client@cryptopals.com",
                                  password="yolo")
        server = m38.SimpleServer(PRIME, G)
        self.assertTrue(m38.simple_srp(client, server))

    @unittest.skip("Requires a wordlist file")
    def test_m38_mitm_simple_srp(self) -> None:
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
    def test_m38_mitm_simple_srp_no_io(self, _words: mock.Mock) -> None:
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

    def test_m39_gcd(self) -> None:
        """Sanity check Euclidean GCD"""
        interval = range(-10, 10)
        for a in interval:
            for b in interval:
                self.assertEqual(m39.gcd(a, b), math.gcd(a, b))

    def test_m39_lcm(self) -> None:
        """Sanity check LCM"""
        interval = range(-10, 10)
        for a in interval:
            for b in interval:
                self.assertEqual(m39.lcm(a, b), math.lcm(a, b))

    def test_m39_modular_inverse(self) -> None:
        """Calculate modular inverse"""
        self.assertEqual(m39.invmod(3, 7), 5)
        self.assertEqual(m39.invmod(17, 3120), 2753)
        self.assertEqual(m39.invmod(17, 3120), pow(17, -1, 3120))

    def test_m39_modular_inverse_does_not_exist(self) -> None:
        """Calculate modular inverse when it doesn't exist"""
        with self.assertRaises(ValueError):
            m39.invmod(3, 3)

    def test_m39_keygen_size(self) -> None:
        """Sanity check keypair for bit size and modulus"""
        e = 3
        size = 128
        public, private = m39.keygen(size, e)
        self.assertEqual(size, public.modulus.bit_length())
        self.assertEqual(public.modulus, private.modulus)
        self.assertEqual(public.exponent, e)
        self.assertGreater(private.exponent, e)

    def test_m39_integer_encryption(self) -> None:
        """RSA encryption and decryption of integer data"""
        public, private = m39.keygen(128)
        m = 42
        c = m39.encrypt_int(m, public)
        m_prime = m39.decrypt_int(c, private)
        self.assertEqual(m, m_prime)

    def test_m39_binary_encryption(self) -> None:
        """RSA encryption and decryption of binary data"""
        public, private = m39.keygen(128)
        m = MESSAGE
        c = m39.encrypt(m, public)
        m_prime = m39.decrypt(c, private)
        self.assertEqual(m, m_prime)

    def test_m39_small_modulus(self) -> None:
        """RSA encryption fails with small modulus"""
        size = 128
        public, _ = m39.keygen(size)
        m = 2 ** size
        with self.assertRaises(ValueError):
            m39.encrypt_int(m, public)

class Test40(unittest.TestCase):

    def test_m40_integer_root(self) -> None:
        """Find the integer nth root"""
        x = 4
        e = 6
        self.assertEqual(m40.integer_root(x ** e, e), x)

    def test_m40_integer_root_of_zero(self) -> None:
        """Calculate the integer square root of 0"""
        self.assertEqual(m40.integer_root(0, 2), 0)

    def test_m40_zeroth_root(self) -> None:
        """Calculate the 0th root"""
        with self.assertRaises(ZeroDivisionError):
            m40.integer_root(2, 0)

    def test_m40_crt(self) -> None:
        """Calculate CRT for a simple system"""
        a = [0, 3, 4]
        n = [3, 4, 5]
        self.assertEqual(m40.crt(a, n), 39)

    def test_m40_crt_impossible_system(self) -> None:
        """Calculate CRT when arguments don't define a system"""
        a = [0]
        n = [4, 5]
        with self.assertRaises(ValueError):
            m40.crt(a, n)

    def test_m40_broadcast(self) -> None:
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

    def test_m41_repeated_decryption(self) -> None:
        """Try to decrypt multiple times"""
        server = m41.DecryptionServer(size=512)
        c = m39.encrypt(MESSAGE, server.public_key)
        server.decrypt(c)
        with self.assertRaises(RuntimeError):
            server.decrypt(c)

    def test_m41_recover_message(self) -> None:
        """Recover plaintext via transformation"""
        server = m41.DecryptionServer(size=512)
        c = m39.encrypt(MESSAGE, server.public_key)
        server.decrypt(c)
        m = m41.recover_message(c, server)
        self.assertEqual(m, MESSAGE)

class Test42(unittest.TestCase):

    def test_m42_pkcs1v15_pad(self) -> None:
        """Pad a message with PKCS#1 v1.5"""
        eb = m42.pkcs1v15_pad(MESSAGE, 256)
        self.assertEqual(eb[0], 0)
        self.assertEqual(eb[1], 1)
        for element in eb[2:9]:
            self.assertNotEqual(element, 0)
        self.assertIn(0, eb[10:])

    def test_m42_pkcs1v15_pad_bad_type(self) -> None:
        """Pad a message with non-existent block type"""
        with self.assertRaises(ValueError):
            m42.pkcs1v15_pad(MESSAGE, 256, block_type=3)

    def test_m42_pkcs1v15_pad_message_too_big(self) -> None:
        """Pad a message that's too big for the size"""
        with self.assertRaises(ValueError):
            m42.pkcs1v15_pad(MESSAGE, 128)

    def test_m42_sign_and_verify(self) -> None:
        """Sign a message and verify the signature"""
        keypair = m39.keygen(bits=512)
        s = m42.sign(MESSAGE, keypair.private)
        self.assertTrue(m42.verify(MESSAGE, s, keypair.public))

    def test_m42_verify_no_match(self) -> None:
        """Try to verify an obviously bad signature"""
        keypair = m39.keygen(bits=512)
        fake_signature = 123456789012
        self.assertFalse(m42.verify(MESSAGE, fake_signature, keypair.public))

    def test_m42_forge_signature(self) -> None:
        """BB'06 via cube root"""
        m = MESSAGE
        keypair = m39.keygen(bits=1024)
        s = m42.forge_signature(m, keypair.public.modulus.bit_length())
        self.assertTrue(m42.verify(m, s, keypair.public))

class Test43(unittest.TestCase):

    @staticmethod
    @functools.cache
    def data() -> dict:
        with open("data/43.txt") as data_fd:
            return json.load(data_fd)

    def test_m43_verify_dsa_signature(self) -> None:
        """Sign a message and verify the DSA signature"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}

        keypair = m43.keygen(**parameters)
        signature = m43.sign(MESSAGE, keypair.private, **parameters)
        self.assertTrue(m43.verify(MESSAGE, signature,
                                   keypair.public, **parameters))

    def test_m43_test_bad_dsa_signature(self) -> None:
        """Verify a message with a bad signature"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}

        bad_sig = m43.DSASignature(parameters["q"], 0)
        self.assertFalse(m43.verify(MESSAGE, bad_sig, 0, **parameters))
        bad_sig = m43.DSASignature(1, parameters["q"])
        self.assertFalse(m43.verify(MESSAGE, bad_sig, 0, **parameters))

    def test_m43_recover_private_key(self) -> None:
        """Recover private key from signature and random subkey k"""
        data = self.data()
        parameters = {k: int(data[k], 16) for k in ["p", "q", "g"]}

        keypair = m43.keygen(**parameters)
        signature, k = m43.sign_leak_k(MESSAGE, keypair.private, **parameters)
        x = m43.recover_private_key(MESSAGE, signature, k, parameters["q"])
        self.assertEqual(keypair.private, x)

    def test_m43_test_vectors(self) -> None:
        """Check given messages hashes as expected"""
        data = self.data()
        m = data["m"].encode()
        h_m = m39.to_int(m28.SHA1(m).digest())
        self.assertEqual(h_m, 0xd2d0714f014a9784047eaeccf956520045c45265)

    def test_m43_validate_expected_good_signature(self) -> None:
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
    def test_m43_brute_force_recover_key(self) -> None:
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

    def test_m43_brute_force_recover_key_with_known_k(self) -> None:
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
        except RuntimeError:
            self.fail("Failed to recover private key from DSA signature")

    def test_m43_brute_force_recover_key_with_no_valid_k(self) -> None:
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

    def test_m43_known_x(self) -> None:
        """Check x hashes to expected value"""
        x = 125489817134406768603130881762531825565433175625
        h_x = m39.to_int(m28.SHA1(hex(x)[2:].encode()).digest())
        self.assertEqual(h_x, 0x0954edd5e0afe5542a4adf012611a91912a3ec16)

class Test44(unittest.TestCase):

    def test_m44_verify_input(self) -> None:
        """Check input messages have expected hashes"""
        messages = m44.get_messages()
        for message in messages:
            h_m = m39.to_int(m28.SHA1(message["msg"]).digest())
            self.assertEqual(h_m, message["m"])

    def test_m44_signatures_validate(self) -> None:
        """Validate message signatures"""
        y = m44.PUBLIC_KEY
        parameters = m44.get_parameters()
        p, q, g = parameters.values()
        messages = m44.get_messages()

        for message in messages:
            signature = m43.DSASignature(message["r"], message["s"])
            self.assertTrue(m43.verify(message["msg"], signature, y, p, q, g))

    def test_m44_candidate_messages_exist(self) -> None:
        """Check inputs are vulnerable"""
        messages = m44.get_messages()
        message_groups = m44.group_by_repeated_k(messages)
        groups_of_more_than_one = [x for x in message_groups if len(x) > 1]
        self.assertTrue(len(groups_of_more_than_one) > 1)

    def test_m44_recover_private_key(self) -> None:
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

    def test_m44_consistent_x(self) -> None:
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

if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
