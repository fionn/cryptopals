#!/usr/bin/env python3

import unittest
import gc
import hmac
import base64
from hashlib import sha1
from Crypto.Random.random import randint, getrandbits
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import MD4

import m01
import m02
import m03
import m04
import m05
import m06
import m08
import m09
import m10
import m15
import m16
import m18
import m21
import m23
import m24
import m26
import m28
import m30
import m31
import m33
import m34
import m35

KEY = B"YELLOW_SUBMARINE"
IV = bytes(len(KEY))
MESSAGE = b"Attack at dawn"
BLOCKSIZE = 16
PRIME = 197
G = 2

class Test01(unittest.TestCase):

    def test_m01_sanity(self):
        """hex_to_base64 should pass 0 --> 0"""
        self.assertEqual(m01.hex_to_base64("00"), "AA==")

class Test02(unittest.TestCase):

    def test_m02_sanity(self):
        """a xor a = 0, a xor 0 = a"""
        for i in range(256):
            self.assertEqual(m02.fixed_xor(bytes([i]), bytes([i])), b'\x00')
            self.assertEqual(m02.fixed_xor(bytes([i]), b'\x00'), bytes([i]))

    def test_m02_out_of_range(self):
        """fixed_xor(x) should fail when x !in [0, 255]"""
        self.assertRaises(ValueError,
                          lambda: m02.fixed_xor(bytes([256]), b'\x00'))

class Test03(unittest.TestCase):

    def test_m03_xor_everything_sanity(self):
        """xor_everything on \\x00 produces [\\x00, ..., \\xff]"""
        x = m03.xor_everything([0])
        self.assertEqual(len(x), 256)
        for i in range(256):
            self.assertEqual(x[i], bytes([i]))

    def test_m03_score_empty_input(self):
        """score zero for zero-length input"""
        self.assertEqual(m03.score(b''), 0)

class Test04(unittest.TestCase):

    def test_m04_find_xored_string(self):
        """find_xored_string"""
        with open("data/04.txt", "r") as f:
            f = f.read().splitlines()
            f = [bytes.fromhex(line) for line in f]
            xored_string = b"Now that the party is jumping\n"
            self.assertEqual(m04.findxoredstring(f), xored_string)

class Test05(unittest.TestCase):

    def test_m05_repeating_key_xor(self):
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

    def test_m06_hamming_distance(self):
        """Hamming distance matches known value"""
        s1, s2 = b"this is a test", b"wokka wokka!!!"
        self.assertEqual(m06.d_H(s1, s2), 37)
        self.assertEqual(m06.d_H(s2, s2), 0)

    def test_m06_key(self):
        """Break repeating key xor"""
        with open("data/06.txt", "r") as f:
            cyphertext = base64.b64decode(f.read())
            self.assertEqual(m06.key(cyphertext), b"Terminator X: Bring the noise")

class Test08(unittest.TestCase):

    def test_m08_ecb_score(self):
        """Trivial values for ecb_score"""
        self.assertEqual(m08.ecb_score(bytes(BLOCKSIZE), BLOCKSIZE), 0)
        self.assertEqual(m08.ecb_score(bytes(2 * BLOCKSIZE), BLOCKSIZE), 1)

    def test_m08_detct_ecb(self):
        """Detect ECB"""
        with open("data/08.txt", "r") as f:
            f = [bytes.fromhex(cyphertext) for cyphertext in f.read().splitlines()]
            ecb_encrypted = m08.detect_ecb(f, BLOCKSIZE)
            index = f.index(ecb_encrypted)
            self.assertEqual(index, 132)

class Test09(unittest.TestCase):

    def test_m09_de_pkcs7_inverts_pkcs7(self):
        """de_pkcs7 inverts pkcs7"""
        message = m09.de_pkcs7(m09.pkcs7(MESSAGE))
        self.assertEqual(message, MESSAGE)

class Test10(unittest.TestCase):

    def test_m10_aes_cbc_encrypt(self):
        """encrypt_aes_cbc matches Crypto.Cipher.AES"""
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_cyphertext = cypher.encrypt(m09.pkcs7(MESSAGE))
        cyphertext = m10.encrypt_aes_cbc(m09.pkcs7(MESSAGE), KEY, IV)
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_m10_aes_cbc_decrypt(self):
        """decrypt_aes_cbc matches Crypto.Cipher.AES"""
        cyphertext = b"x\x9b\xdb\xf8\x93\xae[x\x9a%\xb7\xffT\x1fc\xd5"
        cypher = AES.new(KEY, AES.MODE_CBC, IV)
        crypto_plaintext = cypher.decrypt(cyphertext)
        plaintext = m10.decrypt_aes_cbc(cyphertext, KEY, IV)
        self.assertEqual(plaintext, crypto_plaintext)

    def test_m10_aes_cbc_symmetry(self):
        """decrypt_aes_cbc inverts encrypt_aes_cbc"""
        m = m09.pkcs7(MESSAGE)
        cyphertext = m10.encrypt_aes_cbc(m, KEY, IV)
        plaintext = m10.decrypt_aes_cbc(cyphertext, KEY, IV)
        self.assertEqual(m, plaintext)

class Test15(unittest.TestCase):

    def test_m15_valid_pkcs7_padding(self):
        """de_pkcs7 validates for correct padding"""
        s = b"ICE ICE BABY"
        s_pad = m09.pkcs7(s)
        self.assertEqual(s, m15.de_pkcs7(s_pad))

    def test_m15_invalid_pkcs7_padding(self):
        """de_pkcs7 throws for incorrect padding"""
        s_pad = b"ICE ICE BABY\x01\x02\x03\x04"
        self.assertRaises(m15.PKCS7PaddingError, m15.de_pkcs7, s_pad)
        s_pad = b"ICE ICE BABY\x05\x05\x05\x05"
        self.assertRaises(m15.PKCS7PaddingError, m15.de_pkcs7, s_pad)

class Test16(unittest.TestCase):

    def test_m16_cbc_bitflipping_attack(self):
        """CBC bitflipping attack"""
        plaintext = bytes(16) + b'00000:admin<true'
        cyphertext = bytearray(m16.oracle(plaintext))
        cyphertext = m16.cbc_bitflip(cyphertext)
        cyphertext = bytes(cyphertext)
        self.assertTrue(m16.is_admin(cyphertext))

class Test18(unittest.TestCase):

    def test_m18_aes_ctr(self):
        """aes_ctr matches Crypto.Cipher.AES"""
        ctr = Counter.new(128, initial_value=0)
        cypher = AES.new(KEY, mode=AES.MODE_CTR, counter=ctr)
        crypto_cyphertext = cypher.encrypt(MESSAGE)
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        self.assertEqual(cyphertext, crypto_cyphertext)

    def test_m18_aes_ctr_symmetry(self):
        """aes_ctr is symmetric"""
        cyphertext = m18.aes_ctr(MESSAGE, KEY)
        plaintext = m18.aes_ctr(cyphertext, KEY)
        self.assertEqual(plaintext, MESSAGE)

class Test21(unittest.TestCase):

    def test_m21_mersenne_twister(self):
        """MT19937 returns a known good value"""
        # https://oeis.org/A221557
        x = m21.MT19937(5489)
        self.assertEqual(x.random(), 3499211612)

class Test23(unittest.TestCase):

    def test_m23_clone_mt(self):
        """mt_clone clones an MT19937 instance"""
        mt = m21.MT19937(5489)
        mt_clone = m23.clone_mt(mt)
        self.assertEqual(mt.random(), mt_clone.random())

class Test24(unittest.TestCase):

    def test_m24_verify_mt19937_crypt(self):
        """verify_mt19937_crypt"""
        self.assertTrue(m24.verify_mt19937_crypt())

    @unittest.skip("Long test")
    def test_m24_crack_mt19937(self):
        """Get MT19937 stream cypher seed"""
        seed = getrandbits(16)
        prefix = bytes(getrandbits(8) for i in range(randint(0, 100)))
        plaintext = prefix + bytes("A" * 14, "ascii")
        m24.verify_mt19937_crypt()
        cyphertext = m24.mt19937_crypt(plaintext, seed)
        found_seed = m24.crack_mt19937(cyphertext)
        self.assertEqual(found_seed, seed)

class Test26(unittest.TestCase):

    def test_m26_ctr_bitflipping(self):
        """CTR bitflipping attack"""
        plaintext = bytes(5) + b':admin<true'
        cyphertext = bytearray(m26.oracle(plaintext))
        cyphertext = m26.ctr_bitflip(cyphertext)
        self.assertTrue(m26.is_admin(cyphertext))

class Test28(unittest.TestCase):

    def test_m28_sha1(self):
        """SHA1 matches hashlib.sha1"""
        m = b'digest me' * 512
        h = sha1(m).hexdigest()
        h_prime = m28.SHA1().new(m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_empty_message(self):
        """SHA1 of empty message matches empty hash"""
        m = b''
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

        h = set(h)
        self.assertEqual(h, set(['da39a3ee5e6b4b0d3255bfef95601890afd80709']))

    def test_m28_sha1_long_input(self):
        """SHA1 of variable message length matches hashlib.sha1"""
        for i in range(513):
            m = bytes(i)
            h = sha1(m).hexdigest()
            h_prime = m28.SHA1().new(m).hexdigest()
            self.assertEqual(h, h_prime)

    def test_m28_sha1_mac(self):
        """sha1_mac matches hashlib.sha1"""
        m = b'digest me' * 512
        k = b'it is authentic'
        h = sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_message(self):
        """sha1_mac with empty message matches hashlib.sha1"""
        m = b''
        k = b'it is authentic'
        h = sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_key(self):
        """sha1_mac with empty key matches hashlib.sha1"""
        m = b'not very authenticated'
        k = b''
        h = sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_empty_message_and_key(self):
        """sha1_mac with empty message and key matches hashlib.sha1"""
        m, k = b'', b''
        h = sha1(k + m).hexdigest()
        h_prime = m28.SHA1().new(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m28_sha1_mac_cascade(self):
        """sha1_mac cannot be tampered with"""
        m = b'digest me'
        m_prime = b'digest he'
        k = b'it is authentic'
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m_prime, k))

    def test_m28_sha1_mac_different_key(self):
        """sha1_mac cannot authenticate with different key"""
        m = b'digest me'
        k = b'it is authentic'
        k_prime = b'inauthentic'
        self.assertNotEqual(m28.sha1_mac(m, k), m28.sha1_mac(m, k_prime))

    def test_m28_sha1_update(self):
        """SHA1 updates correctly"""
        m1 = b'A' * 512
        m2 = b'B' * 512
        h = m28.SHA1().new()
        h.update(m1)
        h.update(m2)
        h_combined = m28.SHA1().new(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())
        self.assertEqual(h.hexdigest(), sha1(m1 + m2).hexdigest())

    def test_m28_sha1_initialisation(self):
        """SHA1 initialises correctly"""
        m = b'could be anything'
        h1 = m28.SHA1(m)
        h2 = m28.SHA1().new(m)
        h3 = m28.SHA1().update(m)
        h4 = m28.SHA1().new().update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())
        self.assertEqual(h2.hexdigest(), h3.hexdigest())
        self.assertEqual(h3.hexdigest(), h4.hexdigest())

class Test30(unittest.TestCase):

    def test_m30_md4_test_vectors(self):
        """MD4 digests test vectors correctly (RFC1320)"""
        v = b''
        self.assertEqual(m30.MD4(v).hexdigest(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        v = b'a'
        self.assertEqual(m30.MD4(v).hexdigest(), "bde52cb31de33e46245e05fbdbd6fb24")
        v = b'abc'
        self.assertEqual(m30.MD4(v).hexdigest(), "a448017aaf21d8525fc10ae87aa6729d")
        v = b'message digest'
        self.assertEqual(m30.MD4(v).hexdigest(), "d9130a8164549fe818874806e1c7014b")
        v = b'abcdefghijklmnopqrstuvwxyz'
        self.assertEqual(m30.MD4(v).hexdigest(), "d79e1c308aa5bbcdeea8ed63df412da9")
        v = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        self.assertEqual(m30.MD4(v).hexdigest(), "043f8582f241db351ce627e153e7f0e4")
        v = b'1234567890123456789012345678901234567890' \
            + b'1234567890123456789012345678901234567890'
        self.assertEqual(m30.MD4(v).hexdigest(), "e33b4ddc9c38f2199c3e7b164fcc0536")

    def test_m30_md4_long_input(self):
        """MD4 of variable message length matches Crypto.Hash.MD4"""
        for i in range(513):
            m = bytes(i)
            h = m30.MD4(m)
            h_prime = MD4.new(m)
            self.assertEqual(h.digest(), h_prime.digest())

    def test_m30_md4_initialisation(self):
        """MD4 initialises correctly"""
        m = b'could be anything'
        h1 = m30.MD4(m)
        h2 = m30.MD4().new(m)
        h3 = m30.MD4().update(m)
        h4 = m30.MD4().new().update(m)
        self.assertEqual(h1.hexdigest(), h2.hexdigest())
        self.assertEqual(h2.hexdigest(), h3.hexdigest())
        self.assertEqual(h3.hexdigest(), h4.hexdigest())

    def test_m30_md4_update(self):
        """MD4 updates correctly"""
        m1 = b'A' * 512
        m2 = b'B' * 512
        h = m30.MD4().new()
        h.update(m1)
        h.update(m2)
        h_combined = m30.MD4().new(m1 + m2)
        self.assertEqual(h.hexdigest(), h_combined.hexdigest())

    def test_m30_md4_mac(self):
        """md4_mac matches Crypto.Hash.MD4"""
        m = b'digest me' * 512
        k = b'it is authentic'
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_message(self):
        """md4_mac with empty message matches Crypto.Hash.MD4"""
        m = b''
        k = b'it is authentic'
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_key(self):
        """md4_mac with empty key matches Crypto.Hash.MD4"""
        m = b'not very authenticated'
        k = b''
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_empty_message_and_key(self):
        """md4_mac with empty message and key matches Crypto.Hash.MD4"""
        m, k = b'', b''
        h = MD4.new(k + m).hexdigest()
        h_prime = m30.MD4(k + m).hexdigest()
        self.assertEqual(h, h_prime)

    def test_m30_md4_mac_cascade(self):
        """md4_mac cannot be tampered with"""
        m = b'digest me'
        m_prime = b'digest he'
        k = b'it is authentic'
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m_prime, k))

    def test_m30_md4_mac_different_key(self):
        """md4_mac cannot authenticate with different key"""
        m = b'digest me'
        k = b'it is authentic'
        k_prime = b'inauthentic'
        self.assertNotEqual(m30.md4_mac(m, k), m30.md4_mac(m, k_prime))

class Test31(unittest.TestCase):

    def testi_m31_hmac_sha1(self):
        """hmac_sha1 matches hmac.new(k, m, sha1)"""
        k = KEY
        m = MESSAGE
        h = m31.hmac_sha1(k, m)
        h_prime = hmac.new(k, m, sha1)
        self.assertEqual(h.digest(), h_prime.digest())

class Test33(unittest.TestCase):

    def test_m33_dh_key_exchange(self):
        """Diffie-Hellman peers agree on shared secret"""
        s_a, s_b = m33.dh_key_exchange(PRIME, G)
        self.assertEqual(s_a, s_b)

class Test34(unittest.TestCase):

    def test_m34_dh_protocol(self):
        """Diffie-Hellman peer receives message"""
        received_message = m34.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(received_message, MESSAGE)

    def test_m34_dh_parameter_injection(self):
        """Diffie-Hellman parameter injection intercepts message"""
        intercepted = m34.dh_parameter_injection(PRIME, G, MESSAGE)
        self.assertEqual(intercepted, MESSAGE)

class Test35(unittest.TestCase):

    @staticmethod
    def tearDown():
        gc.collect()

    def test_m35_dh_protocol(self):
        """Diffie-Hellman TCP peer receives message"""
        plaintext = m35.dh_protocol(PRIME, G, MESSAGE)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_1(self):
        """Diffie-Hellman inject malicious parameter g = 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, 1)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_p(self):
        """Diffie-Hellman inject malicious parameter g = p"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME)
        self.assertEqual(plaintext, MESSAGE)

    def test_m35_dh_malicious_g_is_p_minus_1(self):
        """Diffie-Hellman inject malicious parameter g = p - 1"""
        plaintext = m35.dh_malicious_g(PRIME, G, MESSAGE, PRIME - 1)
        self.assertEqual(plaintext, MESSAGE)

if __name__ == "__main__":
    unittest.main(verbosity=2, warnings="ignore")

