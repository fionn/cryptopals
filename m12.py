#!/usr/bin/env python3
# Byte-at-a-time ECB decryption (simple)

from base64 import b64decode
from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from m09 import pkcs7, de_pkcs7
from m11 import detect_ecb

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def oracle(plaintext = b''):
    unknown_string = b64decode(open("data/12.txt", "r").read())
    plaintext = pkcs7(plaintext + unknown_string, 16)
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cypher.encrypt(plaintext)

def blocksize(oracle):
    smallest = len(oracle(b''))
    for i in range(256):
        test = i * b'A'
        if len(oracle(test)) - smallest > 0:
            return len(oracle(test)) - smallest

def len_string(oracle):
    l = len(oracle())
    bs = blocksize(oracle)
    for i in range(1, bs + 1): 
        if l < len(oracle(i * b'A')):
            return l - i 

def break_ecb(oracle):
    bs = blocksize(oracle)
    l = len(oracle())
    string_length = len_string(oracle)

    plaintext = b''
    prefix = (l + bs - 1) * b'A'
    while len(plaintext) <= string_length:
        oracle_prefix = oracle(prefix)
        for i in range(127):
            test = prefix + plaintext + bytes([i])
            if oracle(test)[l:l + bs] == oracle_prefix[l:l + bs]:
                #if i < 10:             # hack to break if non-
                #    return plaintext   # printable padding found
                prefix = prefix[1:]
                plaintext += bytes([i])
                #print(chr(i), end = "", flush = True)
                break

    return de_pkcs7(plaintext)

if __name__ == "__main__":

    if not detect_ecb(oracle(64 * b'A')):
        print("Not ECB")
        raise SystemExit

    print(break_ecb(oracle).decode())

