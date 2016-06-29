#!/usr/bin/env python3
# Byte-at-a-time ECB decryption (simple)

from base64 import b64decode
from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from m09 import pkcs7
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

def break_ecb(oracle):
    bs = blocksize(oracle)
    l = len(oracle())

    plaintext = b''
    prefix = (l + bs - 1) * b'A'
    while len(oracle(bs * b'A')) < len(oracle(prefix)):
        for i in range(127):
            test = prefix + plaintext + bytes([i])
            if oracle(test)[l:l + bs] == oracle(prefix)[l:l + bs]:
                #if i < 10:
                #    return plaintext
                prefix = prefix[1:]
                plaintext += bytes([i])
                #print(chr(i), end = "", flush = True)
                break

    return plaintext

if __name__ == "__main__":

    if detect_ecb(oracle(64 * b'A')) != "ECB":
        print("Not ECB")
        raise SystemExit

    print(break_ecb(oracle).decode())

