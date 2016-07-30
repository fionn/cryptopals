#!/usr/bin/env python3
# The CBC padding oracle

from base64 import b64decode
from binascii import hexlify
from Crypto.Random.random import getrandbits, randint
from m09 import pkcs7
from m15 import de_pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))
IV = bytes(getrandbits(8) for i in range(16))

def chose_plaintext():
    f = open("data/17.txt", "r").read().splitlines()
    return pkcs7(b64decode(f[randint(0, len(f) - 1)]))
    #f = open("scratch/tyger.txt", "r").read()
    #f = bytes(f, "ascii")
    #return pkcs7(f)

def cbc_oracle(plaintext = chose_plaintext(), k = RANDOM_KEY, iv = IV):
    return encrypt_aes_cbc(plaintext, k, iv)

def padding_oracle(cyphertext, k = RANDOM_KEY, iv = IV):
    plaintext = decrypt_aes_cbc(cyphertext, k, iv)
    pad_length = plaintext[-1]
    return pad_length * bytes([pad_length]) == plaintext[-pad_length:]

def attack_block(block, c = cbc_oracle()):
    c = [c[i:i+16] for i in range(0, len(c), 16)]
    c_prime = bytearray(16)
    p = bytearray(16)
    
    for i in range(15, -1, -1):
        for b in range(256):
            c_prime[i] = b
            if padding_oracle(bytes(c_prime) + c[block]):
                print("block", str(block) + ": c' =", hexlify(c_prime).decode() \
                      + ", p =",  hexlify(p).decode(), end="\r")
                if i == 15:
                    c_test = c_prime
                    c_test[i - 1] ^= c_prime[i]
                    if padding_oracle(bytes(c_test) + c[block]):
                        break
                else:
                    break

        p[i] = (16 - i) ^ c_prime[i] ^ c[block - 1][i]

        for j in range(i, 16):
            c_prime[j] = c_prime[j] ^ (16 - i) ^ (16 - i + 1)

    print()
    return bytes(p)

def attack(c = cbc_oracle()):
    p = [attack_block(i, c) for i in range(len(c) // 16 - 1, 0, -1)]
    return de_pkcs7(b''.join(p[::-1]))

if __name__ == "__main__":
    print("[" + 14 * "_" + "]" + attack().decode())

