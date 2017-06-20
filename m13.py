#!/usr/bin/env python3
# ECB cut-and-paste

from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from m09 import pkcs7, de_pkcs7

RANDOM_KEY = bytes(getrandbits(8) for i in range(16))

def parse(string):
    cookie = dict()
    for pairs in string.split("&"):
        key, value = pairs.split("=")
        cookie[key] = value
    return cookie

def profile_for(email):
    email = email.replace("&", "").replace("=", "")
    profile = {"email": email, "uid": 10, "role": "user"}
    formatted = "&".join([key + "=" + str(profile[key]) \
                for key in ["email", "uid", "role"]])
    return formatted

def oracle(email):
    profile = profile_for(email)
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cypher.encrypt(pkcs7(bytes(profile, "ascii"), 16))

def decrypt_oracle(profile):
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    profile = de_pkcs7(cypher.decrypt(profile))
    return parse(profile.decode())

def rewrite_cookie(email = "fake@mail.com"):
    bs = 16
    assert len(email) % bs == 13, "email must be 13 (mod 16) characters"
    admin_block = pkcs7(b'admin', bs).decode()
    d = int(len(email) / bs) * bs
    email = email[:-3] + admin_block + email[-3:]
    c = oracle(email)
    return c[:bs+d] + c[2*bs+d:3*bs+d] + c[bs+d:2*bs+d]

# email=AAAAAAAAA.admin:::::::::::com&uid=10&role=user              # swap
# _______________/_______________/_______________/_______________/  # blocks
#                     └-------------------┐                         # 2 and 3,
# email=AAAAAAAAA.com&uid=10&role=admin:::::::::::user              # discard
# _______________/_______________/_______________/_______________/  # block 4

if __name__ == "__main__":
    admin_cookie = rewrite_cookie()
    print(decrypt_oracle(admin_cookie))

