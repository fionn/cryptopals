#!/usr/bin/env python3
"""ECB cut-and-paste"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from m09 import pkcs7, de_pkcs7

RANDOM_KEY = get_random_bytes(16)

def parse(string: str) -> dict[str, str]:
    cookie = {}
    for pairs in string.split("&"):
        key, value = pairs.split("=")
        cookie[key] = value
    return cookie

def profile_for(email: str) -> str:
    email = email.replace("&", "").replace("=", "")
    profile = {"email": email, "uid": 10, "role": "user"}
    return "&".join([key + "=" + str(profile[key])
                     for key in ["email", "uid", "role"]])

def oracle(email: str) -> bytes:
    profile = profile_for(email)
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cypher.encrypt(pkcs7(bytes(profile, "ascii"), 16))

def decrypt_oracle(profile: bytes) -> dict[str, str]:
    cypher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    profile = de_pkcs7(cypher.decrypt(profile))
    return parse(profile.decode())

def rewrite_cookie(email: str) -> bytes:
    bs = 16
    if len(email) % bs != 13:
        raise ValueError(f"email must be 13 (mod {bs}) characters")
    admin_block = pkcs7(b"admin", bs).decode()
    d = int(len(email) / bs) * bs
    email = email[:-3] + admin_block + email[-3:]
    c = oracle(email)
    return c[:bs + d] + c[2 * bs + d:3 * bs + d] + c[bs + d:2 * bs + d]

# email=AAAAAAAAA.admin:::::::::::com&uid=10&role=user              # swap
# _______________/_______________/_______________/_______________/  # blocks
#                     └-------------------┐                         # 2 and 3,
# email=AAAAAAAAA.com&uid=10&role=admin:::::::::::user              # discard
# _______________/_______________/_______________/_______________/  # block 4

def main() -> None:
    admin_cookie = rewrite_cookie("fake@mail.com")
    print(decrypt_oracle(admin_cookie))

if __name__ == "__main__":
    main()
