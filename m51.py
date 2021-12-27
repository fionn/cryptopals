#!/usr/bin/env python3
"""Compression Ratio Side-Channel Attacks"""
# "Never reveal the Wu-Tang Secret!"

import string
from zlib import compress
from typing import Callable

from Crypto.Random import get_random_bytes

from m09 import pkcs7
from m10 import encrypt_aes_cbc
from m18 import aes_ctr

BLOCKSIZE = 16
SESSION_ID = b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

def format_request(payload: bytes) -> bytes:
    """POST request"""
    return (b"POST / HTTP/1.1\n"
            b"Host: hapless.com\n"
            b"Cookie: sessionid=%b\n"
            b"Content-Length: %d\n\n%b" % (SESSION_ID, len(payload), payload))

def ctr_oracle(plaintext: bytes) -> int:
    """Stream cipher compression oracle"""
    key = get_random_bytes(BLOCKSIZE)
    return len(aes_ctr(compress(format_request(plaintext)), key))

def cbc_oracle(plaintext: bytes) -> int:
    """CBC-mode compression orcle"""
    key = get_random_bytes(BLOCKSIZE)
    iv = get_random_bytes(BLOCKSIZE)
    return len(encrypt_aes_cbc(key, iv, pkcs7(compress(format_request(plaintext)))))

def gen_padding(payload: bytes, oracle: Callable[[bytes], int]) -> bytes:
    """Generate padding to fill the record and split it in two"""
    padding_alphabet = b"!@#$%^&*()-`~[]{}"
    length = oracle(payload)
    padding = b""
    for character in padding_alphabet:
        padding += bytes([character])
        if oracle(padding + payload) > length:
            return padding
    raise AssertionError("Failed to find padding")

def attack(oracle: Callable[[bytes], int]) -> bytes:
    """CRIME attack"""
    b64_alphabet = str.encode(string.ascii_letters + string.digits + "+/=")

    session_id_length = len(SESSION_ID)
    prefix = b"Cookie: sessionid="
    extra_spaces = BLOCKSIZE * b" "

    recovered_id = b""
    while len(recovered_id) < session_id_length:
        min_size = float("inf")
        min_character = b""

        padding = gen_padding(8 * (prefix + recovered_id + b"~" + extra_spaces),
                              oracle)

        for character in b64_alphabet:
            payload = prefix + recovered_id + bytearray([character])
            compressed_size = oracle(padding + 8 * (payload + extra_spaces))

            # The below is almost as effective and doesn't require custom
            # padding, but fails for the given SESSION_ID.
            #compressed_size = oracle(payload + b"~" * BLOCKSIZE)

            print(payload.decode()
                  + "·" * (session_id_length - len(payload) + len(prefix)),
                  compressed_size, end="\r", flush=True)

            if compressed_size < min_size:
                min_size = compressed_size
                min_character = bytes([character])

        recovered_id += min_character

    print()

    return recovered_id

def main() -> None:
    """Entry point"""
    session_id = attack(ctr_oracle)
    assert session_id == SESSION_ID, SESSION_ID

    session_id = attack(cbc_oracle)
    assert session_id == SESSION_ID, SESSION_ID

if __name__ == "__main__":
    main()
