#!/usr/bin/env python3
"""Implement and break HMAC-SHA1 with an artificial timing leak"""

# pylint: disable=consider-using-f-string

import sys
import time
import threading
import urllib.request
import urllib.error
from typing import Generator
from collections import namedtuple
from http.server import HTTPServer, BaseHTTPRequestHandler

from Crypto.Random import get_random_bytes

from m02 import fixed_xor
from m28 import SHA1

def hmac_sha1(key: bytes, message: bytes) -> SHA1:
    opad = b"\x5c" * SHA1.block_size
    ipad = b"\x36" * SHA1.block_size

    if len(key) > SHA1.block_size:
        key = SHA1(key).digest()

    if len(key) < SHA1.block_size:
        key += bytes(SHA1.block_size - len(key))

    return SHA1(fixed_xor(key, opad)
                + SHA1(fixed_xor(key, ipad) + message).digest())

def insecure_compare(a: bytes, b: bytes, delay: float) -> bool:
    if len(a) != len(b):
        raise IndexError("Arguments must be the same size")
    for c, d in zip(a, b):
        if c != d:
            return False
        time.sleep(delay)
    return True

def verify_hmac_sha1_hex(message: bytes, signature: bytes,
                         key: bytes, delay: float) -> bool:
    hmac = hmac_sha1(key, message).hexdigest().encode()
    return insecure_compare(signature, hmac, delay)

class BaseHandler(BaseHTTPRequestHandler):
    key: bytes = b""
    delay: float = 0

class Handler(BaseHandler):

    Result = namedtuple("Result", ["path", "query"])

    def _parse_result(self) -> "Handler.Result":
        result = self.path.split("?")
        try:
            qs_list = result[1].split("&")
            qs_dict = {k: v.encode() for (k, v) in [q.split("=")
                                                    for q in qs_list]}
            qs = namedtuple("QueryString", qs_dict.keys())(**qs_dict)
            return self.Result(result[0], qs)
        except IndexError:
            return self.Result(result, b"")

    def do_GET(self) -> None:
        query = self._parse_result().query
        try:
            if verify_hmac_sha1_hex(query.file, query.signature,
                                    self.key, self.delay):
                self.send_response_only(200)
                self.end_headers()
            else:
                self.send_response_only(500)
                self.end_headers()
        except AttributeError:
            # If _parse_results hits IndexError, query.file doesn't exist
            self.send_response_only(500)
            self.end_headers()

class HMACListener:

    def __init__(self, server: tuple[str, int], key: bytes,
                 delay: float) -> None:
        self.server = server
        self.key = key
        self.delay = delay
        self.stop_serving = threading.Event()

    def run(self, server_class: type = HTTPServer,
            handler_class: type[BaseHandler] = Handler) -> None:
        self.stop_serving.clear()
        handler_class.key = self.key
        handler_class.delay = self.delay
        httpd = server_class(self.server, handler_class)
        threading.Thread(target=self._serve_forever, args=[httpd]).start()

    def _serve_forever(self, httpd: HTTPServer) -> None:
        while not self.stop_serving.is_set():
            httpd.handle_request()

    def stop(self) -> None:
        self.stop_serving.set()
        url = "http://{}:{}".format(*self.server)
        try:
            with urllib.request.urlopen(url):
                pass
        except (urllib.error.HTTPError, ConnectionResetError,
                urllib.error.URLError):
            pass

class HMACAttack:

    def __init__(self, server: tuple[str, int]) -> None:
        self.server = server
        self.base = bytearray(20)

    def _send_forgery(self, message: str, signature: str) -> tuple[int, float]:
        query_string = "/test?file=" + message \
                       + "&signature=" + signature
        url = "http://{}:{}".format(*self.server) + query_string
        start_time = time.time()

        try:
            with urllib.request.urlopen(url) as response:
                status_code = response.getcode()
        except urllib.error.HTTPError as e:
            if e.code not in {200, 500}:
                raise e
            status_code = e.code

        delta = time.time() - start_time
        return status_code, delta

    @staticmethod
    def _signature_generator(index: int,
                             base: bytearray) -> Generator[bytes, None, None]:
        for j in range(256):
            base[index] = j
            yield base

    @staticmethod
    def print_progress(sig_hex: str, delta: float, i: int) -> None:
        print(sig_hex[:2 * (i + 1)] + "··" * (19 - i), delta,
              end="\r", file=sys.stdout, flush=True)

    def get_sha1_hmac(self, message: str) -> str:
        time_leak = 0.0
        for i in range(20):
            sig_gen = self._signature_generator(i, self.base)
            for binary_sig in sig_gen:
                sig_hex = binary_sig.hex()
                code, delta = self._send_forgery(message, sig_hex)
                if code == 200:
                    return sig_hex
                if delta > time_leak:
                    time_leak = delta
                    self.base = bytearray.fromhex(sig_hex)
                    self.print_progress(sig_hex, delta, i)

        raise RuntimeError(f"Could not determine HMAC, got {self.base.hex()}")

def main() -> None:
    file_name = b"foo"
    key = get_random_bytes(16)
    local_server = ("localhost", 9031)

    listener = HMACListener(local_server, key, delay=0.025)
    listener.run()

    try:
        hmac_attack = HMACAttack(local_server)
        hex_hmac = hmac_attack.get_sha1_hmac(file_name.decode())
        assert hex_hmac == hmac_sha1(key, file_name).hexdigest()
        print(hex_hmac)
    finally:
        listener.stop()

if __name__ == "__main__":
    main()
