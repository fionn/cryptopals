#!/usr/bin/env python3
# Implement and break HMAC-SHA1 with an artificial timing leak

import time
import threading
import urllib.request
import urllib.error
from collections import namedtuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from Crypto.Random.random import getrandbits
from m02 import fixed_xor
from m28 import SHA1

def hmac_sha1(k, m):
    opad = b'\x5c' * SHA1.blocksize
    ipad = b'\x36' * SHA1.blocksize

    if len(k) > SHA1.blocksize:
        k = SHA1(k).digest()

    if len(k) < SHA1.blocksize:
        k = k + bytes(SHA1.blocksize - len(k))

    return SHA1(fixed_xor(k, opad) + SHA1(fixed_xor(k, ipad) + m).digest())

def insecure_compare(a, b, delay):
    assert len(a) == len(b)
    for c, d in zip(a, b):
        if c != d:
            return False
        time.sleep(delay)
    return True

def verify_hmac_sha1_hex(m, signature, k, delay):
    hmac = hmac_sha1(k, m).hexdigest().encode()
    return insecure_compare(signature, hmac, delay)

class Handler(BaseHTTPRequestHandler):

    key = None
    delay = None

    def _parse_result(self):
        Result = namedtuple("Result", ["path", "query"])
        result = self.path.split("?")
        try:
            qs = result[1].split("&")
            qs = {k: v.encode() for (k, v) in [q.split("=") for q in qs]}
            qs = namedtuple("QueryString", qs.keys())(**qs)
            return Result(result[0], qs)
        except IndexError:
            return Result(result, b'')

    def do_GET(self):
        query = self._parse_result().query
        try:
            if verify_hmac_sha1_hex(query.file, query.signature, self.key, self.delay):
                self.send_response_only(200)
                self.end_headers()
            else:
                self.send_response_only(500)
                self.end_headers()
        except AttributeError:
            self.send_response_only(500)
            self.end_headers()

class HMACListener:

    def __init__(self, server, key, delay):
        self.server = server
        self.key = key
        self.delay = delay
        self.stop_serving = threading.Event()

    def run(self, server_class = HTTPServer, handler_class = Handler):
        self.stop_serving.clear()
        handler_class.key = self.key
        handler_class.delay = self.delay
        httpd = server_class(self.server, handler_class)
        threading.Thread(target = self._serve_forever, args = [httpd]).start()

    def _serve_forever(self, httpd):
        while not self.stop_serving.is_set():
            httpd.handle_request()

    def stop(self):
        self.stop_serving.set()
        try:
            url = "http://{}:{}".format(*self.server)
            urllib.request.urlopen(url)
        except urllib.error.HTTPError or ConnectionResetError:
            pass

class HMACAttack:

    def __init__(self, server, verbose = False):
        self.server = server
        self.verbose = verbose
        self.base = bytearray(20)

    def _log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def _send_forgery(self, message, signature):
        query_string = "/test?file=" + message \
                       + "&signature=" + signature
        url = "http://{}:{}".format(*self.server) + query_string
        start_time = time.time()

        try:
            status_code = urllib.request.urlopen(url).getcode()
        except urllib.error.HTTPError as e:
            status_code = e.code

        delta = time.time() - start_time
        assert status_code in {200, 500}
        return status_code, delta

    @staticmethod
    def _signature_generator(index, base):
        for j in range(256):
            base[index] = j
            yield base

    def get_sha1_hmac(self, message):
        time_leak = 0
        for i in range(20):
            sig_gen = self._signature_generator(i, self.base)
            for sig in sig_gen:
                sig = sig.hex()
                code, delta = self._send_forgery(message, sig)
                if code == 200:
                    self._log(sig)
                    return sig
                if delta > time_leak:
                    time_leak = delta
                    self.base = bytearray.fromhex(sig)

                    self._log(sig[:2 * (i + 1)] + "··" * (19 - i), delta,
                              end = "\r", flush = True)

        raise RuntimeError("Could not determine HMAC, got {}"
                           .format(self.base.hex()))

if __name__ == "__main__":
    file_name = b"foo"
    key = bytes(getrandbits(8) for i in range(16))
    local_server = ("localhost", 9000)

    listener = HMACListener(local_server, key, delay = 0.025)

    try:
        listener.run()

        hmac_attack = HMACAttack(local_server, verbose = True)
        hex_hmac = hmac_attack.get_sha1_hmac(file_name.decode())
        assert hex_hmac == hmac_sha1(key, file_name).hexdigest()
        print(hex_hmac)

        listener.stop()

    except KeyboardInterrupt:
        listener.stop()

