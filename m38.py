#!/usr/bin/env python3
"""Offline dictionary attack on simplified SRP"""

# Requires cracklib-small from
# https://github.com/cracklib/cracklib/tree/master/src/dicts.

import hmac
import hashlib
from pathlib import Path
from typing import Iterator, Optional

from Crypto.Random.random import randrange

import m36

# Note that we nececessarily diverge from the problem as stated.
# See https://depp.brause.cc/cryptopals/05/38.rb for a correct formulation.

# pylint: disable=too-many-instance-attributes
class SimpleClient(m36.IntegerHasher):

    def __init__(self, prime: int, generator: int,
                 username: str, password: str) -> None:
        self.n = prime
        self.g = generator
        self.I = username

        self.salt = randrange(64)

        self._x = self._integer_hash(self.salt, password)
        self.v = pow(self.g, self._x, self.n)

        self._a = randrange(self.n)
        self.A = pow(self.g, self._a, self.n)

    def gen_hmac(self, s: int, B: int, u: int) -> bytes:
        secret = pow(B, self._a + u * self._x, self.n)
        k = hashlib.sha256(str(secret).encode("ascii")).digest()
        return hmac.new(k, s.to_bytes(64, "big"), hashlib.sha256).digest()

class SimpleServer(m36.IntegerHasher):

    def __init__(self, prime: int, generator: int) -> None:
        self.n = prime
        self.g = generator

        self._b = randrange(self.n)
        self.client: dict[str, dict[str, int]] = {}

    def register(self, I: str, s: int, v: int) -> None:
        self.client[I] = {"s": s, "v": v}

    def receive_pubkey(self, I: str, A: int) -> dict[str, int]:
        self.client[I]["A"] = A
        self.client[I]["u"] = randrange(16)

        return {"s": self.client[I]["s"],
                "B": pow(self.g, self._b, self.n),
                "u": self.client[I]["u"]}

    def verify_hmac(self, I: str, client_hmac: bytes) -> bool:
        client = self.client[I]
        v_pow_u = pow(client["v"], client["u"])
        secret = pow(client["A"] * v_pow_u, self._b, self.n)
        k = hashlib.sha256(str(secret).encode("ascii")).digest()
        server_hmac = hmac.new(k, client["s"].to_bytes(64, "big"), hashlib.sha256)
        return hmac.compare_digest(client_hmac, server_hmac.digest())

class EvilServer(SimpleServer):

    @staticmethod
    def _words() -> Iterator[str]:
        wordlists = [Path("/usr/share/dict/cracklib-small"),  # on Linux
                     Path("/usr/share/dict/words")]           # on macOS
        wordlist_file = [w for w in wordlists if w.exists()][0]
        with wordlist_file.open() as wordlist:
            for line in wordlist:
                yield line.strip()

    def crack_password(self, I: str, client_hmac: bytes) -> Optional[str]:
        if not self.verify_hmac(I, client_hmac):
            raise AssertionError("Failed to verify client HMAC")

        s = self.client[I]["s"]
        u = self.client[I]["u"]
        A = self.client[I]["A"]

        for candidate in self._words():
            x = self._integer_hash(s, candidate)
            v = pow(self.g, x, self.n)
            v_pow_u = pow(v, u)
            secret = pow(A * v_pow_u, self._b, self.n)

            k = hashlib.sha256(str(secret).encode("ascii")).digest()
            computed_hmac = hmac.new(k, s.to_bytes(64, "big"), hashlib.sha256)

            if hmac.compare_digest(client_hmac, computed_hmac.digest()):
                return candidate

        return None

def simple_srp(client: SimpleClient, server: SimpleServer) -> bool:
    server.register(client.I, client.salt, client.v)

    s_b_u = server.receive_pubkey(client.I, client.A)
    client_hmac = client.gen_hmac(**s_b_u)

    return server.verify_hmac(client.I, client_hmac)

def mitm_simple_srp(client: SimpleClient, evil_server: EvilServer) -> str:
    evil_server.register(client.I, client.salt, client.v)

    s_b_u = evil_server.receive_pubkey(client.I, client.A)
    client_hmac = client.gen_hmac(**s_b_u)

    password = evil_server.crack_password(client.I, client_hmac)

    if password:
        return password
    raise RuntimeError("Failed to find candidate password")

def main() -> None:
    n = m36.prime()
    g = 2

    password = "abacus"
    client = SimpleClient(prime=n, generator=g,
                          username="srp-client@cryptopals.com",
                          password=password)
    server = SimpleServer(prime=n, generator=g)

    # Test the simple SRP protocol
    assert simple_srp(client, server)

    # Crack the password
    evil_server = EvilServer(prime=n, generator=g)

    candidate_password = mitm_simple_srp(client, evil_server)
    if candidate_password == password:
        print(password)
    else:
        raise ValueError(f"Candidate \"{candidate_password}\" is incorrect")

if __name__ == "__main__":
    main()
