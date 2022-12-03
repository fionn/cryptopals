#!/usr/bin/env python3
"""Implement Secure Remote Password (SRP)"""

import hmac
import hashlib
from functools import cache
from abc import ABC, abstractmethod
from typing import TypedDict

from Crypto.Random.random import randrange

Parameters = TypedDict("Parameters", {"N": int, "g": int, "k": int,
                                      "I": str, "p": str})
EmailPubKey = TypedDict("EmailPubKey", {"I": str, "pubkey": int})

@cache
def prime() -> int:
    with open("data/33.txt", "r") as prime_file:
        return int(prime_file.read().replace("\n", ""), 16)

class IntegerHasher:

    @staticmethod
    def _integer_hash(a: str | int, b: str | int) -> int:
        return int(hashlib.sha256((str(a) + str(b)).encode("ascii")).hexdigest(), 16)

# pylint: disable=too-many-instance-attributes
class SRPPeer(ABC, IntegerHasher):

    def __init__(self) -> None:
        self.N: int = None
        self.g: int = None
        self.k: int = None
        self.I: str = None
        self.P: str = None
        self.salt: int = None
        self.A: int = None
        self.B: int = None
        self._u: int = None
        # pylint: disable=no-member,protected-access
        self._K: hashlib._Hash = None

    @abstractmethod
    def pubkey(self) -> int:
        pass

    @abstractmethod
    def gen_K(self) -> None:
        pass

    def scrambler(self) -> None:
        self._u = self._integer_hash(self.A, self.B)

    def hmac(self) -> str:
        return hmac.new(self._K.digest(),
                        str(self.salt).encode("ascii"),
                        hashlib.sha256).hexdigest()

# pylint: disable=too-many-instance-attributes
class Client(SRPPeer):

    def __init__(self, p: int = None, email: str = None,
                 password: str = None, g: int = 2, k: int = 3) -> None:
        super().__init__()
        self.N = p
        self.g = g
        self.k = k
        self.I = email
        self.P = password
        self._a: int = None

    def pubkey(self) -> int:
        if self._a is None:
            self._a = randrange(self.N)
        if self.A is None:
            self.A = pow(self.g, self._a, self.N)
        return self.A

    def negotiate_send(self) -> Parameters:
        return {"N": self.N,
                "g": self.g,
                "k": self.k,
                "I": self.I,
                "p": self.P}

    def send_email_pubkey(self) -> EmailPubKey:
        return {"I": self.I, "pubkey": self.pubkey()}

    def receive_salt_pubkey(self, parameters: dict[str, int]) -> None:
        self.salt = parameters["salt"]
        self.B = parameters["pubkey"]

    def gen_K(self) -> None:
        x = self._integer_hash(self.salt, self.P)
        S = pow(self.B - self.k * pow(self.g, x, self.N),
                self._a + self._u * x, self.N)
        self._K = hashlib.sha256(str(S).encode("ascii"))

# pylint: disable=too-many-instance-attributes
class Server(SRPPeer):

    def __init__(self) -> None:
        super().__init__()
        self.salt = randrange(64)
        self._v: int = None
        self._b: int = None

    def pubkey(self) -> int:
        if not self._b:
            self._b = randrange(self.N)
        if not self.B:
            self.B = self.k * self._v + pow(self.g, self._b, self.N)
        return self.B

    def verifier(self) -> None:
        x = self._integer_hash(self.salt, self.P)
        self._v = pow(self.g, x, self.N)

    def negotiate_receive(self, parameters: Parameters) -> None:
        self.N = parameters["N"]
        self.g = parameters["g"]
        self.k = parameters["k"]
        self.I = parameters["I"]
        self.P = parameters["p"]

    def send_salt_pubkey(self) -> dict[str, int]:
        return {"salt": self.salt, "pubkey": self.pubkey()}

    def receive_email_pubkey(self, parameters: EmailPubKey) -> None:
        if self.I != parameters["I"]:
            raise ValueError("Expected {self.I}, got {parameters['I']} instead")
        self.A = parameters["pubkey"]

    def gen_K(self) -> None:
        S = pow(self.A * pow(self._v, self._u, self.N), self._b, self.N)
        self._K = hashlib.sha256(bytes(str(S), "ascii"))

    def receive_hmac(self, peer_hmac: str) -> bool:
        return hmac.compare_digest(self.hmac(), peer_hmac)

def srp_protocol(client: Client, server: Server) -> int:
    parameters = client.negotiate_send()
    server.negotiate_receive(parameters)

    server.verifier()

    email_pubkey = client.send_email_pubkey()
    server.receive_email_pubkey(email_pubkey)

    parameters_salt_pubkey = server.send_salt_pubkey()
    client.receive_salt_pubkey(parameters_salt_pubkey)

    client.scrambler()
    server.scrambler()

    client.gen_K()
    server.gen_K()

    hmac_c = client.hmac()
    return server.receive_hmac(hmac_c)

def main() -> None:
    p = prime()

    carol = Client(p, email="not@real.email", password="submarines")
    steve = Server()

    response = srp_protocol(carol, steve)
    print(response)

if __name__ == "__main__":
    main()
