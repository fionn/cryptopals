#!/usr/bin/env python3
# Implement Secure Remote Password (SRP)

import hmac
from hashlib import sha256
from abc import ABC, abstractmethod
from Crypto.Random.random import randrange

PRIME = int(open("data/33.txt", "r").read().replace("\n", ""), 16)

class SRPPeer(ABC):

    def __init__(self):
        self.N = None
        self.g = None
        self.k = None
        self.I = None
        self.P = None
        self.salt = None
        self.A = None
        self.B = None
        self._u = None
        self._K = None

    @abstractmethod
    def pubkey(self):
        pass

    @abstractmethod
    def gen_K(self):
        pass

    @staticmethod
    def _integer_hash(a, b):
        return int(sha256((str(a) + str(b)).encode("ascii")).hexdigest(), 16)

    def scrambler(self):
        self._u = self._integer_hash(self.A, self.B)

    def hmac(self):
        return hmac.new(self._K.digest(),
                        str(self.salt).encode("ascii"), sha256).hexdigest()

class Client(SRPPeer):

    def __init__(self, prime=None, email=None, password=None, g=2, k=3):
        super().__init__()
        self.N = prime
        self.g = g
        self.k = k
        self.I = email
        self.P = password
        self._a = None

    def pubkey(self):
        if not self._a:
            self._a = randrange(self.N)
        if not self.A:
            self.A = pow(self.g, self._a, self.N)
        return self.A

    def negotiate_send(self):
        return {"N": self.N,
                "g": self.g,
                "k": self.k,
                "I": self.I,
                "p": self.P
               }

    def send_email_pubkey(self):
        return {"I": self.I, "pubkey": self.pubkey()}

    def receive_salt_pubkey(self, parameters):
        self.salt = parameters["salt"]
        self.B = parameters["pubkey"]

    def gen_K(self):
        x = self._integer_hash(self.salt, self.P)
        S = pow(self.B - self.k * pow(self.g, x, self.N),
                self._a + self._u * x, self.N)
        self._K = sha256(str(S).encode("ascii"))

class Server(SRPPeer):

    def __init__(self):
        super().__init__()
        self.salt = randrange(64)
        self._v = None
        self._b = None

    def pubkey(self):
        if not self._b:
            self._b = randrange(self.N)
        if not self.B:
            self.B = self.k * self._v + pow(self.g, self._b, self.N)
        return self.B

    def verifier(self):
        x = self._integer_hash(self.salt, self.P)
        self._v = pow(self.g, x, self.N)

    def negotiate_receive(self, parameters):
        self.N = parameters["N"]
        self.g = parameters["g"]
        self.k = parameters["k"]
        self.I = parameters["I"]
        self.P = parameters["p"]

    def send_salt_pubkey(self):
        return {"salt": self.salt, "pubkey": self.pubkey()}

    def receive_email_pubkey(self, parameters):
        if self.I != parameters["I"]:
            raise ValueError("Expected {} but got {} instead"
                             .format(self.I, parameters["I"]))
        self.A = parameters["pubkey"]

    def gen_K(self):
        S = pow(self.A * pow(self._v, self._u, self.N), self._b, self.N)
        self._K = sha256(bytes(str(S), "ascii"))

    def receive_hmac(self, peer_hmac):
        if self.hmac() == peer_hmac:
            return 200
        return 500

def srp_protocol():
    carol = Client(PRIME, email="not@real.email", password="submarines")
    steve = Server()

    parameters = carol.negotiate_send()
    steve.negotiate_receive(parameters)

    steve.verifier()

    parameters = carol.send_email_pubkey()
    steve.receive_email_pubkey(parameters)

    parameters = steve.send_salt_pubkey()
    carol.receive_salt_pubkey(parameters)

    carol.scrambler()
    steve.scrambler()

    carol.gen_K()
    steve.gen_K()

    hmac_c = carol.hmac()
    return steve.receive_hmac(hmac_c)

if __name__ == "__main__":
    response = srp_protocol()
    print(response)

