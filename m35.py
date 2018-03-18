#!/usr/bin/env python3
# Implement DH with negotiated groups, and break with malicious "g" parameters

import time
import socket
import json
import threading
import logging
from collections import namedtuple
from Crypto.Random.random import randrange, getrandbits
from m09 import pkcs7, de_pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc
from m28 import SHA1

class DHSocket:

    NULL_BYTES = bytes(32)
    Peer = namedtuple("Peer", ["name", "address", "origin", "pubkey", "socket"])

    def __init__(self, name, p=None, g=None, address=("localhost", 0)):
        self.name = name
        self.p = p
        self.g = g
        self._s = None
        self._private_key = None
        self._peer = None
        self._message_buffer = []

        self._sock_incoming = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_incoming.bind(address)
        self._sock_incoming.listen()
        self.address = self._sock_incoming.getsockname()

        self._connection = None
        self._stop_listening = threading.Event()
        self._stop_listening.clear()
        threading.Thread(target=self._listen).start()

    def __repr__(self):
        return "{}(\"{}\")".format(self.__class__.__name__, self.name)

    def __del__(self):
        self._stop_listening.set()
        self._sock_incoming.close()
        self._peer.socket.close()

    @property
    def _a(self):
        if not self._private_key:
            self._private_key = randrange(self.p)
        return self._private_key

    @property
    def pubkey(self):
        return pow(self.g, self._a, self.p)

    def _session_key(self):
        if self._s is None:
            self._s = pow(self._peer.pubkey, self._a, self.p)
        return self._s

    def _aes_key(self):
        s = self._session_key()
        return SHA1(s.to_bytes(s.bit_length() // 8 + 1, "big")).digest()[:16]

    def _listen(self):
        logging.info("%s listening on %s:%s", self.name, *self.address)
        try:
            if not self._stop_listening.is_set():
                self._connection = self._sock_incoming.accept()[0]
            else:
                self._sock_incoming.close()
        finally:
            self._sock_incoming.close()

    def _get_buffer(self):
        Buffer = namedtuple("Buffer", ["origin", "data"])
        stream = bytes()
        while True:
            if self._connection:
                block = self._connection.recv(1024)
                stream += block
                if self.NULL_BYTES in block:
                    origin = self._connection.getpeername()
                    return Buffer(origin, stream[:-len(self.NULL_BYTES)])
            else:
                time.sleep(0.0001)
                return self._get_buffer()

    def _send(self, data, peer):
        data += self.NULL_BYTES
        peer.socket.send(data)

    def _send_dict(self, data, peer=None):
        peer = peer or self._peer
        data = json.dumps(data).encode()
        self._send(data, peer)

    def _receive_connection(self, packet, origin):
        self._peer = self.Peer(name=packet["name"],
                               address=tuple(packet["address"]),
                               origin=origin,
                               pubkey=None,
                               socket=socket.socket(socket.AF_INET,
                                                    socket.SOCK_STREAM))
        self._peer.socket.connect(self._peer.address)

    def connect(self, peer_name, peer_address):
        self._peer = self.Peer(name=peer_name,
                               address=peer_address,
                               origin=None,
                               pubkey=None,
                               socket=socket.socket(socket.AF_INET,
                                                    socket.SOCK_STREAM))
        self._peer.socket.connect(self._peer.address)
        intro = {"name": self.name, "address": self.address}
        self._send_dict(intro, self._peer)
        logging.info("%s hello --> %s@%s:%s", self.name, self._peer.name,
                     *self._peer.address)

    def apply(self):
        raw_packet = self._get_buffer()
        try:
            packet = json.loads(raw_packet.data.decode("ascii"))
            self.p = packet.get("p", self.p)
            self.g = packet.get("g", self.g)
            peer_pubkey = packet.get("pubkey", None)
            if "name" and "address" in packet:
                self._receive_connection(packet, raw_packet.origin)
            if peer_pubkey is not None and self._peer.pubkey is None:
                self._peer = self._peer._replace(pubkey=packet["pubkey"])
                logging.info("%s received %s's public key", self.name, self._peer.name)
        except (UnicodeDecodeError, json.decoder.JSONDecodeError):
            self._message_buffer.append(raw_packet.data)

    def send_parameters(self, peer=None, g=None):
        g = g or self.g
        peer = peer or self._peer
        parameters = {"p": self.p, "g": g}
        self._send_dict(parameters, peer)
        logging.info("%s parameters -->%s@%s:%s", self.name, peer.name, *peer.address)

    def send_pubkey(self):
        A = {"pubkey": self.pubkey}
        self._send_dict(A, self._peer)
        logging.info("%s pubkey --> %s@%s:%s", self.name, self._peer.name,
                     *self._peer.address)

    def send_message(self, message):
        iv = bytes(getrandbits(8) for i in range(16))
        cyphertext = encrypt_aes_cbc(pkcs7(message), self._aes_key(), iv)
        self._send(cyphertext + iv, self._peer)

    def decrypt(self, cyphertext=None):
        cyphertext = cyphertext or self._message_buffer.pop()
        iv = cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(cyphertext[:-16], self._aes_key(), iv))
        return message

    def echo_message(self):
        cyphertext = self._message_buffer.pop()
        message = self.decrypt(cyphertext)
        self.send_message(message)

class DHMaliciousSocket(DHSocket):

    def __init__(self, name, bad_g, address=("localhost", 0)):
        super().__init__(name, address=address)
        self.original_g = None
        self.bad_g = bad_g
        self._peers = dict()

    def __del__(self):
        self._stop_listening.set()
        self._sock_incoming.close()
        for name, peer in self._peers.items():
            peer.socket.close()

    def _send(self, data, peer):
        try:
            peer.socket.connect(peer.address)
        except OSError as e:
            if e.errno != 106: # Transport endpoint is already connected.
                raise e
        super()._send(data, peer)

    def _add_peer(self, peer_name, peer_address, origin=None, pubkey=None):
        peer = self.Peer(name=peer_name,
                         address=peer_address,
                         origin=origin,
                         pubkey=pubkey,
                         socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self._peers[peer_name] = peer
        if origin:
            self._peers[origin] = peer

    def _mitm_parameters(self, peer_name, packet):
        self.original_g = packet["g"]
        self.p = packet["p"]
        packet["g"] = self.bad_g
        self.send_parameters(self._peers[peer_name], self.bad_g)

        if logging.getLogger().getEffectiveLevel() <= logging.INFO:
            x = (self.bad_g == self.p - 1) * "p - 1"
            y = (self.bad_g == self.p) * "p"
            logging.info("%s swaps g = %s <--> g = %s",
                         self.name, self.original_g, x or y or self.bad_g)

    def _mitm_connection(self, peer_name, peer_address, packet, origin):
        self._add_peer(packet["name"], packet["address"], origin) # alice
        self._add_peer(peer_name, peer_address) # bob
        self._send_dict(packet, self._peers[peer_name])

    def mitm(self, peer_name, peer_address=None):
        raw_packet = self._get_buffer()
        try:
            packet = json.loads(raw_packet.data.decode("ascii"))
            if peer_address is not None and "name" and "address" in packet:
                self._mitm_connection(peer_name, peer_address, packet,
                                      raw_packet.origin)
            if "p" and "g" in packet:
                self._mitm_parameters(peer_name, packet)
            elif "pubkey" in packet:
                sender = self._peers.get(raw_packet.origin, None)
                self._peers[sender.name] = self._peers[sender.name] \
                                           ._replace(pubkey=packet["pubkey"])
                self._send(raw_packet.data, self._peers[peer_name])
                logging.info("%s passing packet to %s@%s:%s", self.name,
                             peer_name, *self._peers[peer_name].address)
        except (UnicodeDecodeError, json.decoder.JSONDecodeError):
            self._message_buffer.append(raw_packet.data)
            self._send(raw_packet.data, self._peers[peer_name])

    def break_dh(self):
        if self.bad_g == 1:
            self._s = 1
            return self.decrypt()
        elif self.bad_g == self.p:
            self._s = 0
            return self.decrypt()
        elif self.bad_g == self.p - 1:
            cyphertext = self._message_buffer.pop()
            longest_message = b''
            for self._s in [1, self.bad_g]:
                message = self.decrypt(cyphertext)
                try:
                    message.decode("ascii")
                    if len(message) > len(longest_message):
                        longest_message = message
                except UnicodeDecodeError:
                    continue
            return longest_message
        raise RuntimeError("g must be 1, p or p - 1, not {}".format(g))

def dh_protocol(p, g, message):
    alice = DHSocket("alice", p, g)
    bob = DHSocket("bob")

    alice.connect(bob.name, bob.address)
    bob.apply()

    alice.send_parameters()
    bob.apply()

    alice.send_pubkey()
    bob.apply()

    bob.send_pubkey()
    alice.apply()

    alice.send_message(message)
    bob.apply()

    bob.echo_message()
    alice.apply()

    return alice.decrypt()

def dh_malicious_g(p, g, message, bad_g):
    alice = DHSocket("alice", p, g)
    bob = DHSocket("bob")
    mallory = DHMaliciousSocket("mallory", bad_g)

    alice.connect(bob.name, mallory.address)
    mallory.mitm(bob.name, bob.address)
    bob.apply()

    alice.send_parameters()
    mallory.mitm(bob.name)
    bob.apply()

    alice.send_pubkey()
    mallory.mitm(bob.name)
    bob.apply()

    bob.send_pubkey()
    # No MitM here because Mallory didn't spoof alice.address
    alice.apply()

    alice.send_message(message)
    mallory.mitm(bob.name)
    bob.apply()

    plaintext = mallory.break_dh()

    bob.echo_message()
    alice.apply()

    return plaintext

if __name__ == "__main__":
    p = int(open("data/33.txt", "r").read().replace("\n", ""), 16)
    g = 2

    logging.basicConfig(level=logging.INFO, format="{message}", style="{")

    message = b"Attack at dawn"

    print(dh_protocol(p, g, message))
    print(40 * "~")
    print(dh_malicious_g(p, g, message, bad_g=1))
    print(40 * "~")
    print(dh_malicious_g(p, g, message, bad_g=p))
    print(40 * "~")
    print(dh_malicious_g(p, g, message, bad_g=p - 1))

