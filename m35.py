#!/usr/bin/env python3
"""Implement DH with negotiated groups, and break with malicious "g" parameters"""

import time
import socket
import json
import threading
import logging
from typing import NamedTuple, Optional, Mapping, TypedDict

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange

from m09 import pkcs7, de_pkcs7
from m10 import encrypt_aes_cbc, decrypt_aes_cbc
from m28 import SHA1

Address = NamedTuple("Address", [("host", str), ("port", int)])
ConnPacket = TypedDict("ConnPacket", {"name": str, "address": Address})
ParamPacket = TypedDict("ParamPacket", {"p": int, "g": int})

class DHSocket:  # pylint: disable=too-many-instance-attributes

    NULL_BYTES = bytes(32)
    Peer = NamedTuple("Peer", [("name", str), ("address", Address),
                               ("origin", Optional[str]), ("pubkey", Optional[int]),
                               ("socket", socket.socket)])
    Buffer = NamedTuple("Buffer", [("origin", str), ("data", bytes)])

    def __init__(self, name: str, p: int = None, g: int = None,
                 address: Address = Address("localhost", 0)) -> None:
        self.name = name
        self.p = p
        self.g = g
        self._s: int = None
        self._private_key: int = None
        self._peer: DHSocket.Peer = None
        self._message_buffer: list[bytes] = []

        self._sock_incoming = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_incoming.bind(address)
        self._sock_incoming.listen()
        self.address = Address(*self._sock_incoming.getsockname())

        self._connection: socket.socket = None
        self._stop_listening = threading.Event()
        self._stop_listening.clear()
        threading.Thread(target=self._listen).start()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(\"{self.name}\")"

    def __del__(self) -> None:
        self._stop_listening.set()
        self._sock_incoming.close()
        try:
            self._connection.close()
        except AttributeError:
            pass
        if self._peer is not None:
            self._peer.socket.close()

    @property
    def _a(self) -> int:
        if self._private_key is None:
            self._private_key = randrange(self.p)
        return self._private_key

    @property
    def pubkey(self) -> int:
        if self.g is None or self.p is None:
            raise RuntimeError
        return pow(self.g, self._a, self.p)

    def _session_key(self) -> int:
        if self._s is None:
            if self._peer is None:
                raise RuntimeError
            self._s = pow(self._peer.pubkey, self._a, self.p)
        return self._s

    def _aes_key(self) -> bytes:
        s = self._session_key()
        return SHA1(s.to_bytes(s.bit_length() // 8 + 1, "big")).digest()[:16]

    def _listen(self) -> None:
        logging.info("%s listening on %s:%s", self.name, *self.address)
        try:
            if not self._stop_listening.is_set():
                self._connection = self._sock_incoming.accept()[0]
            else:
                self._sock_incoming.close()
        finally:
            self._sock_incoming.close()

    def _get_buffer(self) -> "DHSocket.Buffer":
        stream = b""
        while True:
            if self._connection:
                block = self._connection.recv(1024)
                stream += block
                if self.NULL_BYTES in block:
                    origin = self._connection.getpeername()
                    return self.Buffer(origin, stream[:-len(self.NULL_BYTES)])
            else:
                time.sleep(0.0001)
                return self._get_buffer()

    def _send(self, data: bytes, peer: Peer) -> None:
        data += self.NULL_BYTES
        peer.socket.send(data)

    def _send_dict(self, data: Mapping[str, object], peer: Peer = None) -> None:
        peer = peer or self._peer
        if not peer:
            raise RuntimeError
        data_encoded = json.dumps(data).encode()
        self._send(data_encoded, peer)

    def _receive_connection(self, packet: ConnPacket, origin: str) -> None:
        self._peer = self.Peer(name=packet["name"],
                               address=packet["address"],
                               origin=origin,
                               pubkey=None,
                               socket=socket.socket(socket.AF_INET,
                                                    socket.SOCK_STREAM))
        self._peer.socket.connect(self._peer.address)

    def connect(self, peer_name: str, peer_address: Address) -> None:
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

    def apply(self) -> None:
        raw_packet = self._get_buffer()
        try:
            packet = json.loads(raw_packet.data.decode("ascii"))
            self.p = packet.get("p", self.p)
            self.g = packet.get("g", self.g)
            peer_pubkey = packet.get("pubkey", None)
            if {"name", "address"} <= set(packet):
                packet["address"] = Address(*packet["address"])
                self._receive_connection(packet, raw_packet.origin)
            if peer_pubkey is not None and self._peer.pubkey is None:
                self._peer = self._peer._replace(pubkey=packet["pubkey"])
                logging.info("%s received %s's public key",
                             self.name, self._peer.name)
        except (UnicodeDecodeError, json.decoder.JSONDecodeError):
            self._message_buffer.append(raw_packet.data)

    def send_parameters(self, peer: Peer = None, g: int = None) -> None:
        g = g or self.g
        peer = peer or self._peer
        if not peer:
            raise RuntimeError
        parameters = {"p": self.p, "g": g}
        self._send_dict(parameters, peer)
        logging.info("%s parameters --> %s@%s:%s",
                     self.name, peer.name, *peer.address)

    def send_pubkey(self) -> None:
        A = {"pubkey": self.pubkey}
        self._send_dict(A, self._peer)
        logging.info("%s pubkey --> %s@%s:%s", self.name, self._peer.name,
                     *self._peer.address)

    def send_message(self, message: bytes) -> None:
        iv = get_random_bytes(16)
        cyphertext = encrypt_aes_cbc(self._aes_key(), iv, pkcs7(message))
        self._send(cyphertext + iv, self._peer)

    def decrypt(self, cyphertext: bytes = None) -> bytes:
        cyphertext = cyphertext or self._message_buffer.pop()
        iv = cyphertext[-16:]
        message = de_pkcs7(decrypt_aes_cbc(self._aes_key(), iv,
                                           cyphertext[:-16]))
        return message

    def echo_message(self) -> None:
        cyphertext = self._message_buffer.pop()
        message = self.decrypt(cyphertext)
        self.send_message(message)

class DHMaliciousSocket(DHSocket):

    def __init__(self, name: str, bad_g: int,
                 address: Address = Address("localhost", 0)) -> None:
        super().__init__(name, address=address)
        self.original_g: int = None
        self.bad_g = bad_g
        self._peers: dict[str, DHSocket.Peer] = {}

    def __del__(self) -> None:
        super().__del__()
        for peer in self._peers.values():
            peer.socket.close()

    def _send(self, data: bytes, peer: DHSocket.Peer) -> None:
        try:
            peer.socket.connect(peer.address)
        except OSError as e:
            # Transport endpoint is already connected, or
            # socket is already connected
            if e.errno not in {106, 56}:
                raise e
        super()._send(data, peer)

    def _add_peer(self, peer_name: str, peer_address: Address,
                  origin: str = None, pubkey: int = None) -> None:
        peer = self.Peer(name=peer_name,
                         address=peer_address,
                         origin=origin,
                         pubkey=pubkey,
                         socket=socket.socket(socket.AF_INET,
                                              socket.SOCK_STREAM))
        self._peers[peer_name] = peer
        if origin:
            self._peers[origin] = peer

    def _mitm_parameters(self, peer_name: str, packet: ParamPacket) -> None:
        self.original_g = packet["g"]
        self.p: int = packet["p"]
        packet["g"] = self.bad_g
        self.send_parameters(self._peers[peer_name], self.bad_g)

        if logging.getLogger().getEffectiveLevel() <= logging.INFO:
            x = (self.bad_g == self.p - 1) * "p - 1"
            y = (self.bad_g == self.p) * "p"
            logging.info("%s swaps g = %s <--> g = %s",
                         self.name, self.original_g, x or y or self.bad_g)

    def _mitm_connection(self, peer_name: str, peer_address: Address,
                         packet: ConnPacket, origin: str) -> None:
        self._add_peer(packet["name"], packet["address"], origin)  # alice
        self._add_peer(peer_name, peer_address)  # bob
        self._send_dict(packet, self._peers[peer_name])

    def mitm(self, peer_name: str,
             peer_address: Address = None) -> None:
        raw_packet = self._get_buffer()
        try:
            packet = json.loads(raw_packet.data.decode("ascii"))
            if peer_address is not None and {"name", "address"} <= set(packet):
                self._mitm_connection(peer_name, peer_address, packet,
                                      raw_packet.origin)
            if {"p", "g"} <= set(packet):
                self._mitm_parameters(peer_name, packet)
            elif "pubkey" in packet:
                sender = self._peers[raw_packet.origin]
                self._peers[sender.name] = self._peers[sender.name] \
                                           ._replace(pubkey=packet["pubkey"])
                self._send(raw_packet.data, self._peers[peer_name])
                logging.info("%s passing packet to %s@%s:%s", self.name,
                             peer_name, *self._peers[peer_name].address)
        except (UnicodeDecodeError, json.decoder.JSONDecodeError):
            self._message_buffer.append(raw_packet.data)
            self._send(raw_packet.data, self._peers[peer_name])

    def break_dh(self) -> bytes:
        if self.bad_g == 1:
            self._s = 1
            return self.decrypt()
        if self.bad_g == self.p:
            self._s = 0
            return self.decrypt()
        if self.p is None:
            raise RuntimeError
        if self.bad_g == self.p - 1:
            cyphertext = self._message_buffer.pop()
            longest_message = b""
            for self._s in [1, self.bad_g]:
                message = self.decrypt(cyphertext)
                try:
                    message.decode("ascii")
                    if len(message) > len(longest_message):
                        longest_message = message
                except UnicodeDecodeError:
                    continue
            return longest_message
        raise RuntimeError(f"g must be 1, p or p - 1, not {self.bad_g}")

def dh_protocol(p: int, g: int, message: bytes) -> bytes:
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

def dh_malicious_g(p: int, g: int, message: bytes, bad_g: int) -> bytes:
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

def main() -> None:
    with open("data/33.txt", "r") as p_file:
        p = int(p_file.read().replace("\n", ""), 16)
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

if __name__ == "__main__":
    main()
