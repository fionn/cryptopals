#!/usr/bin/env python3
"""CBC-MAC Message Forgery"""

from functools import reduce
from hmac import compare_digest
from typing import TypedDict

from Crypto.Random import get_random_bytes

from m02 import fixed_xor
from m09 import pkcs7
from m10 import encrypt_aes_cbc

BLOCKSIZE = 16
KEY = b"yellow submarine"

TX = TypedDict("TX", {"to": str, "amount": int})
TransactionV2 = TypedDict("TransactionV2", {"from": str, "tx_list": list[TX]})

class ClientV1:

    def __init__(self, identity: str) -> None:
        self.id = identity

    @staticmethod
    def compose_message(from_id: str, to_id: str, amount: int) -> bytes:
        return f"from={from_id}&to={to_id}&amount={amount}".encode()

    def send(self, to_id: str, amount: int) -> bytes:
        message = self.compose_message(self.id, to_id, amount)
        iv = get_random_bytes(BLOCKSIZE)
        return message + iv + cbc_mac(KEY, iv, pkcs7(message))

class ServerV1:

    @staticmethod
    def validate(payload: bytes) -> bool:
        message, iv, mac = parse_payload_v1(payload)
        return compare_digest(cbc_mac(KEY, iv, pkcs7(message)), mac)

    @staticmethod
    def _transact(message: bytes) -> dict[str, str]:
        transaction_dict = {}
        for element in message.decode().split("&"):
            k, v = element.split("=")
            transaction_dict[k] = v
        return transaction_dict

    @staticmethod
    def process(payload: bytes) -> dict[str, str]:
        if not ServerV1.validate(payload):
            raise Exception("Invalid payload")
        message, _, _ = parse_payload_v1(payload)
        return ServerV1._transact(message)

class ClientV2:

    def __init__(self, identity: str) -> None:
        self.id = identity

    def cbc_mac(self, message: bytes) -> bytes:
        """Check the from field and return the CBC-MAC if it's ok"""
        from_field = b"from=" + self.id.encode()
        assert message[:len(from_field)] == from_field, message
        return cbc_mac(KEY, bytes(16), message)

    @staticmethod
    def _compose_message(from_id: str, tx_map: dict[str, int]) -> bytes:
        txs = ";".join([f"{to}:{amount}" for to, amount in tx_map.items()])
        return f"from={from_id}&tx_list={txs}".encode()

    def _compose(self, tx_map: dict[str, int]) -> bytes:
        return self._compose_message(self.id, tx_map)

    def send(self, tx_list: dict[str, int]) -> bytes:
        """Return a payload for the server"""
        message = self._compose(tx_list)
        return message + self.cbc_mac(pkcs7(message))

class ServerV2:

    @staticmethod
    def validate(payload: bytes) -> bool:
        """Unreasonably flexible payload validation"""
        message, mac = parse_payload_v2(payload)
        if len(message) % 16 != 0:
            message = pkcs7(message)
        return compare_digest(cbc_mac(KEY, bytes(16), message), mac)

    @staticmethod
    def process(payload: bytes) -> TransactionV2:
        if not ServerV2.validate(payload):
            raise Exception("Invalid payload")
        message, _ = parse_payload_v2(payload)
        return ServerV2._transact(message)

    @staticmethod
    def _transact(message: bytes) -> TransactionV2:
        """Terrible transaction processing"""
        transaction_dict = {}
        for element in message.split(b"&"):
            k, v = element.split(b"=", maxsplit=2)
            transaction_dict[k.decode()] = v.decode(errors="ignore")

        tx_list = transaction_dict["tx_list"].split(";")

        tx_blob: list[TX] = []
        for tx in tx_list:
            try:
                to, amount = tx.split(":", maxsplit=2)
                tx_blob.append({"to": to, "amount": int(amount)})
            except ValueError:
                continue

        return {"from": transaction_dict["from"], "tx_list": tx_blob}

def cbc_mac(key: bytes, iv: bytes, message: bytes) -> bytes:
    assert len(message) % BLOCKSIZE == 0
    ciphertext = encrypt_aes_cbc(key, iv, message)
    return ciphertext[-BLOCKSIZE:]

def parse_payload_v1(payload: bytes) -> tuple[bytes, bytes, bytes]:
    message = payload[:-2 * BLOCKSIZE]
    iv = payload[-2 * BLOCKSIZE: -BLOCKSIZE]
    mac = payload[-BLOCKSIZE:]
    return message, iv, mac

def parse_payload_v2(payload: bytes) -> tuple[bytes, bytes]:
    message = payload[:-BLOCKSIZE]
    mac = payload[-BLOCKSIZE:]
    return message, mac

def forge_via_variable_iv(attacker_id: str, victim_id: str) -> bytes:
    client = ClientV1(attacker_id)
    server = ServerV1()
    amount = 1000000

    # Send 1,000,000 spacebucks from myself to myself.
    payload = client.send(to_id=attacker_id, amount=amount)
    assert server.validate(payload)

    message, iv, mac = parse_payload_v1(payload)

    # Forge a message m_prime by satisfying
    # m xor iv == m_prime xor iv_prime.

    m_prime = ClientV1.compose_message(from_id=victim_id, to_id=attacker_id,
                                       amount=amount)
    iv_prime = reduce(fixed_xor, [m_prime[:BLOCKSIZE], message[:BLOCKSIZE], iv])
    forgery = m_prime + iv_prime + mac

    assert server.validate(forgery)
    return forgery

def forge_via_length_extension(attacker_id: str, victim_id: str) -> bytes:
    victim = ClientV2(victim_id)
    server = ServerV2()

    # Intercept transaction from victim to some recipient "8".
    payload = victim.send({"8": 100})
    assert server.validate(payload)

    message, t = parse_payload_v2(payload)
    message = pkcs7(message)  # It's important to keep track of the padding.

    # CBC-MAC extension works because for some t = mac(m_1),
    # mac(m1 || m_2) = mac(t xor m_2).

    # We want to concatonate the original message with our own extension,
    # which will be a transaction to our ID for 1,000,000 spacebucks.
    # Conveniently that's the largest order of magnitude amount that we
    # can squeeze into the extension.

    # We need to keep the "from=..." field intact. It's 6 bytes long. The
    # below xor ensures that in the extension attack, the resulting message
    # will retain the original 6 bytes.
    mandatory_xor = fixed_xor(message[:6], t[:6])
    extension = mandatory_xor + b";" + attacker_id.encode() + b":1000000"

    # Extend and generate a new CBC-MAC.
    # Yeah, we call victim.cbc_mac here.
    m_prime = message + extension
    mac_prime = victim.cbc_mac(fixed_xor(t, extension))
    payload = m_prime + mac_prime

    assert server.validate(payload)
    return payload

def main() -> None:
    # We use single character IDs because we need the space in the v2 attack.
    attacker_id = "1"  # me
    victim_id = "2"

    # v1
    forgery = forge_via_variable_iv(attacker_id, victim_id)
    print(forgery)
    tx = ServerV1.process(forgery)
    assert tx["from"] == victim_id
    assert tx["to"] == attacker_id
    assert tx["amount"] == str(1000000)
    print(tx)

    # v2
    forgery = forge_via_length_extension(attacker_id, victim_id)
    print(forgery)
    txs = ServerV2.process(forgery)
    assert {"to": attacker_id, "amount": 1000000} in txs["tx_list"]
    assert txs["from"] == victim_id
    print(txs)

if __name__ == "__main__":
    main()
