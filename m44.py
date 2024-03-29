#!/usr/bin/env python3
"""DSA nonce recovery from repeated nonce"""

import json
import functools
from typing import TypedDict

import m39
import m43

PUBLIC_KEY = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
                 "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
                 "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
                 "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
                 "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
                 "2971c3de5084cce04a2e147821", 16)

Message = TypedDict("Message", {"msg": bytes, "s": int, "r": int, "m": int})

@functools.cache
def get_parameters(filename: str = "data/43.txt") -> dict[str, int]:
    with open(filename) as data_fd:
        data = json.load(data_fd)
    return {k: int(data[k], 16) for k in ["p", "q", "g"]}

@functools.cache
def get_messages(filename: str = "data/44.txt") -> list[Message]:
    with open(filename) as data_fd:
        lines = data_fd.readlines()

    messages = []
    for i in range(0, len(lines), 4):
        msg = lines[i].split("msg: ")[1].strip("\n").encode()
        s = int(lines[i + 1].split("s: ", maxsplit=1)[1])
        r = int(lines[i + 2].split("r: ", maxsplit=1)[1])
        m = int(lines[i + 3].split("m: ", maxsplit=1)[1], 16)
        element: Message = {"msg": msg, "s": s, "r": r, "m": m}
        messages.append(element)

    return messages

def group_by_repeated_k(messages: list[Message]) -> list[list[Message]]:
    """
    r = g^k mod p mod q, so we match up messages with identical r values
    which implies they were signed with the same nonce k
    """
    same_r: dict[int, list[Message]] = {}
    for message in messages:
        try:
            same_r[message["r"]].append(message)
        except KeyError:
            same_r[message["r"]] = [message]

    return list(same_r.values())

def recover_k(message_1: Message, message_2: Message, q: int) -> int:
    m_1 = message_1["m"]
    m_2 = message_2["m"]
    s_1 = message_1["s"]
    s_2 = message_2["s"]

    return m39.invmod((s_1 - s_2) % q, q) * ((m_1 - m_2) % q) % q

def main() -> None:
    y = PUBLIC_KEY

    parameters = get_parameters()
    p, q, g = parameters.values()

    messages = get_messages()

    for message in messages:
        signature = m43.DSASignature(message["r"], message["s"])
        assert m43.verify(message["msg"], signature, y, p, q, g)

    message_groups = group_by_repeated_k(messages)
    message_group = [x for x in message_groups if len(x) > 1][0]

    k = recover_k(message_group[0], message_group[1], q)
    message = message_group[0]
    m = message["msg"]
    signature = m43.DSASignature(message["r"], message["s"])
    x = m43.recover_private_key(m, signature, k, q)
    print(x)

if __name__ == "__main__":
    main()
