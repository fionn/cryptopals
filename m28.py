#!/usr/bin/env python3
"""Implement a SHA-1 keyed MAC"""

import abc
from copy import copy
from typing import Union, Literal
from collections.abc import Iterator

Register = Union[tuple[int, ...], tuple[int, int, int, int, int]]

def merkle_pad(data: bytes, blocksize: int,
               byteorder: Literal["little", "big"],
               width: int = 8) -> bytes:
    bit_length = 8 * len(data)
    data += b"\x80"
    data += bytes((-width - len(data) % blocksize) % blocksize)
    return data + bit_length.to_bytes(width, byteorder)

class HashBase:

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        """The internal block size of the hash algorithm in bytes"""

    @property
    @abc.abstractmethod
    def digest_size(self) -> int:
        """The size of the digest"""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The canonical, lowercase name of the hashing algorithm"""

    @abc.abstractmethod
    def __init__(self, data: bytes) -> None:
        """init"""

    @abc.abstractmethod
    def copy(self) -> "HashBase":
        """A separate copy of this hashing object"""

    @abc.abstractmethod
    def digest(self) -> bytes:
        """Hash value as bytes"""

    @abc.abstractmethod
    def hexdigest(self) -> str:
        """Hash value as a hexadecimal string"""

    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        """Hash the input into the current state"""

class SHA1(HashBase):
    block_size = 64
    digest_size = 20
    name = "sha1"

    def __init__(self, data: bytes = b"") -> None:
        self.h: Register = (0x67452301, 0xefcdab89,
                            0x98badcfe, 0x10325476, 0xc3d2e1f0)
        self._current_register: Register = self.h
        self.data = b""
        self.update(data)

    @staticmethod
    def _leftrotate(b: int, n: int = 1) -> int:
        return (b << n | b >> 32 - n) & 0xffffffff

    def update(self, data: bytes) -> None:
        self._current_register = self.h
        self.data += data
        for chunk in self._chunks():
            self._update_register(chunk)

    def copy(self) -> "SHA1":
        return copy(self)

    @staticmethod
    def pad_message(data: bytes) -> bytes:
        data = merkle_pad(data, SHA1.block_size, "big")
        assert len(data) % SHA1.block_size == 0
        return data

    def _chunks(self) -> Iterator[bytes]:
        data = self.pad_message(self.data)
        for i in range(0, len(data), self.block_size):
            yield data[i:i + self.block_size]

    def _update_register(self, chunk: bytes) -> list[int]:
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(chunk[4 * j:4 * (j + 1)], "big")

        for j in range(16, 80):
            w[j] = self._leftrotate(w[j - 3] ^ w[j - 8]
                                    ^ w[j - 14] ^ w[j - 16], 1)

        h = list(self._current_register)
        a, b, c, d, e = h

        for j in range(80):
            if j in range(20):
                f = d ^ (b & (c ^ d))
                k = 0x5a827999
            elif j in range(20, 40):
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif j in range(40, 60):
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            else:
                f = b ^ c ^ d
                k = 0xca62c1d6

            a, b, c, d, e = (self._leftrotate(a, 5) + f + e + k + w[j]
                             & 0xffffffff,
                             a, self._leftrotate(b, 30), c, d)

        h[0] = h[0] + a & 0xffffffff
        h[1] = h[1] + b & 0xffffffff
        h[2] = h[2] + c & 0xffffffff
        h[3] = h[3] + d & 0xffffffff
        h[4] = h[4] + e & 0xffffffff

        self._current_register = tuple(h)
        return h

    def hexdigest(self) -> str:
        h = list(map(lambda x: x.to_bytes(4, "big"), self._current_register))
        return "".join(x.hex() for x in h)

    def digest(self) -> bytes:
        h = list(map(lambda x: x.to_bytes(4, "big"), self._current_register))
        return b"".join(h)

def sha1_mac(message: bytes, key: bytes) -> SHA1:
    return SHA1(key + message)

def main() -> None:
    message = b"Remember when we were young?"
    key = b"ANY COLOUR SUBMARINE"

    h = sha1_mac(message, key)
    print(h.hexdigest())

if __name__ == "__main__":
    main()
