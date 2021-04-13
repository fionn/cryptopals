#!/usr/bin/env python3
"""Break HMAC-SHA1 with a slightly less artificial timing leak"""

from typing import Tuple

from Crypto.Random.random import getrandbits

import m31

class HMACAttack(m31.HMACAttack):

    def __init__(self, server: Tuple[str, int], repetitions: int) -> None:
        super().__init__(server)
        self.repetitions = repetitions

    def get_sha1_hmac(self, message: str) -> str:
        time_leak = 0
        for i in range(20):
            sig_gen = self._signature_generator(i, self.base)
            for sig in sig_gen:
                sig_hex = sig.hex()
                delta_zero = 0
                for _ in range(self.repetitions):
                    code, delta = self._send_forgery(message, sig_hex)
                    if code == 200:
                        return sig_hex
                    delta_zero += delta
                if delta_zero > time_leak:
                    time_leak = delta_zero
                    self.base = bytearray.fromhex(sig_hex)
                    self.print_progress(sig_hex,
                                        delta_zero / self.repetitions, i)

        raise RuntimeError("Could not determine HMAC, got {}"
                           .format(self.base.hex()))

def main() -> None:
    file_name = b"foo"
    key = bytes(getrandbits(8) for i in range(16))
    local_server = ("localhost", 9000)

    listener = m31.HMACListener(local_server, key, delay=0.005)
    hmac_attack = HMACAttack(local_server, 10)

    try:
        listener.run()

        hex_hmac = hmac_attack.get_sha1_hmac(file_name.decode())
        assert hex_hmac == m31.hmac_sha1(key, file_name).hexdigest()
        print(hex_hmac)

        listener.stop()

    except KeyboardInterrupt:
        listener.stop()

if __name__ == "__main__":
    main()
