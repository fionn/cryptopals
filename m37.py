#!/usr/bin/env python3
"""Break SRP with a zero key"""

from hashlib import sha256

import m36

class CustomKeyClient(m36.Client):

    def gen_K(self) -> None:
        self._K = sha256(bytes(str(self.A % self.N), "ascii"))

def main() -> None:
    prime = m36.PRIME

    for coefficient in range(3):
        carol = CustomKeyClient(prime, email="not@real.email",
                                password="submarine")
        steve = m36.Server()

        carol.A = coefficient * prime

        result = m36.srp_protocol(carol, steve)
        print(f"{coefficient=}:", result)

if __name__ == "__main__":
    main()
