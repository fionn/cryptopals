#!/usr/bin/env python3
"""Convert hex to base64"""

import base64

def hex_to_base64(hex_str: str) -> str:
    s_bytes = bytes.fromhex(hex_str)
    return base64.b64encode(s_bytes).decode("ascii")

def main() -> None:
    with open("data/01.txt") as s:
        print(hex_to_base64(s.read().strip()))

if __name__ == "__main__":
    main()
