#!/usr/bin/env python3
"""Crack an MT19937 seed"""

from random import randint
from time import time, sleep

from m21 import MT19937

def sleep_mersenne() -> int:
    sleep(randint(40, 1000))
    seed = int(time())
    sleep(randint(40, 1000))

    x = MT19937(seed)
    return x.random()

def crack_seed(r: int) -> int:
    seed = int(time())
    while MT19937(seed).random() != r and seed > 0:
        seed -= 1
    return seed

def main() -> None:
    r = sleep_mersenne()
    seed = crack_seed(r)
    print(seed)

if __name__ == "__main__":
    main()
