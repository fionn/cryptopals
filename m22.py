#!/usr/bin/env python3
# Crack an MT19937 seed

from m21 import MT19937
from random import randint
from time import time, sleep

def sleep_mersenne():
    sleep(randint(40, 1000))
    seed = int(time())
    sleep(randint(40, 1000))

    x = MT19937(seed)
    return x.random()

def crack_seed(r):
    seed = int(time())
    while MT19937(seed).random() != r and seed > 0:
        seed -=1
    return seed

if __name__ == "__main__":
    r = sleep_mersenne()
    seed = crack_seed(r)
    print(seed)

