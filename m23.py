#!/usr/bin/env python3
# Clone an MT19937 RNG from its output

from m21 import MT19937

def untemper(y):
    y ^= y >> MT19937.l
    y ^= y << MT19937.t & MT19937.c
    for i in range(7):
        y ^= y << MT19937.s & MT19937.b
    for i in range(3):
        y ^= y >> MT19937.u
    return y

def clone_mt(mt):
    mt_clone = MT19937(0)
    for i in range(624):
        mt_clone.state[i] = untemper(mt.random())
    return mt_clone

if __name__ == "__main__":
    mt = MT19937(5489)
    mt_clone = clone_mt(mt)
    
    for i in range(2000):
        assert mt_clone.random() == mt.random()

    print(mt_clone)

