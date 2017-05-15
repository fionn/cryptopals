#!/usr/bin/env python3
# The Mersenne Twister

class MT19937:
    u = 11
    s, b = 7,  0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18

    def __init__(self, seed):
        self.index = 624
        self.state = [0] * 624
        self.state[0] = seed & 0xffffffff
        for i in range(1, 624):
            self.state[i] = 0x6c078965 \
                            * (self.state[i - 1] ^ self.state[i - 1] >> 30) \
                            + i & 0xffffffff

    @staticmethod
    def temper(y):
        y ^= y >> MT19937.u
        y ^= y << MT19937.s & MT19937.b  
        y ^= y << MT19937.t & MT19937.c 
        y ^= y >> MT19937.l
        return y

    def random(self):
        if self.index >= 624:
            self.__twist()
        y = self.temper(self.state[self.index])
        self.index += 1
        return y

    def __twist(self):
        for i in range(624):
            y = (self.state[i] & 0x80000000) \
                + (self.state[(i + 1) % 624] & 0x7fffffff)
            self.state[i] = self.state[(i + 397) % 624] ^ y >> 1
            if y % 2 != 0:
                self.state[i] ^= 0x9908b0df
        self.index = 0

if __name__ == "__main__":
    x = MT19937(5489)      # Seed from mt19937ar.c
    for i in range(1000):
        print(x.random())

