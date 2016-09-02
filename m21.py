#!/usr/bin/env python3
# The Mersenne Twister

class MT19937:

    def __init__(self, seed):
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed & 0xffffffff
        for i in range(1, 624):
            self.mt[i] = 1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i \
                         & 0xffffffff

    def random(self):
        if self.index >= 624:
            self.twist()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= y << 7 & 0x9d2c5680  #2636928640
        y ^= y << 15 & 0xefc60000 #4022730752
        y ^= y >> 18
        self.index += 1
        return y

    def twist(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1
            if y % 2 != 0:
                self.mt[i] ^= 0x9908b0df
        self.index = 0

if __name__ == "__main__":
    x = MT19937(5489)      # Seed from mt19937ar.c
    for i in range(1000):
        print(x.random())

