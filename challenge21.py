
class MT19937():
    def __init__(self, is64bits=False):
        self.w, self.n, self.m, self.r, \
        self.a, self.u, self.d, self.s, \
        self.b, self.t, self.c, self.l, self.f = [
            32, 624, 397, 31, 0x9908b0df, 11, 0xffffffff, 7,
            0x9d2c5680, 15, 0xefc60000, 18, 1812433253
        ]
        if is64bits:
            self.w, self.n, self.m, self.r, \
            self.a, self.u, self.d, self.s, \
            self.b, self.t, self.c, self.l, self.f = [
                64, 312, 156, 31, 0xb5026f5aa96619e9, 29,
                0x5555555555555555, 17, 0x71d67fffeda60000, 37,
                0xfff7eee000000000, 43, 6364136223846793005
            ]
        
        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & (2 ** self.w - 1)

    def seed_mt(self, seed):
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = (self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i) & (2 ** self.w - 1) 

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError('The generator was never seeded')
            self.twist()

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y >> self.s) & self.b)
        y = y ^ ((y >> self.t) & self.c)
        y = y ^ (y >> self.l)
        
        self.index += 1
        return y & (2 ** self.w - 1)

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a

            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0

if __name__ == '__main__':
    mt = MT19937(is64bits=False)
    mt.seed_mt(123456)
    for _ in range(10):
        print(mt.extract_number())

    mt = MT19937(is64bits=True)
    mt.seed_mt(123456)
    for _ in range(10):
        print(mt.extract_number())

