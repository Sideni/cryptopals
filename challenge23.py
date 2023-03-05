import secrets

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

    def set_state(self, state):
        if type(state) != list or len(state) != self.n:
            raise ValueError('Invalid state given')
        self.MT = state
        self.index = self.n

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

def untemper_out(mt, out):
    # In 32 bits
    # y1 = self.MT[self.index]
    # y2 = y1 ^ ((y1 >> self.u) & self.d)
    # y2 = lower bits of y1 xored with the 21 upper bits of y1 ANDED with 0xffffffff
    # This means that we've got y1 xored with int(y1_bits[11:], 2)
    # We already have the first 11 bits of y1 which can be used to recover the next 11
    # And do that until we've got them all
    
    # y3 = y2 ^ ((y2 >> self.s) & self.b)
    # y3 = lower bits of y2 xored with the 25 upper bits of y2 ANDED with 0x9d2c5680
    # This means that we've got y2 xored with int(y2_bits[7:-7], 2) << 7
    # The AND will turn the 7 lower bits of the 25 bits mask to zeroes
    
    # (for this block, don't forget to take into account the AND)
    # This means that y3 has y2's 7 first bits,
    # That y3_bits[7:14] are equal to y2_bits[7:14] xored with y3_bits[:7],
    # That y3 has y2's 7 last bits

    # y4 = y3 ^ ((y3 >> self.t) & self.c)
    # y4 = lower bits of y3 xored with the 17 upper bits of y3 ANDED with 0xefc60000
    # In other words, this doesn't change anything
    # The AND will cut all 17 lower bits (the 17 remaining after the bitshift)
    
    # out = y4 ^ (y4 >> self.l)
    # out = 14 lower bits of y4 xored with the 14 upper bits of y4
    
    y4 = out ^ (out >> mt.l)
    y3 = y4 ^ ((y4 >> mt.t) & mt.c)
    
    y2tmp = y3 ^ ((y3 >> mt.s) & mt.b) # first 14 bits and last 7 are correct
    y2tmp = y3 ^ ((y2tmp >> mt.s) & mt.b) # Using the first 14 bits to figure out the 7 next
    y2 = y3 ^ ((y2tmp >> mt.s) & mt.b) # Same trick to get them all

    y1tmp = y2 ^ ((y2 >> mt.u) & mt.d) # First 11 bits are correct and which recovers the next 11
    y1tmp = y2 ^ ((y1tmp >> mt.u) & mt.d) # Using the recovered bits to recover more
    y1 = y2 ^ ((y1tmp >> mt.u) & mt.d)
    return y1

def recover_state(mt, outs):
    state = []
    for out in outs:
        state.append(untemper_out(mt, out))

    return state

def test_recover(is64bits=False):
    mt = MT19937(is64bits=is64bits)
    
    seed = secrets.randbelow(2 ** 64) if is64bits else secrets.randbelow(2 ** 32)
    mt.seed_mt(seed)

    outs = []
    for _ in range(mt.n):
        outs.append(mt.extract_number())

    state = recover_state(mt, outs)
    new_mt = MT19937(is64bits=is64bits)
    new_mt.set_state(state)
    
    for _ in range(20):
        assert mt.extract_number() == new_mt.extract_number()

    print('Success 64 bits !' if is64bits else 'Success 32 bits !')
    

if __name__ == '__main__':
    test_recover()
    test_recover(True)

