import challenge21

import time
import random

def crack_seed(mt, first_out, start_seed, is32bits=True):
    ceil = start_seed + 2 ** 32 if is32bits else start_seed + 2 ** 64
    for i in range(start_seed, ceil):
        seed = i % (2 ** 32) if is32bits else i % (2 ** 64)
        mt.seed_mt(seed)
        if first_out == mt.extract_number():
            return seed

if __name__ == '__main__':
    start_seed = int(time.time())
    mt = challenge21.MT19937(is64bits=False)
    
    secs = random.randint(40, 120)
    time.sleep(secs)
    
    seed = int(time.time())
    mt.seed_mt(seed)
    
    secs = random.randint(40, 120)
    time.sleep(secs)

    out = mt.extract_number()
    
    cracked = crack_seed(challenge21.MT19937(is64bits=False), out, start_seed)
    assert seed == cracked
    print('Success !')

