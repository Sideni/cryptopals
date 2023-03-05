import challenge5
import challenge23

import time
import secrets

def get_mt_keystream(key, ks_len, key_size=16):
    if type(key) == str:
        key = key.encode('utf-8')
    if type(key) == bytes:
        key = int.from_bytes(key, 'big')
    
    # Making sure the seed is max 16 bits (or the size given as parameter)
    key &= (2 ** key_size) - 1
    
    mt = challenge23.MT19937()
    mt.seed_mt(key)
    ks = bytearray()
    while len(ks) < ks_len:
        n = mt.extract_number()
        n_bytes = n.to_bytes(4, 'big')[::-1]
        for c in n_bytes:
            ks.append(c)
    
    return bytes(ks)[:ks_len]

def encrypt(s, key, key_size=16):
    ks = get_mt_keystream(key, len(s), key_size=key_size)
    return challenge5.xor(s, ks)

def gen_prefixed_ct(pt):
    if type(pt) == str:
        pt = pt.encode('utf-8')

    len_prefix = secrets.randbelow(64)
    prefix = secrets.token_bytes(len_prefix)
    prefixed = prefix + pt
    
    key = secrets.randbits(16)
    return encrypt(pt, key), key

def recover_seed(ct, known_suffix, seed_start=0, seed_end=0x10000, key_size=16):
    suf_len = len(known_suffix)
    keystream_end = challenge5.xor(ct[-suf_len:], known_suffix)
    
    for seed in range(seed_start, seed_end):
        ks_tmp = get_mt_keystream(seed, len(ct), key_size=key_size)
        if ks_tmp.endswith(keystream_end):
            return seed

def gen_passwd_reset():
    seed = int(time.time())
    plain = b'password reset token'
    return encrypt(plain, seed, key_size=32)

def is_valid_passwd_token(token, seconds_diff=3600):
    now = int(time.time())
    then = now - seconds_diff
    seed = recover_seed(token, b'password reset token', seed_start=then, seed_end=now, key_size=32)
    return seed != None, seed

if __name__ == '__main__':
    s = secrets.token_bytes(128)
    key = 'Wo'
    c = encrypt(s, key)
    
    assert s == encrypt(c, key)

    pt = b'A' * 14
    ct, seed =  gen_prefixed_ct(pt)   
    recovered_seed = recover_seed(ct, pt)
    assert seed == recovered_seed

    tokens = []
    for _ in range(10):
        if secrets.choice([True, False]):
            token = gen_passwd_reset()
            tokens.append((token, True))
        else:
            token = challenge5.xor(b'password reset token', secrets.token_bytes(20))
            tokens.append((token, False))
    
    for token, isValid in tokens:
        valid, seed = is_valid_passwd_token(token)
        assert valid == isValid

    print('Success !')

