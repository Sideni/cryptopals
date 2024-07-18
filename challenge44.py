import challenge1
import challenge39
import challenge43

import math
import hashlib
import itertools

class Signed_msg:
    def __init__(self, msg, r, s, hm):
        self.msg = msg
        self.r = r
        self.s = s
        self.hm = hm

def parse_msg_file(filename):
    msgs = []
    msg, r, s, m = None, None, None, None

    with open(filename, 'rb') as f:
        line = f.readline()
        while line:
            line = line.replace(b'\n', b'')

            if line.startswith(b'msg: '):
                msg = line.split(b'msg: ')[1]
            elif line.startswith(b's: '):
                s = int(line.split(b's: ')[1])
            elif line.startswith(b'r: '):
                r = int(line.split(b'r: ')[1])
            elif line.startswith(b'm: '):
                m = line.split(b'm: ')[1]
                # Because of the ordering in the file, all variables should now be freshly populated
                msgs.append(Signed_msg(msg, r, s, m))

            else:
                # Shouldn't reach that point
                break
            
            line = f.readline()

    return msgs

def find_reused_k(msgs, dsa):
    # 
    # Because s = k^-1 * (m + x * r) % q
    # 
    # With s1 - 2, we have
    # 
    # s1 - s2 = k^-1 * (m1 + x * r1) - k^-1 * (m2 + x * r2)
    #         = k^-1 * (m1 - m2 + x * r1 - x * r2)
    #         = (m1 - m2 + x * (r1 - r2)) / k
    # 
    # Because r = (g^k % p) % q, with the same k, r1 = r2
    # Therefore, we have
    # 
    # s1 - s2 = (m1 - m2 + x * (0)) / k
    #         = (m1 - m2) / k
    # 
    # Knowing that, we have
    # 
    # (m1 - m2) / (s1 - s2) = (m1 - m2) / ((m1 - m2) / k)
    #                       = (m1 - m2) * (k / (m1 - m2)) = k
    # 
    # Note that all of this is done modulo q
    #
    
    for combi in itertools.combinations(msgs, 2):
        msg1, msg2 = combi
        if msg1.r != msg2.r: # As shown above, r will be the same for the same k
            continue

        numerator = (int(msg1.hm, 16) - int(msg2.hm, 16)) % dsa.q
        denominator = (msg1.s - msg2.s) % dsa.q
        deno_inv = challenge39.invmod(denominator, dsa.q)

        potential_k = deno_inv * numerator % dsa.q
        r = pow(dsa.g, potential_k, dsa.p) % dsa.q
        if r == msg1.r:
            print('Found reused k with messages "{}" and "{}"'.format(msg1.msg, msg2.msg))
            return potential_k, msg1
        else:
            raise ValueError('A calculation issue occured. The Rs should have been the same...')

if __name__ == '__main__':
    # Parsing messages
    msgs = parse_msg_file('44.txt')
    
    # Challenge params + public key
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

    dsa = challenge43.DSA(pqg=(p,q,g))
    k, msg = find_reused_k(msgs, dsa)
    print('k is:', k)

    priv_key = challenge43.recover_priv_x(k, msg.msg, (msg.r, msg.s), dsa)
    assert(hashlib.sha1(hex(priv_key)[2:].encode()).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
    print('Recovered private key:', priv_key)

