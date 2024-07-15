import challenge1
import challenge39

import secrets
import hashlib
from Crypto.Util import number

class DSA():
    
    def gen_pqg(self, ln):
        l, n = ln
        q = number.getPrime(n)

        # Making sure p - 1 is multiple of q        
        p_min_1 = 2 ** l - 2 ** l % q + q
        while not number.isPrime(p_min_1 + 1):
            p_min_1 += q

        p = p_min_1 + 1
        
        g = 1
        h = 2
        while g == 1:
            g = pow(h, (p - 1) // q, p)
            h += 1

        return (p, q, g)

    def __init__(self, ln=(3072, 256), hash_fct=hashlib.sha1, pqg=None):
        self.hash_fct = hash_fct
        
        hash_len = len(hash_fct(b'').digest()) * 8
        n = ln[1]
        self.hash_shift = hash_len - n if hash_len >= n else 0

        if pqg == None and ln not in [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]:
            raise TypeError('Invalid L and N combination')
        elif pqg == None:
            pqg = self.gen_pqg(ln)
        
        self.p, self.q, self.g = pqg
        self.x, self.y = self.gen_key_pair()
    
    def gen_key_pair(self):
        # +1 to move up the [0,q-1[ bounds to [1, q-1]
        x = secrets.randbelow(self.q - 1) + 1
        y = pow(self.g, x, self.p)
        return x, y

    def set_key_pair(self, x, y):
        self.x = x
        self.y = y

    def get_public(self):
        return self.y
    
    def get_private(self):
        return self.x

    def gen_digest(self, m):
        h = self.hash_fct(m).digest()

        h = int.from_bytes(h, 'big')
        return h >> self.hash_shift
        
    def sign(self, m, k=None):
        r = 0
        s = 0

        h = self.gen_digest(m)
        while r == 0 or s == 0:
            # +1 to move up the [0,q-1[ bounds to [1, q-1]
            k = secrets.randbelow(self.q - 1) + 1 if not k else k
            k_inv = challenge39.invmod(k, self.q)

            r = pow(self.g, k, self.p) % self.q
            s = k_inv * (h + self.x * r) % self.q
        
        return (r, s)

    def verify(self, m, sign_rs):
        r, s = sign_rs
        if not 0 < r < self.q or not 0 < s < self.q:
            raise TypeError('Invalid r or s')

        w = challenge39.invmod(s, self.q)
        u1 = self.gen_digest(m) * w % self.q
        u2 = r * w % self.q
        v = pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p % self.q
        return v == r

def recover_priv_x(known_k, msg, sign_rs, dsa):
    r, s = sign_rs
    r_inv = challenge39.invmod(r, dsa.q)
    h = dsa.gen_digest(msg)

    return r_inv * ((s * k) - h) % dsa.q

if __name__ == '__main__':
    # Test normal behaviour
    dsa = DSA()
    msg = b'No, I am your father!'
    signature = dsa.sign(msg)
    if dsa.verify(msg, signature):
        print('Successs!!')
    else:
        print('Bad signature...')

    # Test recovering x with known k
    k = 12345
    signature = dsa.sign(msg, k=k)
    x = recover_priv_x(k, msg, signature, dsa)
    assert(x == dsa.get_private())
    print('Private key recovered!')

    # Get challenge private key
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
   
    msg = b'''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
''' # Note that final newline being required to get the proper hash
    dsa = DSA(pqg=(p,q,g))
    assert(dsa.gen_digest(msg) == 0xd2d0714f014a9784047eaeccf956520045c45265)

    signature = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)
    for k in range(2 ** 16 + 1):
        x = recover_priv_x(k, msg, signature, dsa)
        dsa.set_key_pair(x, y)
        tmp_sign = dsa.sign(msg, k=k)
        if tmp_sign == signature:
            print('Challenge private key is:', x)
            print('Signature was generated with k:', k)
            assert(hashlib.sha1(hex(x)[2:].encode()).hexdigest() == '0954edd5e0afe5542a4adf012611a91912a3ec16')
            break

