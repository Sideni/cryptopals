from Crypto.Util import number
import challenge1

def invmod(a, m):
    gcd, x, y = egcd(a, m)
    if gcd == 1:
        return x % m

    raise ValueError('No modular multiplicative inverse exists')

def lcm(a, b):
    gcd, _, _ = egcd(a, b)
    num = a * b
    num = num if num >= 0 else num * -1

    return num // gcd

def carmichael_totient(p, q):
    return lcm(p - 1, q - 1)

def egcd(a, b):
    r0 = a
    r1 = b
    s0 = 1
    s1 = 0
    t0 = 0
    t1 = 1

    qi = r0 // r1
    r2 = r0 % r1
    s2 = s0 - qi * s1
    t2 = t0 - qi * t1
    while r2 != 0:
        r0 = r1
        r1 = r2
        s0 = s1
        s1 = s2
        t0 = t1
        t1 = t2

        qi = r0 // r1
        r2 = r0 % r1
        s2 = s0 - qi * s1
        t2 = t0 - qi * t1

    return r1, s1, t1

class RSA():

    def gen_coprime_prime(self, e, prime_size):
        p = e + 1
        while (p - 1) % e == 0:
            p = number.getPrime(prime_size)
        return p

    def __init__(self, e=3, prime_size=1024):
        self.p = self.gen_coprime_prime(e, prime_size)
        self.q = self.gen_coprime_prime(e, prime_size)
        self.n = self.p * self.q
        self.e = e
        self.et = carmichael_totient(self.p, self.q)
        self.d = invmod(e, self.et)
    
    def get_public(self):
        return (self.e, self.n)

    def get_private(self):
        return (self.d, self.n)
        
    def encrypt(self, m, pub=None):
        if pub:
            e, n = pub
            return pow(m, e, n)
        return pow(m, self.e, self.n)

    def decrypt(self, c, priv=None):
        if priv:
            d, n = priv
            return pow(c, d, n)
        return pow(c, self.d, self.n)
    
    def encrypt_str(self, m, pub=None):
        m = int(challenge1.encode_hexstr(m), 16)
        return self.encrypt(m, pub=pub)
    
    def decrypt_str(self, c, priv=None):
        dec = self.decrypt(c, priv=priv)
        return challenge1.decode_hexstr(hex(dec)[2:])


if __name__ == '__main__':
    rsa = RSA()
    m = 42
    c = rsa.encrypt(m)
    assert(m == rsa.decrypt(c))

    m = b'This is a secret!'
    c = rsa.encrypt_str(m)
    dec = rsa.decrypt_str(c)
    assert(m == dec)

    print('Successs!!')

