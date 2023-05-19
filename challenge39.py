from Crypto.Util import number

def invmod(x, m):
    pass

def egcd(a, b):
    pass

class RSA():
    def __init__(self, e=3, prime_size=1024):
        self.p = number.getPrime(prime_size)
        self.q = number.getPrime(prime_size)
        self.n = self.p * self.q
        self.e = e
        self.et = (self.p - 1) * (self.q - 1)
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

if __name__ == '__main__':
    pass

