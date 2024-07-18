import challenge1
import challenge39
import challenge43

import secrets

class VulnDSA(challenge43.DSA):
    def sign(self, m, k=None):
        r = 0
        s = 0

        h = self.gen_digest(m)
        # Removed this validation to avoid infinite loop during vulnerability demonstration
        #while r == 0 or s == 0:
        # +1 to move up the [0,q-1[ bounds to [1, q-1]
        k = secrets.randbelow(self.q - 1) + 1 if not k else k
        k_inv = challenge39.invmod(k, self.q)

        r = pow(self.g, k, self.p) % self.q
        s = k_inv * (h + self.x * r) % self.q
        
        return (r, s)

    def verify(self, m, sign_rs):
        r, s = sign_rs
        
        # Removed this validation to make it vulnerable
        #if not 0 < r < self.q or not 0 < s < self.q:
        #    raise TypeError('Invalid r or s')

        w = challenge39.invmod(s, self.q)
        u1 = self.gen_digest(m) * w % self.q
        u2 = r * w % self.q
        v = pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p % self.q
        return v == r

def test_dsa_generator(dsa, pqg):
    msg = b'Hello, world'
    dsa = dsa(pqg=pqg)
    
    print('Testing signatures and verification with g =', pqg[2])
    print('-' * 88)
    signature = dsa.sign(msg)
    
    print('Generated signature is', signature)

    if dsa.verify(msg, signature):
        print('Signature verified!')
    else:
        print('Not verified...')
    
    if dsa.verify(b'You mean to tell me that this is always valid?', signature):
        print('Signature valid for anything!')
    else:
        print('Signature invalid with garbage data')
    
    print('-' * 88)

def craft_magic_signature(dsa, z=12345):
    # The public key is 1 because y = (p+1) ** x % p = 1
    r = pow(dsa.get_public(), z, dsa.p) % dsa.q
    
    inv_z = challenge39.invmod(z, dsa.q)
    s = inv_z * r % dsa.q

    return (r, s)

if __name__ == '__main__':
    # Set challenge params
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    
    # With g = 0
    # y and r will be 0
    # 
    # Then, during the verification, the computed value v = 0
    # Because v = ((g ** u1) * (y ** u2) % p) % q
    # and both g and y are 0
    #
    # If v = r, the signature is verified (and since both v and g are 0....)
    # 
    test_dsa_generator(VulnDSA, (p, q, 0))
    
    # With g = 1
    # y and r will be 1 (1 ** (anything) = 1)
    # 
    # Then, during the verification, the computed value v = 1
    # Same as before, but with g and y being 1
    # v = ((1 ** u1) * (1 ** u2) % p) % q = 1
    #
    # Again, v = r = 1
    # 
    test_dsa_generator(challenge43.DSA, (p, q, 1))

    msg = b'Goodbye, world'
    dsa = challenge43.DSA(pqg=(p, q, p + 1))
    signature = craft_magic_signature(dsa)
   
    # With g = p + 1
    # the generated public key (y) is always 1
    # 
    # This is because y = (p + 1) ** x % p
    # 
    # With x = 1, it's easy to see how (p + 1) % p == 1
    #
    # Let's see what happens when x is incremented
    # 
    # With x = 2 
    # 
    # (p + 1) ** 2 = (p + 1) * (p + 1) 
    #              = p ** 2 + 2p + 1
    # 
    # This polynomial minus one is a multiple of p and thus, mod p will give 1
    # 
    # With x = 3
    # 
    # (p + 1) ** 3 = (p ** 2 + 2p + 1) * (p + 1)
    #              = p ** 3 + 3p ** 2 + 3p + 1
    # 
    # Again, still a multiple of p plus one.
    # This repeats over and over and will always be equivalent to 1 mod p
    # 
    # For the same reason, r will also be 1 (not just the public key y)
    #
    # And again for the same reason, v = ((g ** u1) * (y ** u2) mod p) mod q = 1
    #                                  = ((p_polynomial_plus_one) * 1 mod p) mod q = 1
    #
    # This gives v = r = 1
    #
    print('The magic signature is', signature)
    assert(dsa.verify(msg, signature))
    print('Aaaaaaaaaannd... it works!')

