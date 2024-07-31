import challenge1
import challenge39
import challenge42

import math
import base64
from Crypto.Util import number

# https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

class PKCS1_5_OracleRSA(challenge39.RSA):
    def unpad_pkcs1_5_type2_oracle(self, data):
        if not data.startswith(b'\x00'):
            return None
            #raise TypeError('Padding invalid')
    
        block_type = data[1]
        rest = data[2:]
        end_pad_i = rest.find(b'\x00')
        if end_pad_i < 8: # padding string length must be 8 bytes or longer
            return None
            #raise TypeError('Padding invalid')

        padding = rest[:end_pad_i]
        data = rest[end_pad_i + 1:]
    
        if block_type == challenge42.BLOCK_TYPE.TYPE_2.value:
            return data
        else:
            return None
            #raise TypeError('Padding invalid')

    def encrypt_str(self, m, ret_type=str):
        m = challenge42.pad_pkcs1_5(m, self.n, block_type=challenge42.BLOCK_TYPE.TYPE_2)
        m = int(challenge1.encode_hexstr(m), 16)
        c = self.encrypt(m)
        
        if ret_type == str:
            return challenge42.int_to_bytes(c)
        else:
            return c
    
    def decrypt_str(self, c):
        if type(c) != int:
            c = int.from_bytes(c, 'big')
        m = self.decrypt(c)
        m = m.to_bytes(math.ceil(self.n.bit_length() / 8), 'big')
        
        # If None is returned, padding was invalid        
        return self.unpad_pkcs1_5_type2_oracle(m)

    def is_pkcs_conformant(self, c):
        return self.decrypt_str(c) != None

def ceiled_div(i, divisor):
    r = i // divisor
    r += 1 if i % divisor > 0 else 0
    return r

class PKCS_Oracle_Attacker():
    def __init__(self, rsa):
        # 2B = 0x020000000...00000
        # 3B = 0x030000000...00000
        self.B = 2 ** (math.ceil(rsa.n.bit_length() / 8) * 8 - 16)
        self.rsa = rsa
        self.n = rsa.n
        self.M = []
        self.s = []

    def is_valid_pkcs(self, c0, s):
        c0si = c0 * self.rsa.encrypt(s) % self.n
        return self.rsa.is_pkcs_conformant(c0si)

    def step1(self, c):
        # Step 1: Find s0 (Skipping since c is already PKCS conforming; it was padded when encrypted)
        # This would be needed to forge a signature
        if not rsa.is_pkcs_conformant(c):
            TypeError('Ciphertext with no valid PKCS padding. Step 1 was not implemented to support this.')

        M0 = ((2 * self.B, 3 * self.B - 1),)
        self.M.append(M0)
        self.s.append(1)

    def step2a_2b(self, c0, is_2a=False):
        # Step 2.b: Searches si from (s(i-1) + 1) and over
        si = self.s[-1] + 1
        if is_2a:
            # Step 2.a: Start search
            si = ceiled_div(self.n, (3 * self.B))
        
        while not self.is_valid_pkcs(c0, si):
            si += 1
        
        self.s.append(si)

    def step2c(self, c0):
        # Step 2.c: Searching with one interval left
        a, b = self.M[-1][0]
        ri = ceiled_div(2 * (b * self.s[-1] - 2 * self.B), self.n)
        
        si_found = False
        while not si_found:
            bottom_si = ceiled_div(2 * self.B + ri * self.n, b)
            top_si = ceiled_div(3 * self.B + ri * self.n, a)
            
            for new_s in range(bottom_si, top_si):
                if self.is_valid_pkcs(c0, new_s):
                    si_found = True
                    self.s.append(new_s)
                    break

            ri += 1

    def step3(self):
        # Step 3: Narrowing the set of solutions
        # Computing Mi intervals
        new_intervals = tuple()
        
        si = self.s[-1]
        for a, b in self.M[-1]: # Unpacking intervals
            bottom_r = ceiled_div((a * si - 3 * self.B + 1), self.n)
            top_r = ceiled_div((b * si - 2 * self.B), self.n)
            
            for r in range(bottom_r, top_r):
                new_a = max(a, ceiled_div(2 * self.B + r * self.n, si))
                new_b = min(b, (3 * self.B - 1 + r * self.n) // si)
                new_intervals += ((new_a, new_b),)

        self.M.append(new_intervals)

    def attack(self, c):
        c0 = c
        if type(c) == bytes:
            c0 = int.from_bytes(c, 'big')
        elif type(c) != int:
            raise TypeError('Invalid ciphertext type. Must be either bytes or int')
       
        self.step1(c0)
        self.step2a_2b(c0, is_2a=True)
        self.step3()

        while len(self.M[-1]) != 1 or self.M[-1][0][0] != self.M[-1][0][1]:
            if len(self.M[-1]) == 1:
                self.step2c(c0)
            else:
                # Step 2b because more than one interval in M(i - 1)
                self.step2a_2b(c0)
            self.step3()

        # Step 4: Computing the solution
        a = self.M[-1][0][0]
        s0_inv = challenge39.invmod(self.s[0], self.n)
        return a * s0_inv % self.n

if __name__ == '__main__':
    msg = b'This is a secret message!'

    rsa = PKCS1_5_OracleRSA(e=65537, prime_size=512)
    c = rsa.encrypt_str(msg)
    assert(msg == rsa.decrypt_str(c)) # Sanity check to validate the modified implementation
    
    attacker = PKCS_Oracle_Attacker(rsa)
    
    m = attacker.attack(c)
    m = m.to_bytes(math.ceil(rsa.n.bit_length() / 8), 'big')
    m = rsa.unpad_pkcs1_5_type2_oracle(m)
    assert(msg == m)

    print('Success !')

