import challenge1
import challenge39
import challenge42

import base64
from Crypto.Util import number
from decimal import Decimal, getcontext

class ParityOracleRSA(challenge39.RSA):

    def isDecryptedEven(self, c, priv=None):
        return self.decrypt(c) % 2 == 0

def attack_parity_oracle(rsa, ciphertext):
    getcontext().prec = 1234

    # Bounds
    lower = Decimal(0) # Float division on big numbers is necessary to avoid losing precision with int divisions
    upper = Decimal(rsa.n)
    
    while upper - lower > 1:
        ciphertext = ciphertext * pow(2, rsa.e, rsa.n)
        
        # if even twice
        # 
        # 0          ¼          ½          ¾          N
        # |     x    |          |          |          |
        #       ^ where we land
        # 
        # if even and odd
        # 
        # 0          ¼          ½          ¾          N
        # |          |     x    |          |          |
        #                  ^ where we land
        # 
        # if odd and even
        # 
        # 0          ¼          ½          ¾          N
        # |          |          |     x    |          |
        #                             ^ where we land
        # 
        # if odd twice
        # 0          ¼          ½          ¾          N
        # |          |          |          |     x    |
        #                                        ^ where we land
        # 

        new_bound = (upper + lower) / 2
        if rsa.isDecryptedEven(ciphertext):
            upper = new_bound
        else:
            lower = new_bound
        
        print(challenge42.int_to_bytes(int(upper)))
    
    return challenge42.int_to_bytes(int(upper))

if __name__ == '__main__':
    secret_msg = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
    rsa = ParityOracleRSA()
    c = rsa.encrypt_str(secret_msg)

    decrypted = attack_parity_oracle(rsa, c)

    assert(decrypted == secret_msg)
    print('Successs!!')
