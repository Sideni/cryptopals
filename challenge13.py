import challenge6
import challenge7
import challenge9
import challenge11

import random
from Crypto.Cipher import AES

class User:
    key = challenge11.gen_key()
    
    # profile_for function
    def __init__(self, email):
        self.email = email.replace(b'&', b'').replace(b'=', b'')
        self.uid = random.randint(10, 99)
        self.role = b'user'

    def toEncString(self):
        profile_str = b'email=%b&uid=%d&role=%b' % (self.email, self.uid, self.role)
        padded = challenge9.pad_pkcs7(profile_str)
        return challenge7.aes_ecb_encrypt(padded, self.key)

    def fromEncString(self, enc_str):
        profile_str = challenge7.aes_ecb_decrypt(enc_str, self.key)
        profile_str = challenge9.unpad_pkcs7(profile_str)
        attrs = profile_str.split(b'&')
        for attr in attrs:
            var_name, val = attr.split(b'=')
            if var_name == b'email':
                self.email = val
            elif var_name == b'uid':
                self.uid = val
            elif var_name == b'role':
                self.role = val

if __name__ == '__main__':
    # Completing the first block
    email_block = b'a' * (AES.block_size - len('email='))
    # Getting a block with correct padding to set role
    admin_block = challenge9.pad_pkcs7(b'admin')
    user1 = User(email_block + admin_block)
    admin_enc = challenge6.get_blocks(user1.toEncString())[1]
    
    # Creating email to have the role alone in the padding block
    part_enc_str = b'email=&uid=12&role='
    email_size = AES.block_size - (len(part_enc_str) % AES.block_size)
    email = b'a' * email_size
    user2 = User(email)
    
    admin_blocks = challenge6.get_blocks(user2.toEncString())[:-1]
    admin_blocks.append(admin_enc)
    admin_enc_str = b''.join(admin_blocks)
    user2.fromEncString(admin_enc_str)
    
    assert user2.role == b'admin'
    print('Success !')

