import challenge7
import challenge8
import challenge9
import challenge10

import random
import secrets
from Crypto.Cipher import AES

def gen_key():
    return secrets.token_bytes(AES.block_size)

def encryption_oracle_11(s):
    if type(s) == str:
        s = s.encode('utf-8')
    
    prefix = secrets.token_bytes(random.randint(5,10))
    suffix = secrets.token_bytes(random.randint(5,10))
    msg = challenge9.pad_pkcs7(prefix + s + suffix)
    key = gen_key()
    iv = gen_key()

    fct = secrets.choice(['ecb', 'cbc'])
    if fct == 'ecb':
        return ('ecb', challenge7.aes_ecb_encrypt(msg, key))
    elif fct == 'cbc':
        return ('cbc', challenge10.aes_cbc_encrypt(msg, key, iv))

def detect_mode(enc_fct, nb_tries=30):
    # A minimum of 3 identical blocks is required to have 2 aligned identical blocks
    #0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
    #xxxxxxxxxxxxxxx0 123456789abcdef0 123456789abcdef0 123456789abcdefx
    #
    #0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
    #x0123456789abcde f0123456789abcde f0123456789abcde fxxxxxxxxxxxxxxx
    pt = b'a' * AES.block_size * 3
    for _ in range(nb_tries):
        fct, ct = enc_fct(pt)
        if challenge8.is_probably_ecb(ct):
            print('This is ECB : {}'.format(fct == 'ecb'))
        else:
            print('This is CBC : {}'.format(fct == 'cbc'))

if __name__ == '__main__':
    detect_mode(encryption_oracle_11)

