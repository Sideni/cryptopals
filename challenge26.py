import challenge5
import challenge11
import challenge18

from urllib import parse

def create_enc_params(s, key, nonce):
    if type(s) == str:
        s = s.encode('utf-8')

    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    pt = prefix + s + suffix
    return challenge18.aes_ctr_encrypt(pt, key, nonce)

def parse_enc_params(ct, key, nonce):
    pt = challenge18.aes_ctr_encrypt(ct, key, nonce)
    
    params = pt.split(b';')
    for param in params:
        k, v = param.split(b'=')
        if k == b'admin' and v == b'true':
            return True
    
    return False

def create_bit_flipped(ct, offset, plain_val, new_val):
    to_flip = ct[offset:offset + len(new_val)]
    flip_to_apply = challenge5.xor(plain_val, new_val)
    flipped = challenge5.xor(to_flip, flip_to_apply)
    
    return ct[:offset] + flipped + ct[offset + len(new_val):]

if __name__ == '__main__':
    key = challenge11.gen_key()
    nonce = 7654321
    wanted = ';admin=true;'
    plain = b'a' * len(wanted)

    enc_params = create_enc_params(plain, key, nonce)
    
    prefix = b'comment1=cooking%20MCs;userdata='
    flipped = create_bit_flipped(enc_params, len(prefix), plain, wanted)
    if parse_enc_params(flipped, key, nonce):
        print('Success !')

