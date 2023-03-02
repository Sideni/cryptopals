import challenge2
import challenge6
import challenge10
import challenge11
import challenge15

from urllib import parse
from Crypto.Cipher import AES

SECRET_KEY = challenge11.gen_key()
IV = challenge11.gen_key()

def create_enc_params(s):
    if type(s) == str:
        s = s.encode('utf-8')

    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    pt = prefix + s + suffix
    padded = challenge15.pad_pkcs7(pt)
    return challenge10.aes_cbc_encrypt(padded, SECRET_KEY, IV)

def parse_enc_params(ct):
    pt = challenge10.aes_cbc_decrypt(ct, SECRET_KEY, IV)
    pt = challenge15.unpad_pkcs7(pt)
    
    params = pt.split(b';')
    for param in params:
        k, v = param.split(b'=')
        if k == b'admin' and v == b'true':
            return True
    
    return False

def create_bit_flipped(ct, i_block_to_mod, plain_val, new_val):
    if i_block_to_mod <= 0:
        raise ValueError('Cannot apply bit flip on first block unless IV is being controlled')

    blocks = challenge6.get_blocks(ct)
    block_to_modify = blocks[i_block_to_mod]
    block_to_flip = blocks[i_block_to_mod - 1]
    
    flip_to_apply = challenge2.fixed_xor(plain_val, new_val)
    flipped = challenge2.fixed_xor(flip_to_apply, block_to_flip)
    blocks[i_block_to_mod - 1] = flipped
    
    return b''.join(blocks)

if __name__ == '__main__':
    #            0123456789abcdef0123456789abcdef
    # prefix = b'comment1=cooking%20MCs;userdata='
    # Our data is added directly at the beginning of a new block
    # The new block is at index 2 and will have all 'a'
    param = b'a' * AES.block_size
    enc_params = create_enc_params(param)
    
    #                0123456789abcdef
    wanted_param = b'a;admin=true;a=a'
    bit_flipped = create_bit_flipped(enc_params, 2, param, wanted_param)
    if parse_enc_params(bit_flipped):
        print('Success !')

