import challenge2
import challenge6
import challenge7
import challenge9

import base64
from Crypto.Cipher import AES

def aes_cbc_encrypt(s, key, iv):
    if len(iv) != AES.block_size:
        raise ValueError('The IV does not have the right size')
    if len(s) % AES.block_size != 0:
        raise ValueError('The plaintext does not have the right size')

    pt_blocks = challenge6.get_blocks(s, AES.block_size)
    last_block = iv
    ct_blocks = []
    for i, pt_block in enumerate(pt_blocks):
        xored = challenge2.fixed_xor(last_block, pt_block)
        ct_block = challenge7.aes_encrypt_single_block(key, xored)
        ct_blocks.append(ct_block)
        last_block = ct_block
    
    return b''.join(ct_blocks)

def aes_cbc_decrypt(s, key, iv):
    if len(iv) != AES.block_size:
        raise ValueError('The IV does not have the right size')

    ct_blocks = challenge6.get_blocks(s, AES.block_size)
    previous_block = iv
    pt_blocks = []
    for i, ct_block in enumerate(ct_blocks):
        block = challenge7.aes_decrypt_single_block(key, ct_block)
        pt_block = challenge2.fixed_xor(previous_block, block)
        pt_blocks.append(pt_block)
        previous_block = ct_block
    
    return b''.join(pt_blocks)

if __name__ == '__main__':
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'
    
    pt = b'test'
    padded = challenge9.pad_pkcs7(pt)
    ct = aes_cbc_encrypt(padded, key, iv)
    dec = challenge9.unpad_pkcs7(aes_cbc_decrypt(ct, key, iv))
    assert pt == dec
    
    with open('10.txt') as f:
        ct = base64.b64decode(f.read())

    pt = aes_cbc_decrypt(ct, key, iv)
    pt = challenge9.unpad_pkcs7(pt)
    print(pt)

