import challenge6

import base64
from Crypto.Cipher import AES

def aes_encrypt_single_block(key, block):
    if len(block) != AES.block_size:
        raise ValueError('Invalid block size.')
    
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def aes_decrypt_single_block(key, block):
    if len(block) != AES.block_size:
        raise ValueError('Invalid block size.')
    
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def aes_ecb_encrypt(pt, key):
    if len(pt) % AES.block_size != 0:
        raise ValueError('Invalid message length')

    blocks = challenge6.get_blocks(pt, AES.block_size)
    ct = b''
    for block in blocks:
        ct += aes_encrypt_single_block(key, block)
    
    return ct

def aes_ecb_decrypt(ct, key):
    blocks = challenge6.get_blocks(ct, AES.block_size)
    pt = b''
    for block in blocks:
        pt += aes_decrypt_single_block(key, block)
    
    return pt

if __name__ == '__main__':
    with open('7.txt') as f:
        ct = base64.b64decode(f.read())
    
    key = b'YELLOW SUBMARINE'
    print(aes_ecb_decrypt(ct, key))

