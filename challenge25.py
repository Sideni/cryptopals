import challenge5
import challenge6
import challenge7
import challenge11
import challenge18

import base64
import struct
from Crypto.Cipher import AES

def get_aes_ctr_keystream(key, ks_len=AES.block_size, nonce=0, offset=0):
    if type(key) == str:
        key = key.encode('utf-8')

    block_start = offset // AES.block_size
    block_end = ((offset + ks_len) // AES.block_size) + 1

    nonce = struct.pack('<Q', nonce)
    keystream = b''
    for i in range(block_start, block_end):
        block_id = struct.pack('<Q', i)
        ct = nonce + block_id
        keystream += challenge7.aes_encrypt_single_block(key, ct)
 
    ks_start = offset % AES.block_size
    return keystream[ks_start:ks_start + ks_len]

def edit(ct, key, nonce, offset, newtext):
    if type(newtext) == str:
        newtext = newtext.encode('utf-8')

    ks = get_aes_ctr_keystream(key, ks_len=len(newtext), nonce=nonce, offset=offset)
    edited = ct[:offset] + challenge5.xor(newtext, ks) + ct[offset + len(newtext):]
    return edited

def break_edit(ct, key, nonce):
    edition = b'A' * len(ct)
    edited = edit(ct, key, nonce, 0, edition)
    ks = challenge5.xor(edited, edition)
    pt = challenge5.xor(ct, ks)
    return pt

if __name__ == '__main__':
    ecb_key = b'YELLOW SUBMARINE'
    with open('25.txt') as f:
        ecb_ct = base64.b64decode(f.read())

    pt = challenge7.aes_ecb_decrypt(ecb_ct, ecb_key)
    key = challenge11.gen_key()
    nonce = 123456
    ct = challenge18.aes_ctr_encrypt(pt, key, nonce=nonce)

    print(break_edit(ct, key, nonce))

