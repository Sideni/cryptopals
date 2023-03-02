import challenge5
import challenge6
import challenge7
import challenge11

import base64
import struct

def aes_ctr_encrypt(s, key, nonce=0):
    if type(s) == str:
        s = s.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')

    blocks = challenge6.get_blocks(s)
    nonce = struct.pack('<Q', nonce)

    out = b''
    for i, block in enumerate(blocks):
        block_id = struct.pack('<Q', i)
        ct = nonce + block_id
        keystream = challenge7.aes_encrypt_single_block(key, ct)
        out += challenge5.xor(block, keystream)
    
    return out

if __name__ == '__main__':
    key = b'YELLOW SUBMARINE'
    nonce = 0
    ct = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    pt = aes_ctr_encrypt(ct, key, nonce)
    print(pt)

