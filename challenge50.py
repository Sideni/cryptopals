import random
import binascii

from challenge5 import xor
from challenge7 import aes_decrypt_single_block as aes_ecb_dec
from challenge10 import aes_cbc_encrypt
from challenge15 import pad_pkcs7

from Crypto.Cipher import AES
from hmac import compare_digest
from urllib.parse import quote, unquote, parse_qs

KEY = b'YELLOW SUBMARINE'

def cbc_mac(m, iv = None, gen_iv = False):
    if gen_iv:
        iv = secrets.token_bytes(AES.block_size)
    elif not iv:
        iv = b'\x00' * AES.block_size

    m = pad_pkcs7(m, AES.block_size)
    signature = aes_cbc_encrypt(m, KEY, iv)[-AES.block_size:]
   
    if gen_iv:
        return iv, signature
    else:
        return signature

def check_signature(m, s, iv = None):
    candidate = cbc_mac(m, iv)
    return compare_digest(s, candidate)

def forge_js(wanted_js, needed_hash):
    wanted_js = wanted_js + b'//'
    wanted_js = wanted_js + b' ' * (len(wanted_js) % AES.block_size)
    
    # Without padding
    wanted_js_ct = aes_cbc_encrypt(wanted_js, KEY, b'\x00' * AES.block_size)
    last_block_ct = [wanted_js_ct[i:i + AES.block_size] for i in range(0, len(wanted_js_ct), AES.block_size)][-1]

    # Calculate wanted last block (with padding and correct hash)
    plain_last = b'\x10' * AES.block_size
    last = aes_ecb_dec(KEY, needed_hash)
    
    prev_ct = xor(plain_last, last)
    prev_plain = xor(last_block_ct, aes_ecb_dec(KEY, prev_ct))
    middle_plain_block = b''

    while b'\n' in prev_plain:
        middle_ct_block = random.randbytes(AES.block_size)
        
        middle_plain_block = xor(last_block_ct, aes_ecb_dec(KEY, middle_ct_block))
        if b'\n' in middle_plain_block:
            continue

        prev_plain = xor(middle_ct_block, aes_ecb_dec(KEY, prev_ct))
    
    return wanted_js + middle_plain_block + prev_plain

if __name__ == '__main__':
    test_js = b"alert('MZA who was that?');\n"
    mac = cbc_mac(test_js)
    needed_hash = binascii.unhexlify(b'296b8d7cb78a243dda4d0a61d33bbdd1')
    assert(needed_hash == mac)
    print('CBC-MAC with YELLOW SUBMARINE works as expected!')
    
    js = forge_js(b"alert('Ayo, the Wu is back!');", needed_hash)
    print(js)
    mac = cbc_mac(js)
    assert(needed_hash == mac)
    print('Gives the same hash!')

    with open('challenge50_out.js', 'wb') as f:
        f.write(js)

