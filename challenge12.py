import challenge6
import challenge7
import challenge8
import challenge9
import challenge11

import base64

SECRET_KEY = challenge11.gen_key()
SECRET_MSG = base64.b64decode(b'''
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK''')

def encryption_oracle_12(s):
    if type(s) == str:
        s = s.encode('utf-8')
    
    msg = challenge9.pad_pkcs7(s + SECRET_MSG)
    return challenge7.aes_ecb_encrypt(msg, SECRET_KEY)

def find_blocksize(enc_fct):
    i = 0
    pt = 'a' * i
    ct = enc_fct(pt)
    last_len = len(ct)
    while last_len == len(ct):
        i += 1
        pt = 'a' * i
        ct = enc_fct(pt)
    
    return len(ct) - last_len

def find_mode(enc_fct, blocksize):
    # A minimum of 3 identical blocks is required to have 2 aligned identical blocks
    #0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
    #xxxxxxxxxxxxxxx0 123456789abcdef0 123456789abcdef0 123456789abcdefx
    #
    #0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
    #x0123456789abcde f0123456789abcde f0123456789abcde fxxxxxxxxxxxxxxx
    pt = b'a' * blocksize * 3
    ct = enc_fct(pt)
    if challenge8.is_probably_ecb(ct):
        return 'ecb'
    else:
        return 'cbc'

# First block with 1 byte off
# 0123456789abcdef 0123456789abcdef
# aaaaaaaaaaaaaaa0 123456789abcdef0
# Then, try all possible last byte until one match the first block with 1 byte off

# Second block
# 0123456789abcdef 0123456789abcdef 0123456789abcdef
# known_completely unknown..........................
#
# Use 1st block to bruteforce a character followed a block with 1 byte off to slide the whole message one byte off
# 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
# nown_completelyX aaaaaaaaaaaaaaak nown_completelyX unknown
def find_ecb_byte(enc_fct, known, blocksize):
    i_block_searching = len(known) // blocksize
    size_oneoff = blocksize - len(known) % blocksize - 1
    
    oneoff_block = b'a' * size_oneoff
    brute_block = known[-(blocksize - 1):]
    brute_block = b'a' * ((blocksize - 1) - len(brute_block)) + brute_block
    for i in range(256):
        pt = brute_block + bytes([i]) + oneoff_block
        ct = enc_fct(pt)
        ct_blocks = challenge6.get_blocks(ct, blocksize)
        if ct_blocks[0] == ct_blocks[i_block_searching + 1]:
            return bytes([i])


def decrypt_ecb_enc_oracle_no_prefix():
    blocksize = find_blocksize(encryption_oracle_12)
    mode = find_mode(encryption_oracle_12, blocksize)
    if mode =='ecb':
        known = b''
        new_c = find_ecb_byte(encryption_oracle_12, known, blocksize)
        while new_c:
            known += new_c
            new_c = find_ecb_byte(encryption_oracle_12, known, blocksize)
        return known

if __name__ == '__main__':
    pt = challenge9.unpad_pkcs7(decrypt_ecb_enc_oracle_no_prefix())
    assert pt == SECRET_MSG
    print('Success !')

