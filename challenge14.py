import challenge6
import challenge7
import challenge9
import challenge11
import challenge12

import base64
import random
import secrets
import itertools

SECRET_KEY = challenge11.gen_key()
SECRET_MSG = b'This is a secret message known only by the creator of this code'
SECRET_PREFIX = secrets.token_bytes(secrets.randbelow(100))

def encryption_oracle_14(s):
    if type(s) == str:
        s = s.encode('utf-8')
    
    msg = challenge9.pad_pkcs7(SECRET_PREFIX + s + SECRET_MSG)
    return challenge7.aes_ecb_encrypt(msg, SECRET_KEY)

# Returns the number of chars required to make the last block all padding
def find_blocksize_and_chars_required(enc_fct):
    i = 0
    pt = 'a' * i
    ct = enc_fct(pt)
    last_len = len(ct)
    while last_len == len(ct):
        i += 1
        pt = 'a' * i
        ct = enc_fct(pt)
    
    blocksize = len(ct) - last_len
    return (blocksize, (i - 1) % blocksize)

def find_repetition(s, blocksize):
    blocks = challenge6.get_blocks(s, blocksize)
    for i, j in itertools.combinations(range(len(blocks)), 2):
        if blocks[i] == blocks[j]:
            return i, j
    return None, None

def find_mode_and_repetition_loc(enc_fct, blocksize):
    pt = b'a' * blocksize * 3
    ct = enc_fct(pt)
    first_block, second_block = find_repetition(ct, blocksize)
    if first_block != None:
        return 'ecb', first_block
    else:
        return 'cbc', None

def find_ecb_byte_from_pos(enc_fct, known, blocksize, nb_required, first_block_loc):
    i_block_searching = (len(known) // blocksize) + first_block_loc
    size_oneoff = blocksize - len(known) % blocksize - 1
    
    prefix_pad = b'a' * nb_required
    oneoff_block = b'a' * size_oneoff
    brute_block = known[-(blocksize - 1):]
    brute_block = b'a' * ((blocksize - 1) - len(brute_block)) + brute_block
    for i in range(256):
        pt = prefix_pad + brute_block + bytes([i]) + oneoff_block
        ct = enc_fct(pt)
        ct_blocks = challenge6.get_blocks(ct, blocksize)
        if ct_blocks[first_block_loc] == ct_blocks[i_block_searching + 1]:
            return bytes([i])

def decrypt_ecb_enc_oracle():
    blocksize, nb_required = find_blocksize_and_chars_required(encryption_oracle_14)
    mode, complete_block_loc = find_mode_and_repetition_loc(encryption_oracle_14, blocksize)
    if mode == 'ecb':
        known = b''
        new_c = find_ecb_byte_from_pos(encryption_oracle_14, known, blocksize, nb_required, complete_block_loc)
        while new_c:
            known += new_c
            new_c = find_ecb_byte_from_pos(encryption_oracle_14, known, blocksize, nb_required, complete_block_loc)
        return known

if __name__ == '__main__':
    print(decrypt_ecb_enc_oracle())

