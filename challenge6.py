import challenge1
import challenge3
import challenge5

import base64
import itertools
from Levenshtein import distance as levenshtein_distance
from Crypto.Cipher import AES

def to_bin_str(s):
    if type(s) == str:
        s = s.encode('utf-8')
    return ''.join([bin(c)[2:].zfill(8) for c in s]).encode('utf-8')

def hamming_bindist(d1, d2):
    str1 = to_bin_str(d1)
    str2 = to_bin_str(d2)
    
    i = 0
    count = 0 
    while(i < len(str1)):
        if(str1[i] != str2[i]):
            count += 1
        i += 1
    return count

def avg_hamming_bindist(strs):
    distance = 0
    nb_calculated = 0
    for strs_pair in itertools.combinations(strs, 2):
        distance += hamming_bindist(strs_pair[0], strs_pair[1])
        nb_calculated += 1
    return distance / nb_calculated

def get_norm_dist(s, keysize, nb_blocks_used):
    blocks = get_blocks(s, keysize)
    avg_dist = avg_hamming_bindist(blocks[:nb_blocks_used])
    return avg_dist / keysize

def guess_keysize(s, maxsize=40, nb_blocks_used=4):
    keysize_dists = []
    for keysize in range(2, maxsize + 1):
        norm_dist = get_norm_dist(s, keysize, nb_blocks_used)
        keysize_dists.append((keysize, norm_dist))

    keysize_dists.sort(key=lambda x:x[1])
    return keysize_dists

def get_blocks(s, n=AES.block_size):
    return [s[i:i+n] for i in range(0, len(s), n)]

def get_transposed_blocks(ct, keysize):
    ct_blocks = get_blocks(ct, keysize)
    cts_trans = [b''] * keysize

    # Each ct_block is of size keysize (or less)
    for ct_block in ct_blocks:
        for i in range(keysize):
            if len(ct_block) > i:
                cts_trans[i] += chr(ct_block[i]).encode('utf8')
    
    return cts_trans

def get_probable_key(ct, keysize):
    cts_trans = get_transposed_blocks(ct, keysize)
    key = bytearray()
    for i, ct_trans in enumerate(cts_trans):
        pt_trans = challenge3.brute_single_byte_xor_probability(ct_trans)
        if pt_trans:
            key.append(challenge5.xor(ct_trans, pt_trans)[0])
    
    return bytes(key)

if __name__ == '__main__':
    assert hamming_bindist('this is a test', 'wokka wokka!!!') == 37

    with open('6.txt') as f:
        ct = base64.b64decode(f.read())
    
    keysizes = guess_keysize(ct)[:1]
    for keysize, dist in keysizes:
        key = get_probable_key(ct, keysize)
        print(key)
        print(challenge5.xor(ct, key))
        print('-' * 88)

