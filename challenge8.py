import challenge1
import challenge6

import itertools
from Crypto.Cipher import AES

def is_probably_ecb(s):
    blocks = challenge6.get_blocks(s, AES.block_size)
    for pair in itertools.combinations(blocks, 2):
        if pair[0] == pair[1]:
            return True

    return False

if __name__ == '__main__':
    with open('8.txt') as f:
        cts = [challenge1.decode_hexstr(line.strip()) for line in f]        
    
    for i, ct in enumerate(cts):
        if is_probably_ecb(ct):
            print('Cipher at line {} seems to be ECB encrypted'.format(i))
            blocks = challenge6.get_blocks(ct, AES.block_size)
            for block in blocks:
                print(challenge1.encode_hexstr(block))
