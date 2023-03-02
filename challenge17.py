import challenge5
import challenge6
import challenge10
import challenge11
import challenge15

import base64
import secrets
from Crypto.Cipher import AES

SECRET_KEY = challenge11.gen_key()

def encrypt_cbc_pad(s):
    if type(s) == str:
        s = s.encode('utf-8')
    
    iv = challenge11.gen_key()
    s = challenge15.pad_pkcs7(s, AES.block_size)
    ct = challenge10.aes_cbc_encrypt(s, SECRET_KEY, iv)
    return ct, iv

def get_encrypted_str():
    strs = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    s = base64.b64decode(secrets.choice(strs))
    return encrypt_cbc_pad(s)

def decrypt_cbc_unpad(ct, iv):
    if type(ct) == str:
        ct = ct.encode('utf-8')
    
    padded = challenge10.aes_cbc_decrypt(ct, SECRET_KEY, iv)
    try:
        pt = challenge15.unpad_pkcs7(padded, AES.block_size)
        return True
    except ValueError:
        return False

def padding_attack(dec_func, ct, iv, blocksize, print_progress=False):
    # Attacking the last block first
    rev_blocks = challenge6.get_blocks(ct)[::-1]
    
    recovered = b''
    for i in range(len(rev_blocks)):
        attacked_block = rev_blocks[i]
        prev_block = iv
        if i + 1 != len(rev_blocks):
            prev_block = rev_blocks[i + 1]
        
        prev_block_alt = b'\x00' * blocksize
        # From last char to first
        for i_char_searching in range(blocksize - 1, -1, -1):
            chr_pad = blocksize - i_char_searching
            for c in range(256):
                tmp_prev_alt = prev_block_alt[:i_char_searching] + bytes([c])

                # Last block ended by \x01, we cancel it with itself and replace it by \x02
                suffix_alt = prev_block_alt[i_char_searching + 1:]
                if len(suffix_alt) > 0:
                    suffix_alt = challenge5.xor(suffix_alt, bytes([chr_pad - 1]))
                    suffix_alt = challenge5.xor(suffix_alt, bytes([chr_pad]))
                
                tmp_prev_alt += suffix_alt
                
                # It has decrypted to valid padding aka chr_pad
                if dec_func(attacked_block, tmp_prev_alt):
                    # if it's the last byte, maybe we've got padding \x02\x02 or \x03\x03\x03 ....
                    # So, let's test by modifying the second to last byte
                    # And see if padding still works. If it still works, it'll mean
                    if i_char_searching == blocksize - 1:
                        tmp2_prev_alt = tmp_prev_alt[:i_char_searching - 1] + bytes([c]) + tmp_prev_alt[i_char_searching:]
                        if dec_func(attacked_block, tmp2_prev_alt):
                            prev_block_alt = tmp_prev_alt
                            mid_val = c ^ chr_pad
                            pt_c = mid_val ^ prev_block[i_char_searching]

                            recovered = bytes([pt_c]) + recovered
                            break
                    else:
                        prev_block_alt = tmp_prev_alt
                        mid_val = c ^ chr_pad
                        pt_c = mid_val ^ prev_block[i_char_searching]

                        recovered = bytes([pt_c]) + recovered
                        break
            if print_progress:
                print(recovered)
        
    return recovered

if __name__ == '__main__':
    ct, iv = get_encrypted_str()
    pt = padding_attack(decrypt_cbc_unpad, ct, iv, AES.block_size)
    print(pt)

