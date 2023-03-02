from Crypto.Cipher import AES

def pad_pkcs7(s, blocksize=AES.block_size):
    if type(s) == str:
        s = s.encode('utf-8')
    
    bytes_missing = blocksize - (len(s) % blocksize)
    s += bytes([bytes_missing for _ in range(bytes_missing)])
    return s

def unpad_pkcs7(s, blocksize=AES.block_size):
    if type(s) == str:
        s = s.encode('utf-8')
    
    last_byte = s[-1]
    return s[:-last_byte]

if __name__ == '__main__':
    pt = b'YELLOW SUBMARINE'
    padded = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    blocksize = 20
    assert pad_pkcs7(pt, blocksize) == padded
    assert unpad_pkcs7(padded, blocksize) == pt

    print('Success !')

