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

    # Validate padding
    if last_byte > 0 and last_byte <= blocksize and len(s) >= last_byte:
        same_last_bytes = True
        for i in range(-1, -last_byte-1, -1):
            if s[i] != last_byte:
                raise ValueError('Padding invalid.')
    else:
        raise ValueError('Padding invalid.')
    # Remove it
    return s[:-last_byte]

if __name__ == '__main__':
    valid = 'ICE ICE BABY\x04\x04\x04\x04'
    invalid1 = 'ICE ICE BABY\x05\x05\x05\x05'
    invalid2 = 'ICE ICE BABY\x01\x02\x03\x04'
    unpad_pkcs7(valid)
    try:
        unpad_pkcs7(invalid1)
    except ValueError:
        try:
            unpad_pkcs7(invalid2)
        except ValueError:
            print('Success !')

