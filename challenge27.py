import challenge5
import challenge6
import challenge10
import challenge11
import challenge15

def create_enc_params(s, key):
    if type(s) == str:
        s = s.encode('utf-8')

    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    pt = prefix + s + suffix
    padded = challenge15.pad_pkcs7(pt)
    return challenge10.aes_cbc_encrypt(padded, key, key)

def validate_ascii(pt):
    valid = set(b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ')
    if any((c not in valid) for c in pt):
        raise ValueError('Invalid ascii found in "{}".'.format(pt))

    return True

def parse_enc_params(ct, key):
    pt = challenge10.aes_cbc_decrypt(ct, key, key)
    pt = challenge15.unpad_pkcs7(pt)
    
    if validate_ascii(pt):
        params = pt.split(b';')
        for param in params:
            k, v = param.split(b'=')
            if k == b'admin' and v == b'true':
                return True
    
    return False

def recover_iv_key(ct, key):
    blocks = challenge6.get_blocks(ct)
    if len(blocks) < 3:
        # The last block must be valid padding to get to the ascii exception
        raise ValueError(b'At least three blocks are required...')

    # First block takes the value of the second block to avoid modifying the 3rd block (which might be padding)
    blocks[0] = blocks[1]
    modified = b''.join(blocks)
    try:
        parse_enc_params(modified, key)
    except ValueError as e:
        error = e.args[0]
        start_dec = error.find('in "') + len('in "')
        end_dec = error.find('".')
        dec = error[start_dec:end_dec]
        dec = eval(dec) # converting 'b\'somestring\'' to b'somestring'
        
        dec_blocks = challenge6.get_blocks(dec)
        dec_0 = dec_blocks[0] # decrypted block 0 xored with KEY
        dec_1 = dec_blocks[1] # decrypted block 1 xored with block 0
        
        # Because block 0 == block 1, they both decrypt to the same thing
        # They're just xored with different values
        
        # Getting decrypted block without xor with block 0
        dec_without_xor = challenge5.xor(dec_1, blocks[0])
        
        # Removing decrypted block on decrypted block 0 xored with KEY
        key = challenge5.xor(dec_0, dec_without_xor)
        return key

if __name__ == '__main__':
    key = challenge11.gen_key()
    plain_param = 'Hello there... General Kenobi'
    enc_params = create_enc_params(plain_param, key)
    
    recovered_key = recover_iv_key(enc_params, key)
    assert recovered_key == key
    
    built_params = padded = challenge15.pad_pkcs7('admin=true')
    built_enc = challenge10.aes_cbc_encrypt(built_params, recovered_key, recovered_key)
    assert parse_enc_params(built_enc, key)
    print('Success !')

