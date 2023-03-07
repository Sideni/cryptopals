import challenge1
import challenge6

import struct
import secrets

def md4(msg, last_hash=None, extra_len=0):
    if type(msg) == str:
        msg = msg.encode('utf-8')

    # This code is based on the following pseudocode
    # (http://practicalcryptography.com/hashes/md4-hash/)
    # It can also be found in RFC1320 (https://www.ietf.org/rfc/rfc1320.txt)

    def leftrotate(n, rot, bits_size=32):
        return ((n << rot) | (n >> (bits_size - rot))) % 2 ** bits_size

    def bit_not(n, numbits=32):
        return n ^ ((1 << numbits) - 1)

    def f(x, y, z):
        return (x & y) | (bit_not(x) & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    msg += glue_pad(len(msg), extra_len=extra_len)
    
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    if last_hash:
        A, B, C, D = list(struct.unpack('<4I', last_hash))
    
    blocks = challenge6.get_blocks(msg, 512 // 8)
    
    #/* Process each 16-word block. */
    # In other words, 16 * 32bits = 512 bits blocks
    for block in blocks:
        
        #/* Copy block i into X. */
        #For j = 0 to 15 do
        X = list(struct.unpack('<16I', block))
        
        #/* Save A as AA, B as BB, C as CC, and D as DD. */
        AA = A
        BB = B
        CC = C
        DD = D
        
        #/* Round 1. */
        #/* Let [abcd k s] denote the operation:
        #         a = (a + F(b,c,d) + X[k]) <<< s. */
        #/* Do the following 16 operations. */
        #[ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
        #[ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
        #[ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
        #[ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
        
        
        A = leftrotate((A + f(B, C, D) + X[0]) % 2 ** 32, 3)
        D = leftrotate((D + f(A, B, C) + X[1]) % 2 ** 32, 7)
        C = leftrotate((C + f(D, A, B) + X[2]) % 2 ** 32, 11)
        B = leftrotate((B + f(C, D, A) + X[3]) % 2 ** 32, 19)
        
        A = leftrotate((A + f(B, C, D) + X[4]) % 2 ** 32, 3)
        D = leftrotate((D + f(A, B, C) + X[5]) % 2 ** 32, 7)
        C = leftrotate((C + f(D, A, B) + X[6]) % 2 ** 32, 11)
        B = leftrotate((B + f(C, D, A) + X[7]) % 2 ** 32, 19)

        A = leftrotate((A + f(B, C, D) + X[8]) % 2 ** 32, 3)
        D = leftrotate((D + f(A, B, C) + X[9]) % 2 ** 32, 7)
        C = leftrotate((C + f(D, A, B) + X[10]) % 2 ** 32, 11)
        B = leftrotate((B + f(C, D, A) + X[11]) % 2 ** 32, 19)

        A = leftrotate((A + f(B, C, D) + X[12]) % 2 ** 32, 3)
        D = leftrotate((D + f(A, B, C) + X[13]) % 2 ** 32, 7)
        C = leftrotate((C + f(D, A, B) + X[14]) % 2 ** 32, 11)
        B = leftrotate((B + f(C, D, A) + X[15]) % 2 ** 32, 19)

        #/* Round 2. */
        #/* Let [abcd k s] denote the operation:
        #         a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
        #/* Do the following 16 operations. */
        #[ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
        #[ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
        #[ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
        #[ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]
        
        A = leftrotate((A + g(B, C, D) + X[0] + 0x5a827999) % 2 ** 32, 3)
        D = leftrotate((D + g(A, B, C) + X[4] + 0x5a827999) % 2 ** 32, 5)
        C = leftrotate((C + g(D, A, B) + X[8] + 0x5a827999) % 2 ** 32, 9)
        B = leftrotate((B + g(C, D, A) + X[12] + 0x5a827999) % 2 ** 32, 13)
        
        A = leftrotate((A + g(B, C, D) + X[1] + 0x5a827999) % 2 ** 32, 3)
        D = leftrotate((D + g(A, B, C) + X[5] + 0x5a827999) % 2 ** 32, 5)
        C = leftrotate((C + g(D, A, B) + X[9] + 0x5a827999) % 2 ** 32, 9)
        B = leftrotate((B + g(C, D, A) + X[13] + 0x5a827999) % 2 ** 32, 13)

        A = leftrotate((A + g(B, C, D) + X[2] + 0x5a827999) % 2 ** 32, 3)
        D = leftrotate((D + g(A, B, C) + X[6] + 0x5a827999) % 2 ** 32, 5)
        C = leftrotate((C + g(D, A, B) + X[10] + 0x5a827999) % 2 ** 32, 9)
        B = leftrotate((B + g(C, D, A) + X[14] + 0x5a827999) % 2 ** 32, 13)

        A = leftrotate((A + g(B, C, D) + X[3] + 0x5a827999) % 2 ** 32, 3)
        D = leftrotate((D + g(A, B, C) + X[7] + 0x5a827999) % 2 ** 32, 5)
        C = leftrotate((C + g(D, A, B) + X[11] + 0x5a827999) % 2 ** 32, 9)
        B = leftrotate((B + g(C, D, A) + X[15] + 0x5a827999) % 2 ** 32, 13)

        #/* Round 3. */
        #/* Let [abcd k s] denote the operation:
        #         a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
        #/* Do the following 16 operations. */
        #[ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
        #[ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
        #[ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
        #[ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]
        
        A = leftrotate((A + h(B, C, D) + X[0] + 0x6ED9EBA1) % 2 ** 32, 3)
        D = leftrotate((D + h(A, B, C) + X[8] + 0x6ED9EBA1) % 2 ** 32, 9)
        C = leftrotate((C + h(D, A, B) + X[4] + 0x6ED9EBA1) % 2 ** 32, 11)
        B = leftrotate((B + h(C, D, A) + X[12] + 0x6ED9EBA1) % 2 ** 32, 15)
        
        A = leftrotate((A + h(B, C, D) + X[2] + 0x6ED9EBA1) % 2 ** 32, 3)
        D = leftrotate((D + h(A, B, C) + X[10] + 0x6ED9EBA1) % 2 ** 32, 9)
        C = leftrotate((C + h(D, A, B) + X[6] + 0x6ED9EBA1) % 2 ** 32, 11)
        B = leftrotate((B + h(C, D, A) + X[14] + 0x6ED9EBA1) % 2 ** 32, 15)

        A = leftrotate((A + h(B, C, D) + X[1] + 0x6ED9EBA1) % 2 ** 32, 3)
        D = leftrotate((D + h(A, B, C) + X[9] + 0x6ED9EBA1) % 2 ** 32, 9)
        C = leftrotate((C + h(D, A, B) + X[5] + 0x6ED9EBA1) % 2 ** 32, 11)
        B = leftrotate((B + h(C, D, A) + X[13] + 0x6ED9EBA1) % 2 ** 32, 15)

        A = leftrotate((A + h(B, C, D) + X[3] + 0x6ED9EBA1) % 2 ** 32, 3)
        D = leftrotate((D + h(A, B, C) + X[11] + 0x6ED9EBA1) % 2 ** 32, 9)
        C = leftrotate((C + h(D, A, B) + X[7] + 0x6ED9EBA1) % 2 ** 32, 11)
        B = leftrotate((B + h(C, D, A) + X[15] + 0x6ED9EBA1) % 2 ** 32, 15)
    
        #/* Then perform the following additions. (That is, increment each
        #   of the four registers by the value it had before this block
        #   was started.) */
        A = (A + AA) % 2 ** 32
        B = (B + BB) % 2 ** 32
        C = (C + CC) % 2 ** 32
        D = (D + DD) % 2 ** 32
    
    h = struct.pack('<I', A)
    h += struct.pack('<I', B)
    h += struct.pack('<I', C)
    h += struct.pack('<I', D)
    return h

def glue_pad(msg_len, extra_len=0):
    pad = b'\x80'
    # msg_len + 1 to count the \x80 byte
    k = ((448 + 512) // 8 - ((msg_len + 1) % (512 // 8))) % (512 // 8)
    pad += b'\x00' * k
    pad += struct.pack('<Q', msg_len * 8 + extra_len * 8)
    return pad

def authenticate(msg, key):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    
    return challenge1.encode_hexstr(md4(key + msg)) + b':' + msg

def verify_mac(msg, key):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    
    splitter = b':'
    mac = msg[:msg.find(splitter)]
    msg = msg[msg.find(splitter) + 1:]
    
    return challenge1.encode_hexstr(md4(key + msg)) == mac

def create_auth_params(s, key):
    if type(s) == str:
        s = s.encode('utf-8')

    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    pt = prefix + s + suffix
    return authenticate(pt, key)

def parse_enc_params(auth_params, key):
    if verify_mac(auth_params, key):
        auth_params = auth_params[auth_params.find(b':') + 1:]
        params = auth_params.split(b';')
        for param in params:
            k, v = param.split(b'=')
            if k == b'admin' and v == b'true':
                return True
    
    return False

def md4_hash_length_attack(auth_params, key, suffix):
    if type(auth_params) == str:
        auth_params = auth_params.encode('utf-8')
    if type(suffix) == str:
        suffix = suffix.encode('utf-8')

    index = auth_params.find(b':')
    auth_hash = challenge1.decode_hexstr(auth_params[:index])
    params = auth_params[index + 1:]
    
    for nb_bytes_key in range(2 ** 32):
        prev_msg_len = nb_bytes_key + len(params)
        msg = params + glue_pad(prev_msg_len)
        
        prev_padded_msg_len = nb_bytes_key + len(msg)
        new_hash = challenge1.encode_hexstr(md4(suffix, last_hash=auth_hash, extra_len=prev_padded_msg_len))
        
        msg += suffix
        tmp_params = new_hash + b':' + msg
        if verify_mac(tmp_params, key):
            return tmp_params

if __name__ == '__main__':
    assert challenge1.encode_hexstr(md4(b'')) == b'31d6cfe0d16ae931b73c59d7e0c089c0'
    assert challenge1.encode_hexstr(md4(b'a')) == b'bde52cb31de33e46245e05fbdbd6fb24'
    assert challenge1.encode_hexstr(md4(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')) == b'043f8582f241db351ce627e153e7f0e4'

    key = secrets.token_bytes(secrets.randbelow(150))
    auth_params = create_auth_params(b'This is user data', key)
    forged_params = md4_hash_length_attack(auth_params, key, b';admin=true;')

    assert verify_mac(forged_params, key)
    assert parse_enc_params(forged_params, key)

    print('Success !')

