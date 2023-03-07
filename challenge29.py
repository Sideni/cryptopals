import challenge1
import challenge6

import struct
import secrets

def leftrotate(n, rot, bits_size=32):
    return (n << rot) | (n >> (bits_size - rot))

def bit_not(n, numbits=32):
    return n ^ ((1 << numbits) - 1)

def sha1(msg, last_hash=None, extra_len=0):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    # This code is based on Wikipedia's pseudocode
    # (https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    if last_hash:
        h0, h1, h2, h3, h4 = [int.from_bytes(word, 'big') for word in challenge6.get_blocks(last_hash, 4)]
    
    # message length in bits (always a multiple of the number of bits in a character).
    ml = len(msg) * 8 + extra_len * 8
    
    # Pre-processing:
    # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    msg += b'\x80'
    
    # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    #   is congruent to −64 ≡ 448 (mod 512)
    
    # The initial addition with 512 is to avoid negative results
    k = ((448 + 512) // 8 - (len(msg) % (512 // 8))) % (512 // 8)
    msg += b'\x00' * k
    
    #append ml, the original message length in bits, as a 64-bit big-endian integer. 
    #   Thus, the total length is a multiple of 512 bits.
    msg += struct.pack('>Q', ml)
    
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    chunks = challenge6.get_blocks(msg, 512 // 8)
    
    # for each chunk
    for chunk in chunks:
        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        words = challenge6.get_blocks(chunk, 32 // 8)
        w = [int.from_bytes(word, 'big') for word in words]
        
        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        # for i from 16 to 79
        for i in range(16, 80):
            w.append(leftrotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1) % 2 ** 32)
        
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        # Main loop:
        # for i from 0 to 79
        for i in range(80):
            if 0 <= i and i <= 19:
                f = (b & c) ^ (bit_not(b) & d)
                k = 0x5A827999
            elif 20 <= i and i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i and i <= 59:
                f = (b & c) ^ (b & d) ^ (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i and i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = (leftrotate(a, 5) + f + e + k + w[i]) % 2 ** 32
            e = d % 2 ** 32
            d = c % 2 ** 32
            c = leftrotate(b, 30) % 2 ** 32
            b = a % 2 ** 32
            a = temp
    
        # Add this chunk's hash to result so far:
        h0 = (h0 + a) % 2 ** 32
        h1 = (h1 + b) % 2 ** 32 
        h2 = (h2 + c) % 2 ** 32
        h3 = (h3 + d) % 2 ** 32
        h4 = (h4 + e) % 2 ** 32
    
    # Produce the final hash value (big-endian) as a 160-bit number:
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh.to_bytes(160 // 8, byteorder='big')

def authenticate(msg, key):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    
    return challenge1.encode_hexstr(sha1(key + msg)) + b':' + msg

def verify_mac(msg, key):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    
    splitter = b':'
    mac = msg[:msg.find(splitter)]
    msg = msg[msg.find(splitter) + 1:]
    
    return challenge1.encode_hexstr(sha1(key + msg)) == mac

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

def glue_pad(msg_len):
    pad = b'\x80'
    # msg_len + 1 to count the \x80 byte
    k = ((448 + 512) // 8 - ((msg_len + 1) % (512 // 8))) % (512 // 8)
    pad += b'\x00' * k
    pad += struct.pack('>Q', msg_len * 8)
    return pad

def sha1_hash_length_attack(auth_params, key, suffix):
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
        new_hash = challenge1.encode_hexstr(sha1(suffix, last_hash=auth_hash, extra_len=prev_padded_msg_len))
        
        msg += suffix
        tmp_params = new_hash + b':' + msg
        if verify_mac(tmp_params, key):
            return tmp_params

if __name__ == '__main__':
    key = secrets.token_bytes(secrets.randbelow(150))
    
    auth_params = create_auth_params(b'This is user data', key)
    forged_params = sha1_hash_length_attack(auth_params, key, b';admin=true;')
    
    assert verify_mac(forged_params, key)
    assert parse_enc_params(forged_params, key)
    print('Success !')

