import challenge1
import challenge6
import challenge11

import struct

def leftrotate(n, rot, bits_size=32):
    return (n << rot) | (n >> (bits_size - rot))

def bit_not(n, numbits=32):
    return n ^ ((1 << numbits) - 1)

def sha1(msg):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    # This code is based on Wikipedia's pseudocode
    # (https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    # message length in bits (always a multiple of the number of bits in a character).
    ml = len(msg) * 8
    
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

if __name__ == '__main__':
    assert challenge1.encode_hexstr(sha1(b'')) == b'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    assert challenge1.encode_hexstr(sha1(b'The quick brown fox jumps over the lazy dog')) == b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
    assert challenge1.encode_hexstr(sha1(b'iuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijewiuasdiasjdaijew')) == b'31a0e7cc585193e39a6afafc4b884d997b6c0cae'
    
    key = challenge11.gen_key()
    msg = b'This is a test message'
    auth_msg = authenticate(msg, key)
    assert verify_mac(auth_msg, key)
    assert not verify_mac(auth_msg[:-1], key)
    assert not verify_mac(authenticate(msg, b'test wrong key'), key)
    
    print('Success !')

