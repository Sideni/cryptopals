import challenge1
import challenge39

import random
import secrets
import hashlib

# From https://github.com/coruus/pyasn1-modules/tree/master
from pyasn1_modules import rfc5208
from pyasn1.codec.der import encoder, decoder

from enum import Enum
from sympy import integer_nthroot

ASN1_HASH_IDENTIFIERS = {  
    b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10': 'MD5',
    b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14': 'SHA-1',
    b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20': 'SHA-256',
    b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30': 'SHA-384',
    b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40': 'SHA-512',
}

ALPHABET = [chr(i) for i in range(1,256)]

class BLOCK_TYPE(Enum):
    TYPE_0 = 0
    TYPE_1 = 1
    TYPE_2 = 2

def pad_pkcs1_5(data, n, block_type=BLOCK_TYPE.TYPE_1):
    sign_len = n.bit_length() // 8
    padding_len = sign_len - len(data) - 3

    # Defined here: https://www.rfc-editor.org/rfc/rfc2313#section-8.1
    # And here: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
    #
    # For block type 00, the octets shall have value 00;
    # for block type 01, they shall have value FF;
    # and for block type 02, they shall be pseudorandomly generated and nonzero
    
    if block_type == BLOCK_TYPE.TYPE_0:
        pad = b'\x00' * padding_len
    elif block_type == BLOCK_TYPE.TYPE_1:
        pad = b'\xff' * padding_len
    elif block_type == BLOCK_TYPE.TYPE_2:
        pad = b''.join(secrets.choice(ALPHABET) for i in range(padding_len))
    else:
        raise TypeError('The chosen block type is not supported')

    return b'\x00' + block_type.value.to_bytes(1, 'big') + pad + b'\x00' + data

def unpad_pkcs1_5(data):
    if not data.startswith(b'\x00'):
        raise TypeError('Padding invalid')
    
    block_type = data[1]
    rest = data[2:]
    end_pad_i = rest.find(b'\x00')
    padding = rest[:end_pad_i]
    digest = rest[end_pad_i + 1:]
   
    if block_type == BLOCK_TYPE.TYPE_0.value and len(set(list(padding))) == 1 and padding[0] == 0:
        return digest  
    elif block_type == BLOCK_TYPE.TYPE_1.value and len(set(list(padding))) == 1 and padding[1] == 0xff:
        return digest
    elif block_type == BLOCK_TYPE.TYPE_2.value:
        return digest
    else:
        raise TypeError('Padding invalid')
    
def int_to_bytes(i):
    hex_i = hex(i)[2:].replace('L','')
    hex_i = hex_i if len(hex_i) % 2 == 0 else '0' + hex_i
    return challenge1.decode_hexstr(hex_i)

def hash_msg(m, alg='SHA-1'):
    alg = alg.upper()
    if alg == 'MD5':
        h = hashlib.md5(m).digest()
    elif alg == 'SHA-1':
        h = hashlib.sha1(m).digest()
    elif alg == 'SHA-256':
        h = hashlib.sha256(m).digest()
    elif alg == 'SHA-384':
        h = hashlib.sha384(m).digest()
    elif alg == 'SHA-512':
        h = hashlib.sha512(m).digest()
    else:
        raise NotImplementedError('Support for other hash functions was not implemented')
    
    return h

def sign(m, rsa, alg='SHA-1'):
    h = hash_msg(m, alg)
    asn1_encoding = next(key for key, value in ASN1_HASH_IDENTIFIERS.items() if value == alg)

    digest_info = asn1_encoding + h
    padded_digest = pad_pkcs1_5(digest_info, rsa.n)

    # The decrypt function is used, but all it does is m**d % n
    return rsa.decrypt_str(int.from_bytes(padded_digest, 'big'))
    
def verify_sign(m, s, rsa):
    # The encrypt function is used, but all it does is m**e % n
    padded_digest = rsa.encrypt_str(s).to_bytes(rsa.n.bit_length() // 8, 'big')
    
    digest = unpad_pkcs1_5(padded_digest)
    
    key, rest = decoder.decode(digest, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())
    sign_hash = key.getComponentByName('encryptedData').asOctets()
    
    alg = next(value for key, value in ASN1_HASH_IDENTIFIERS.items() if digest.startswith(key))
    h = hash_msg(m, alg)

    return h == sign_hash

def craft_sign(m, n, e, alg='SHA-1'):
    # Hal Finney's writeup
    # https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/

    # With D = int.from_bytes(b'\x00' + asn1 data + hash, 'big')
    # With SHA-1, this is 36 bytes long (288 bits)

    # Let N = 2^288 - D (and assume N is multiple of 3, can be arranged)
    # 
    # Padded digest: 0x0001ffffffffffff...ff 00_ASN1_HASH garbage
    #                   paddddddddinnnnnngg       D              
    #
    # The padded digest (with trailing garbage) can be expressed as:
    # 
    # 2^(modulus_bit_length - 8 - 7) - 2^(nb_bytes_from_last_null_to_end * 8)
    # + D * 2^(nb_bytes_of_garbage * 8) + garbage
    #
    # Because:
    # (nb_bytes_from_last_null_to_end * 8) - (nb_bytes_of_garbage * 8) == 288
    # 
    # We have:
    #
    # 2^(modulus_bit_length - 8 - 7) - N * 2^(nb_bytes_of_garbage * 8) + garbage
    #
    # With:
    # (A-B)^3 = A^3 -3(A^2)B + 3A(B^2) - B^3
    #
    # Let's say 2^(modulus_bit_length - 8 - 7) = A^3
    #
    # A = 2^((modulus_bit_length - 8 - 7) / 3)
    #
    # Note that for this exponent to be an integer, (modulus_bit_length - 8 - 7) needs to be a multiple of 3.
    # To have an integer for A, the polynomial needs to be a cube.
    # This can be arranged by including into A values from the rest of the polynomial.
    #
    # We would have something like:
    #
    # -3(A^2)B + 3A(B^2) - B^3 = -N * 2^(nb_bytes_of_garbage * 8) + garbage (minus data required to create A^3)
    #
    # Knowing A and N (this is 2^288 - D), we can solve for B and retrieve the value necessary for "garbage"
    #
    #
    # A simpler approach (because this^ is an explanation without a general solution)
    # is to add enough garbage (a bunch of null bytes) data after the hash, computing the
    # closest cube root and from this estimation, computing the cube (estimation + 1) ^ 3
    # to see that this cube has valid padding, the proper ASN1 hash and appended garbage.
    #

    h = hash_msg(m, alg)
    asn1_encoding = next(key for key, value in ASN1_HASH_IDENTIFIERS.items() if value == alg)

    digest_info = asn1_encoding + h

    i = 0
    signature = None
    while signature == None:
        i += 1
        garbage = b'\x00' * i
        complete_digest = digest_info + garbage
        
        padded_digest = pad_pkcs1_5(complete_digest, n)
        
        root, is_perfect = integer_nthroot(int.from_bytes(padded_digest, 'big'), e)
        if is_perfect:
            signature = root
        elif digest_info in int_to_bytes((root + 1) ** e):
            signature = root + 1
        
    return int_to_bytes(signature)


if __name__ == '__main__':
    rsa = challenge39.RSA(e=3, prime_size=512)
    msg = b'test'
    signature = sign(msg, rsa)

    print('Signing the message "{}"'.format(msg))
    assert(verify_sign(msg, signature, rsa))    
    print('The signature has been verified.')
    print('Therefore, the message "{}" is legit!'.format(msg))

    print('-' * 88)

    msg = b'hi mom'
    print('Crafting signature for "{}"'.format(msg))
    signature = craft_sign(msg, rsa.n, rsa.e)
    
    assert(verify_sign(msg, signature, rsa))
    print('The signature has been verified.')
    print('Therefore, the message "{}" is legit!'.format(msg))


