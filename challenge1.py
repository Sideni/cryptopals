import base64
import binascii

def decode_hexstr(s):
    if type(s) == str:
        s = s.encode('utf-8')
    return binascii.unhexlify(s)

def encode_hexstr(s):
    if type(s) == str:
        s = s.encode('utf-8')
    return binascii.hexlify(s)
    
if __name__ == '__main__':
    hex_str = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    out_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    assert hex_str == encode_hexstr(decode_hexstr('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

    data = decode_hexstr(hex_str)    

    assert out_str == base64.b64encode(data)

    print('Success !')

