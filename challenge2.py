import challenge1

def fixed_xor(d1, d2):
    if len(d1) != len(d2):
        raise ValueError('Data1 does not have the same length as data2.')

    return bytes([c ^ d2[i] for i, c in enumerate(d1)])

if __name__ == '__main__':
    ct = challenge1.decode_hexstr(b'1c0111001f010100061a024b53535009181c')
    key = challenge1.decode_hexstr(b'686974207468652062756c6c277320657965')
    pt = b'746865206b696420646f6e277420706c6179'
   
    assert challenge1.encode_hexstr(fixed_xor(ct, key)) == pt

    print("Success !")

