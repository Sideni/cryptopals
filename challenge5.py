import challenge1

def xor(d, k):
    if type(d) == str:
        d = d.encode('utf-8')

    if type(k) == str:
        k = k.encode('utf-8')

    return bytes([c ^ k[i % len(k)] for i, c in enumerate(d)])

if __name__ == '__main__':
    pt = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'    
    key = b'ICE'
    ct = challenge1.decode_hexstr('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    assert ct == xor(pt, key)
    print('Success !')

