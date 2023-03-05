import challenge5
import challenge11
import challenge18

import json
import base64

with open('chr_freq.json') as f:
    CHR_FREQ = json.loads(f.read())


def get_common_chr_freq(s):
    freq = {}
    s = s.upper()
    for c in CHR_FREQ.keys():
        freq[c] = s.count(c.encode('utf-8')) / len(s)
    return freq

def chi2_freq(s):
    if type(s) == str:
        s = s.encode('utf-8')

    chi2 = 0
    s_chr_freq = get_common_chr_freq(s)
    for k, v in s_chr_freq.items():
        observed = v
        expected = CHR_FREQ[k]
        chi2 += ((observed - expected) ** 2) / expected

    return chi2

def brute_single_byte_xor_chi2(ct):
    chi2 = None
    pt = b''
    for i in range(256):
        pt_tmp = challenge5.xor(ct, bytes([i]))
        chi2_tmp = chi2_freq(pt_tmp)
        if chi2 == None or chi2 > chi2_tmp:
            chi2 = chi2_tmp
            pt = pt_tmp
    return pt

def get_transposed_cts(cts, ks_len):
    transposed = [b''] * ks_len
    for i in range(ks_len):
        for ct in cts:
            transposed[i] += bytes([ct[i]])
    
    return transposed

def attack_ctr_stat(cts):
    ks_len = len(min(cts, key=len))

    cts_trans = get_transposed_cts(cts, ks_len)
    keystream = bytearray()
    for i, ct_trans in enumerate(cts_trans):
        pt_trans = brute_single_byte_xor_chi2(ct_trans)
        if pt_trans:
            keystream.append(challenge5.xor(pt_trans, ct_trans)[0])
    
    return bytes(keystream)

if __name__ == '__main__':
    key = challenge11.gen_key()
    nonce = 0
    
    with open('20.txt') as f:
        pts = [base64.b64decode(line.strip()) for line in f]
    cts = [challenge18.aes_ctr_encrypt(pt, key, nonce) for pt in pts]
    
    keystream = attack_ctr_stat(cts)
    for ct in cts:
        pt = challenge5.xor(keystream, ct)
        print(pt)

