import challenge3
import challenge5
import challenge11
import challenge18

import base64

def try_chrs_at_offset(cts, known_keystream, chrs, offset=0, choose=False, show_ct_i=False, ct_index=None):
    if type(chrs) == str:
        chrs = chrs.encode('utf-8')

    if show_ct_i:
        for i, ct in enumerate(cts):
            if len(ct) >= len(known_keystream):
                print(i, challenge5.xor(known_keystream, ct))
        return b''
    
    for i, ct1 in enumerate(cts):
        enc_part = ct1[offset:offset + len(chrs)]
        if (len(enc_part) and ct_index == None) or ct_index == i:
            keystream_part = challenge5.xor(enc_part, chrs)
            enc_chrs = b''.join([ct2[offset:offset + len(chrs)] for ct2 in cts if len(ct2) > len(known_keystream)])
            dec_chrs = challenge5.xor(enc_chrs, keystream_part)
            if challenge3.probably_txt(dec_chrs) or choose:
                print('Plaintext parts :')
                print('-' * 80)
                for j, ct3 in enumerate(cts):
                    if len(ct3) > len(known_keystream):
                        plain_part = challenge5.xor(known_keystream + keystream_part, ct3)
                        print(j, plain_part)
                
                print('-' * 80)
                print('Decrypted chars :')
                print(dec_chrs)
                if 'n' == input('Does that make sense ? [Y/n]'):
                    continue
                else:
                    return keystream_part
    return b''        

def attack_ctr_freq_analysis(cts):
    trigrams = ['the','and','ing','her','hat','his','tha','ere','for','ent','ion','ter','was','you','ith','ver','all','wit','thi','tio']
    trigrams += ['The','And','Her','His','Tha','For','You','All','Wit','Thi']
    
    keystream = b''
    ks_len = len(max(cts, key=len))
    while len(keystream) != ks_len:
        if 'n' != input('Want to try trigraphs ? [Y/n]'):
            for trigram in trigrams:
                keystream += try_chrs_at_offset(cts, keystream, trigram, offset=len(keystream))
        
        if 'y' == input('Want to try your own input ? [y/N]'):
            keystream += try_chrs_at_offset(cts, keystream, b'', offset=len(keystream), show_ct_i=True)
            ct_index = int(input('On which ciphertext do we append your input ?'))
            pattern = input('Enter the input you want to try : ')
            keystream += try_chrs_at_offset(cts, keystream, pattern, offset=len(keystream), choose=True, ct_index=ct_index)

        if 'y' == input('Want to try common chars ? [y/N]'):
            for common_chr in challenge3.COMMON_CHARS:
                cur_len = len(keystream)
                keystream += try_chrs_at_offset(cts, keystream, bytes([common_chr]), offset=len(keystream))
                if cur_len != len(keystream):
                    break
        
        if 'y' == input('Want to bruteforce the possible byte ? [y/N]'):
            for i in range(256): 
                cur_len = len(keystream)
                keystream += try_chrs_at_offset(cts, keystream, bytes([i]), offset=len(keystream), choose=True)
                if cur_len != len(keystream):
                    break
    
    return keystream

if __name__ == '__main__':
    pts = [
        'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
        'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
        'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
        'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
        'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
        'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
        'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
        'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
        'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
        'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
        'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
        'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
        'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
        'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
        'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
        'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
        'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
        'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
        'U2hlIHJvZGUgdG8gaGFycmllcnM/',
        'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
        'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
        'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
        'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
        'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
        'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
        'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
        'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
        'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
        'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
        'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
        'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
        'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
        'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
        'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
        'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
    ]
    pts = [base64.b64decode(pt) for pt in pts]

    nonce = 0
    key = challenge11.gen_key()
    cts = []
    for pt in pts:
        ct = challenge18.aes_ctr_encrypt(pt, key, nonce)
        cts.append(ct)
    
    keystream = attack_ctr_freq_analysis(cts)
    print('Here is the recovered keystream :')
    print(base64.b64encode(keystream))
    print('Here are the plaintexts :')
    for ct in cts:
        pt = challenge5.xor(ct, keystream)
        print(pt)

