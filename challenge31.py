import challenge1
import challenge5
import challenge29

import time
import requests

def insecure_compare(s1, s2):
    if type(s1) == str:
        s1 = s1.encode('utf-8')
    if type(s2) == str:
        s2 = s2.encode('utf-8')
    
    for i, c in enumerate(s1):
        if len(s2) <= i:
            return False
        if c != s2[i]:
            return False
        time.sleep(0.05)

    return True    

def hmac(h_fct, m, key, h_blocksize=64):
    if type(m) == str:
        m = m.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')

    k_prime = key if len(key) <= h_blocksize else h_fct(key)
    if len(k_prime) < h_blocksize:
        k_prime += b'\x00' * (h_blocksize - len(k_prime))
    
    k_opad = challenge5.xor(k_prime, b'\x5c')
    k_ipad = challenge5.xor(k_prime, b'\x36')

    msg = k_opad + h_fct(k_ipad + m)
    return h_fct(msg)

def attack_hmac_insecure_compare(url, params, signature_param, sign_len, delay):
    if type(url) == str:
        url = url.encode('utf-8')
    if type(params) == str:
        params = params.encode('utf-8')
    if type(signature_param) == str:
        signature_param = signature_param.encode('utf-8')
    
    sess = requests.Session()
    signature = b'z' * sign_len
    complete_url = url + b'?' + params + b'&' + signature_param + b'=' + signature
    r = sess.get(complete_url) 
    r = sess.get(complete_url) # The second request is faster because the session has been established
    invalid_time = r.elapsed.total_seconds()
    for i in range(sign_len):
        for c in b'0123456789abcdef':
            tmp_sign = signature[:i] + bytes([c]) + signature[i + 1:]
            complete_url = url + b'?' + params + b'&' + signature_param + b'=' + tmp_sign
            r = sess.get(complete_url)
            elapsed = r.elapsed.total_seconds()
            if r.status_code == 200 or invalid_time + delay < elapsed:
                signature = tmp_sign
                invalid_time = elapsed
                print(signature)
                break
    
    return signature

if __name__ == '__main__':
    h = hmac(challenge29.sha1, 'this is a test', '1234')
    assert challenge1.encode_hexstr(h) == b'3564f42fd7e0535e2311725641ca02ecc59d9a00'

    signature = attack_hmac_insecure_compare(b'http://127.0.0.1:1234/read', b'file=/etc/passwd', b'signature', len('243e758323edafdf9b960b82f96691de36a5bb3c'), 0.03)
    print(signature)

