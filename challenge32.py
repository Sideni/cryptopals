import challenge1
import challenge5

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
        time.sleep(0.005)

    return True

def get_elapsed_mean(sess, url, n):
    elapsed = 0
    for _ in range(n):
        r = sess.get(url)
        elapsed += r.elapsed.total_seconds()
    
    return elapsed / n

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
    r = sess.get(complete_url) # The second request is faster because the session has been established
    invalid_time = get_elapsed_mean(sess, complete_url, 20)
    for i in range(sign_len):
        for c in b'0123456789abcdef':
            tmp_sign = signature[:i] + bytes([c]) + signature[i + 1:]
            complete_url = url + b'?' + params + b'&' + signature_param + b'=' + tmp_sign
            elapsed = get_elapsed_mean(sess, complete_url, 20)
            if r.status_code == 200 or invalid_time + delay < elapsed:
                signature = tmp_sign
                invalid_time = elapsed
                print(signature)
                break
    
    return signature

if __name__ == '__main__':
    signature = attack_hmac_insecure_compare(b'http://127.0.0.1:1234/read', b'file=/etc/passwd', b'signature', len('243e758323edafdf9b960b82f96691de36a5bb3c'), 0.003)
    print(signature)

