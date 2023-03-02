import challenge1
import challenge2
import string
from Levenshtein import distance as levenshtein_distance

ETAOIN = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
ETAOIN_FB = b' ETAOINSHRDLCUMWFGYPBVKJXQZ'
COMMON_CHARS = (' !,.?\'\n-' + string.ascii_letters + string.digits).encode('utf-8')
DISALLOWED_CHARS = bytes([i for i in range(9)]) + b'\x0b\x0c' + bytes([i for i in range(14, 31)]) + bytes([i for i in range(127, 256)]) + b'+&'

def hamming_str_dist(str1, str2):
    i = 0
    count = 0
 
    while(i < len(str1)):
        if(str1[i] != str2[i]):
            count += 1
        i += 1
    return count

def get_etaoin_fmt(s):
    if type(s) == str:
        s = s.encode('utf-8')

    d = {}
    for c in s:
        d[c] = d.get(c, 0) + 1
    
    c_counts = list(d.items())
    c_counts.sort(key=lambda x:x[1], reverse=True)
    
    result = ''
    for c, _ in c_counts:
        if chr(c).upper() in ETAOIN:
            result += chr(c).upper()
    
    # To compare etaoin to an etaoin formatted string with the hamming distance, both must be the same length
    result += '\xff' * (len(ETAOIN) - len(result))
    return result

def get_etaoin_fullbytes_fmt(s):
    if type(s) == str:
        s = s.encode('utf-8')

    d = {}
    for c in s:
        d[c] = d.get(c, 0) + 1
    
    c_counts = list(d.items())
    c_counts.sort(key=lambda x:x[1], reverse=True)
    
    result = bytearray()
    for c, _ in c_counts:
        result.append(c)
    
    return bytes(result).upper()

def closest_etaoin(strs):
    dist = 99999999999999
    closest = ''
    for s in strs:
        s_etaoin = get_etaoin_fmt(s)
        tmp_dist = hamming_str_dist(s_etaoin, ETAOIN)
        if tmp_dist < dist:
            dist = tmp_dist
            closest = s
    
    return (dist, closest)

def closest_etaoin_fullbytes(strs):
    dist = 99999999999999
    closest = ''
    for s in strs:
        s_etaoin = get_etaoin_fullbytes_fmt(s)
        tmp_dist = levenshtein_distance(s_etaoin.upper(), ETAOIN_FB)
        if tmp_dist < dist:
            dist = tmp_dist
            closest = s
    
    return (dist, closest)

def single_byte_xor(s, i):
    key = bytes([i for _ in range(len(s))])
    return challenge2.fixed_xor(s, key)

def brute_single_byte_xor(s):
    pts = []
    for i in range(256):
        pts.append(single_byte_xor(s, i))

    _, pt = closest_etaoin(pts)
    return pt

def brute_single_byte_xor_fullbytes(s):
    pts = []
    for i in range(256):
        pts.append(single_byte_xor(s, i))

    _, pt = closest_etaoin_fullbytes(pts)
    return pt

def common_char_ratio(s):
    if len(s) == 0:
        return 0
    nb_common = sum([1 for c in s if c in COMMON_CHARS])
    # A higher "punition" if not printable
    nb_common -= sum([10 for c in s if c in DISALLOWED_CHARS])
    return nb_common / len(s)

def probably_txt(s, accepted_ratio=0.95):
    r = common_char_ratio(s)
    return r > accepted_ratio

def brute_single_byte_xor_probability(s, accepted_ratio=0.95):
    for i in range(256):
        pt = single_byte_xor(s, i)
        if probably_txt(pt, accepted_ratio=accepted_ratio):
            return pt

if __name__ == '__main__':
    
    ct = challenge1.decode_hexstr(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    print(brute_single_byte_xor(ct))
    print(brute_single_byte_xor_fullbytes(ct))
    # This final version seems better than playing with distances
    print(brute_single_byte_xor_probability(ct))

