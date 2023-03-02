import challenge1
import challenge2
import challenge3

def search_best_pt(pts):
    _, pt = challenge3.closest_etaoin_fullbytes(pts)
    return pts.index(pt), pt

def get_pts_fullbytes(cts):
    pts = []
    for ct in cts:
        pts.append(challenge3.brute_single_byte_xor_fullbytes(ct))
    return pts

def get_pts_prob(cts):
    pts = []
    for ct in cts:
        pt = challenge3.brute_single_byte_xor_probability(ct)
        if pt:
            pts.append(pt)
    return pts

if __name__ == '__main__':
    with open('4.txt') as f:
        cts = [challenge1.decode_hexstr(line.strip()) for line in f]

    # Levenshtein test
    pts = get_pts_fullbytes(cts)
    i, pt = search_best_pt(pts)
    print('Ciphertext {} decrypts to : {}'.format(challenge1.encode_hexstr(cts[i]), pts[i]))
    
    # Printability test
    pts = get_pts_prob(cts)
    for pt in pts:
        print(pt)

