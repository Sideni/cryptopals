import challenge1
import challenge39
import math

SECRET_MESSAGE = 'Alice and Bob are talking behind my back...'

def encrypt_secret(e=3):
    rsa = challenge39.RSA(e=e)
    return rsa.encrypt_str(SECRET_MESSAGE), rsa.e, rsa.n

def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

def crt(as_and_ns):
    N = math.prod([n for a, n in as_and_ns])
    x = 0
    for i, a_and_n in enumerate(as_and_ns):
        ai, ni = a_and_n

        yi = N // ni
        inv_yi = challenge39.invmod(yi, ni)
        x += ai * yi * inv_yi

    x = x % N
    return nth_root(x, len(as_and_ns))
    

def rsa_broadcast_attack(e=3):
    coerced = []
    for _ in range(e):
        enc, e, n = encrypt_secret(e=e)
        coerced.append((enc, n))

    x = crt(coerced)

    print(challenge1.decode_hexstr(hex(x)[2:]))


if __name__ == '__main__':
    rsa_broadcast_attack(e=3)

