import challenge33

import hmac
import secrets
import hashlib

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
G = 2
K = 3
I = b'test@example.com'
P = b'SuperSecretPasswordThatNoOneKnowsOtherThanMe'

def gen_salt(byte_len=16):
    return secrets.token_bytes(byte_len)

def gen_x(password, salt):
    if type(password) == str:
        password = password.encode('utf-8')
    if type(salt) == str:
        salt = salt.encode('utf-8')
    
    xh = hashlib.sha256(salt + password).digest()
    return int.from_bytes(xh, 'big')

def gen_u(pub_a, pub_b):
    pub_a = challenge33.int_to_bytes(pub_a)
    pub_b = challenge33.int_to_bytes(pub_b)
    uh = hashlib.sha256(pub_a + pub_b).digest()
    return int.from_bytes(uh, 'big')

def gen_priv(n):
    return secrets.randbelow(n)

def gen_mixed_pub(v, priv):
    return (K * v + pow(G, priv, N)) % N

# v = g ** x % N
# B = kv + g ** b % N
# S = (B - k * g**x)**(a + u * x) % N
# S = (kv + g ** b - k * g ** x) ** (a + u * x) % N
# S = (k * g**x + g**b - k * g**x) ** (a + u * x) % N
# S = (g**b) ** (a + u * x) % N
# S = (g ** (b * a + b * u * x)) % N
def gen_client_s(mixed_server_pub, client_priv, x, u):
    return pow((mixed_server_pub - K * pow(G, x, N)), client_priv + u * x, N)

# A = g ** a % N
# v = g ** x % N
# S = (A * v ** u) ** b % N
# S = (g ** a * (g ** x) ** u) ** b % N
# S = (g ** a * g ** (u * x)) ** b % N
# S = (g ** (a + u * x)) ** b % N
# S = (g ** (b * a + b * u * x)) % N 
def gen_server_s(client_pub, server_priv, v, u):
    return pow(client_pub * pow(v, u, N), server_priv, N)

def gen_key(i):
    return hashlib.sha256(challenge33.int_to_bytes(i)).digest()

def hmac_sha256(key, msg):
    return hmac.digest(key, msg, hashlib.sha256)

if __name__ == '__main__':
    # Server
    salt = gen_salt()
    x = gen_x(P, salt)
    v = pow(G, x, N)
    x = None # Erasing X (the server wouldn't keep it)

    # Client
    # Sending I and A (public key)
    pub_c, priv_c = challenge33.dh_gen_keypair(N, G)
    email = input('What is your email ?').encode('utf-8')

    # Server
    # Sending salt and B (public key mixed with password)
    if email != I:
        print('Invalid credentials')
        exit()

    priv_s = gen_priv(N)
    pub_s = gen_mixed_pub(v, priv_s)

    # Server and client compute U
    u = gen_u(pub_c, pub_s)

    # Client generates S from password
    passwd = input('What is your password ?').encode('utf-8')
    x = gen_x(passwd, salt)
    client_s = gen_client_s(pub_s, priv_c, x, u)
    client_key = gen_key(client_s)

    # Server generates S from v and u
    server_s = gen_server_s(pub_c, priv_s, v, u)
    server_key = gen_key(server_s)

    # Client sends hmac-sha256(key, salt) to server
    client_hmac = hmac_sha256(client_key, salt)

    # Server validates the hmac
    server_hmac = hmac_sha256(server_key, salt)
    if hmac.compare_digest(client_hmac, server_hmac):
        print('The entered credentials are valid')
    else:
        print('Invalid credentials')

