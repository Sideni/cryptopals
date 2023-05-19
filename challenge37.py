import challenge1
import challenge33
import challenge36

import sys
import hmac
import secrets
import hashlib

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
G = 2
K = 3
I = b'test@example.com'
P = b'SuperSecretPasswordThatNoOneKnowsOtherThanMe'

class Server():
    def __init__(self, n, g, k, i, p):
        self.n = n
        self.g = g
        self.k = k
        self.i = i
        
        self.salt = challenge36.gen_salt()
        
        x = challenge36.gen_x(p, self.salt)
        self.v = pow(self.g, x, self.n)

    # A = g ** a % N
    # v = g ** x % N
    # S = (A * v ** u) ** b % N
    # S = (g ** a * (g ** x) ** u) ** b % N
    # S = (g ** a * g ** (u * x)) ** b % N
    # S = (g ** (a + u * x)) ** b % N
    # S = (g ** (b * a + b * u * x)) % N 

    # When A = 0
    # S = (A * v ** u) ** b % N == 0

    # When A = N, N*2, N*3, ...
    # S = (some multiple of N) % N == 0
    def gen_server_s(self, client_pub, server_priv, u):
        return pow(client_pub * pow(self.v, u, self.n), server_priv, self.n)
    
    def serve_forever(self):
        while True:
            pub_c = int(input('What is your public key?'))
            email = input('What is your email ?').encode('utf-8')
            
            priv_s = challenge36.gen_priv(self.n)
            mixed_pub_s = challenge36.gen_mixed_pub(self.v, priv_s)
            
            print('Salt is : {}'.format(challenge1.encode_hexstr(self.salt)))
            print('Mixed public key : {}'.format(mixed_pub_s))
            
            u = challenge36.gen_u(pub_c, mixed_pub_s)
            server_s = self.gen_server_s(pub_c, priv_s, u)
            server_key = challenge36.gen_key(server_s)
            hmac_s = challenge36.hmac_sha256(server_key, self.salt)

            hmac_c = challenge1.decode_hexstr(input('What is the computed hmac ?'))
            
            if self.i == email and hmac.compare_digest(hmac_c, hmac_s):
                print('You have successfully logged on !')
            else:
                print('The entered information is incorrect')

class Client():
    def __init__(self, n, g, k):
        self.n = n
        self.g = g
        self.k = k

    # v = g ** x % N
    # B = kv + g ** b % N
    # S = (B - k * g**x)**(a + u * x) % N
    # S = (kv + g ** b - k * g ** x) ** (a + u * x) % N
    # S = (k * g**x + g**b - k * g**x) ** (a + u * x) % N
    # S = (g**b) ** (a + u * x) % N
    # S = (g ** (b * a + b * u * x)) % N

    # When client pub = 0, the server's S = 0 and so, the client set S to 0
    def gen_client_s(self, mixed_server_pub, client_priv, x, u):
        return pow((mixed_server_pub - self.k * pow(self.g, x, self.n)), client_priv + u * x, self.n)

    def answer(self):
        bypass = bool(input('Want to bypass the login ? [y/N]'))
        
        pub_c, priv_c = challenge33.dh_gen_keypair(self.n, self.g)
        if bypass:
            pub_c = self.n * secrets.randbelow(5)        

        print('Public key : {}'.format(pub_c))
        
        salt = challenge1.decode_hexstr(input('What is the salt ?'))
        
        if not bypass:
            mixed_pub_s = int(input('What is server\'s mixed public key ?'))
        
            u = challenge36.gen_u(pub_c, mixed_pub_s)
        
            passwd = input('What is your password ?').encode('utf-8')

            x = challenge36.gen_x(passwd, salt)
            client_s = self.gen_client_s(mixed_pub_s, priv_c, x, u)
        
        else:
            client_s = 0
        client_key = challenge36.gen_key(client_s)
        hmac_c = challenge36.hmac_sha256(client_key, salt)
        
        print('Computed hmac : {}'.format(challenge1.encode_hexstr(hmac_c)))

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server = Server(N, G, K, I, P)
        server.serve_forever()
    elif sys.argv[1] == 'client':
        client = Client(N, G, K)
        client.answer()

