import challenge1
import challenge33
import challenge36

import sys
import hmac
import secrets
import hashlib

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
G = 2
I = b'test@example.com'
P = b'SuperSecretPasswordThatNoOneKnowsOtherThanMe'

def gen_x(passwd, salt):
    x = hashlib.sha256(salt + passwd).hexdigest()
    return int(x, 16)

class Server():
    def __init__(self, n, g, i, p):
        self.n = n
        self.g = g
        self.i = i
        
        self.salt = challenge36.gen_salt()
        
        x = gen_x(p, self.salt)
        self.v = pow(self.g, x, self.n)

    def gen_server_s(self, client_pub, server_priv, u):
        return pow(client_pub * pow(self.v, u, self.n), server_priv, self.n)
    
    def serve_forever(self):
        while True:
            pub_c = int(input('What is your public key?'))
            email = input('What is your email ?').encode('utf-8')
            
            pub_s, priv_s = challenge33.dh_gen_keypair(self.n, self.g)
            u = secrets.randbits(128)
            
            print('Salt is : {}'.format(challenge1.encode_hexstr(self.salt)))
            print('Public key : {}'.format(pub_s))
            print('Private key : {}'.format(priv_s))
            print('U is : {}'.format(u))

            server_s = self.gen_server_s(pub_c, priv_s, u)
            server_key = challenge36.gen_key(server_s)
            
            hmac_s = challenge36.hmac_sha256(server_key, self.salt)

            hmac_c = challenge1.decode_hexstr(input('What is the computed hmac ?'))
            
            if self.i == email and hmac.compare_digest(hmac_c, hmac_s):
                print('You have successfully logged on !')
            else:
                print('The entered information is incorrect')

class Client():
    def __init__(self, n, g):
        self.n = n
        self.g = g

    def gen_client_s(self, server_pub, client_priv, x, u):
        return pow(server_pub, client_priv + u * x, self.n)

    def answer(self, p=None):
        pub_c, priv_c = challenge33.dh_gen_keypair(self.n, self.g)

        print('Public key : {}'.format(pub_c))
        
        salt = challenge1.decode_hexstr(input('What is the salt ?'))
        
        pub_s = int(input('What is server\'s public key ?'))
        
        u = int(input('What is server\'s U ?'))
        
        if not p:
            passwd = input('What is your password ?').encode('utf-8')
        else:
            passwd = p

        x = gen_x(passwd, salt)
        client_s = self.gen_client_s(pub_s, priv_c, x, u)
        client_key = challenge36.gen_key(client_s)

        hmac_c = challenge36.hmac_sha256(client_key, salt)
        
        print('Computed hmac : {}'.format(challenge1.encode_hexstr(hmac_c)))

def bruteforce(pwd_list, computed_hmac, salt, pub_c, priv_s, u, g, n):
    for i, pwd in enumerate(pwd_list):
        x_candidate = gen_x(pwd, salt)
        v_candidate = pow(g, x_candidate, n)
        s_candidate = pow(pub_c * pow(v_candidate, u, n), priv_s, n)
        k_candidate = challenge36.gen_key(s_candidate)
        hmac_candidate = challenge36.hmac_sha256(k_candidate, salt)
        if computed_hmac == hmac_candidate:
            return pwd

if __name__ == '__main__':
    # python challenge38.py [server|client|brute] /path/to/rockyou.txt

    random_pass = False
    if len(sys.argv) == 3:
        rockyou_path = sys.argv[2]
        with open(rockyou_path, 'rb') as f:
            rockyou = [line.rstrip() for line in f][:10000] # Use only the first 10000 passwords
        
        P = secrets.choice(rockyou)
        random_pass = True

    if sys.argv[1] == 'server':
        server = Server(N, G, I, P)
        server.serve_forever()
    elif sys.argv[1] == 'client':
        client = Client(N, G)
        if random_pass:
            client.answer(p=P)
        else:
            client.answer()
    elif sys.argv[1] == 'brute':
        # The bruteforce is done on a small list of 10000 words
        # The process is quite slow because of modular exponentiation
        # The whole process requires three exponentiations (g ** x, v ** u, (A * v ** u) ** b)
        # This process could be faster by choosing a small U and a small private key for the server
        # This would make two of the three exponentiation faster

        pub_c = int(input('What is client\'s public key ?'))
        priv_s = int(input('What is server\'s private key ?'))
        u = int(input('What is U ?'))
        salt = challenge1.decode_hexstr(input('What is the salt ?'))
        computed_hmac = challenge1.decode_hexstr(input('HMAC computed ?'))
        pwd = bruteforce(rockyou, computed_hmac, salt, pub_c, priv_s, u, G, N)
        print('The password is : {}'.format(pwd))

