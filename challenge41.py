import challenge1
import challenge28
import challenge39

class Server():
    def __init__(self):
        self.validated = []
        self.rsa = challenge39.RSA(e=65537)

    def alreadyValidated(self, c):
        h = challenge28.sha1(hex(c))
        if h in self.validated:
            return True

        self.validated.append(h)
        return False

    def decrypt(self, c):
       if self.alreadyValidated(c):
           return 'No replay possible'

       return self.rsa.decrypt_str(c) 

def client(server):
    secret_str = b'Nobody will ever know my secret :)'
    pub = server.rsa.get_public()

    rsa = challenge39.RSA()
    enc = rsa.encrypt_str(secret_str, pub=pub)
    dec = server.decrypt(enc)
    assert dec == secret_str

    return enc

if __name__ == '__main__':
    server = Server()
    enc = client(server)

    e, n = server.rsa.get_public()
    s = 1234
    s_inv = challenge39.invmod(s, n)

    # Everything here is mod n
    # enc == m**e
    # s**e * m**e = (sm)**e = enc'
    # enc'**d = (sm)**e*d = sm
    # sm / s = m
    enc_mod = enc * pow(s, e, n) % n

    dec = int.from_bytes(server.decrypt(enc_mod), 'big')
    dec = dec * s_inv % n
    print(challenge1.decode_hexstr(hex(dec)[2:]))

