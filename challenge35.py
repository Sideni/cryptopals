import challenge10
import challenge11
import challenge15
import challenge33

import sys
import json
import socket
import base64
from socketserver import StreamRequestHandler, TCPServer

BOB_IP = '127.0.0.1'
BOB_PORT = 1234
FORCED_G = None

class MitmHandler(StreamRequestHandler):

    def recv_pg(self):
        data = self.rfile.readline()
        if not data:
            return False
        
        data = json.loads(data)
        print('Received {}'.format(data))
        self.p = data['p']
        self.g = data['g']
        return True
    
    def recv_pub(self):
        data = self.rfile.readline()
        if not data:
            return False
        
        data = json.loads(data)
        print('Received {}'.format(data))
        self.alice_pub = data['pub']
        return True
    
    def send_ack(self, ack):
        self.request.sendall(json.dumps(ack).encode('utf-8'))

    def send_pub(self, pub):
        params = {'pub' : pub}
        self.request.sendall(json.dumps(params).encode('utf-8'))

    def recv_enc_msg(self):
        data = self.rfile.readline()
        if not data:
            return None
        
        print('Received encrypted msg : {}'.format(data))
        return data

    def send_enc_msg(self, data):
        self.request.sendall(data)

    def handle(self) -> None:
        print('connection from {}:{}'.format(*self.client_address))
        try:
            while True:
                # Receiving P and G from Alice
                if not self.recv_pg():
                    break
                
                with socket.socket() as sock:
                    sock.connect((BOB_IP, BOB_PORT))
                    
                    # Manipulating chosen G
                    if FORCED_G != None:
                        self.g = FORCED_G

                    # Sending P and G to Bob
                    pg = {'g' : self.g, 'p' : self.p}
                    pg = (json.dumps(pg) + '\n').encode('utf-8')
                    sock.sendall(pg)
                    
                    # Receiving ack from Bob and relaying to alice
                    bob_ack = sock.recv(8192)
                    self.send_ack(json.loads(bob_ack))
                    
                    # Receiving pub from Alice
                    if not self.recv_pub():
                        break
                    
                    # Relaying alice's pub to bob
                    dict_pub = {'pub' : self.alice_pub}
                    dict_pub = (json.dumps(dict_pub) + '\n').encode('utf-8')
                    sock.sendall(dict_pub)
                
                    # Receiving pub from Bob
                    bob_pub = sock.recv(8192)
                    bob_pub = json.loads(bob_pub)['pub']
                    print('Bob pub is {}'.format(bob_pub))
                    
                    # Sending Bob's pub to Alice
                    self.send_pub(bob_pub)

                    # Because we've manipulated the G parameter sent to Bob
                    # Bob's public key will have a forced value (depending on which G was sent)
                    # With G = 1, Bob's public key = 1 -----> (1 ** priv) = 1 --> 1 % p = 1
                    # With G = p, Bob's public key = 0 -----> (p ** priv) % p = 0
                    # With G = p - 1, Bob's public key is either 1 or p - 1
                    # With the last case, Bob's public key with be 1 if priv is even and p - 1 if priv is odd
                    # By manipulating Bob's pub, we have a direct impact on Alice's S.
                    # For G = 1, s = (1 ** a) % p = 1
                    # For G = p, s = (0 ** a) % p = 0
                    # For G = p - 1, with Bob's priv even (same as G = 1)
                    # For G = p - 1, with Bob's priv odd (pub = p - 1), s = ((p - 1) ** a) % p = 1 OR p - 1
                    
                    # Because Bob computes S with alice's pub ** bob's priv, Alice and Bob won't have the same decryption key.
                    # So, unless we manipulate alice's pub sent to bob, we can't decrypt Bob's msg                    

                    if FORCED_G != None:
                        enc_key, hmac_key = challenge33.dh_gen_shared(bob_pub, 1234, self.p)

                    # Receiving encrypted msg from Alice
                    msg = self.recv_enc_msg()
                    if not msg:
                        break
                    
                    if FORCED_G != None:
                        print('Intercepted message from Alice to Bob : {}'.format(dec_msg(msg, enc_key)))
                        break

                    # Relaying encrypted msg to Bob
                    sock.sendall(msg)
                    
                    # Receiving encrypted msg from Bob
                    data = sock.recv(8192)
                    
                    if FORCED_G != None:
                        print('Intercepted message from Bob to Alice : {}'.format(dec_msg(data, enc_key)))

                    # Relaying encrypted msg to Alice
                    self.send_enc_msg(data)

        finally:
            print('disconnected from {}:{}'.format(*self.client_address))

class BobHandler(StreamRequestHandler):

    def recv_pg(self):
        data = self.rfile.readline()
        if not data:
            return False
        
        data = json.loads(data)
        print('Received {}'.format(data))
        self.p = data['p']
        self.g = data['g']
        return True
    
    def recv_pub(self):
        data = self.rfile.readline()
        if not data:
            return False
        
        data = json.loads(data)
        print('Received {}'.format(data))
        self.alice_pub = data['pub']
        return True
    
    def send_ack(self):
        params = {'ack' : True}
        self.request.sendall(json.dumps(params).encode('utf-8'))

    def send_pub(self):
        self.pub, self.priv = challenge33.dh_gen_keypair(self.p, self.g)
        self.enc_key, self.hmac_key = challenge33.dh_gen_shared(self.alice_pub, self.priv, self.p)
        
        params = {'pub' : self.pub}
        self.request.sendall(json.dumps(params).encode('utf-8'))

    def recv_enc_msg(self):
        data = self.rfile.readline()
        if not data:
            return None
        
        print('Received encrypted msg : {}'.format(data))
        return dec_msg(data, self.enc_key)

    def send_enc_msg(self, msg):
        data = enc_msg(msg, self.enc_key)
        self.request.sendall(data)

    def handle(self) -> None:
        print('connection from {}:{}'.format(*self.client_address))
        try:
            while True:
                if not self.recv_pg():
                    break
                
                self.send_ack()
                
                if not self.recv_pub():
                    break

                self.send_pub()
                msg = self.recv_enc_msg()
                if not msg:
                    break

                print('Received encrypted message : {}'.format(msg))                

                self.send_enc_msg(msg)

        finally:
            print('disconnected from {}:{}'.format(*self.client_address))

def enc_msg(msg, key):
    iv = challenge11.gen_key()
    padded = challenge15.pad_pkcs7(msg)
    ct = challenge10.aes_cbc_encrypt(padded, key, iv)
    
    return base64.b64encode(ct) + b':' + base64.b64encode(iv)

def dec_msg(data, key):
    if type(data) == str:
        data = data.encode('utf-8')

    ct, iv = data.split(b':')
    ct, iv = base64.b64decode(ct), base64.b64decode(iv)
    padded = challenge10.aes_cbc_decrypt(ct, key, iv)
    return challenge15.unpad_pkcs7(padded)

def alice(ip, port, p, g):
    pub, priv = challenge33.dh_gen_keypair(p, g)
    msg = b'Our last secret got leaked, this one will remain secret this time'

    with socket.socket() as sock:
        sock.connect((ip, port))
        
        pg = {'g' : g, 'p' : p}
        pg = (json.dumps(pg) + '\n').encode('utf-8')
        sock.sendall(pg)
        
        bob_ack = sock.recv(8192)
        bob_ack = json.loads(bob_ack)['ack']
        if not bob_ack:
            print('No acknowlegment received from Bob...')
            return

        dict_pub = {'pub' : pub}
        dict_pub = (json.dumps(dict_pub) + '\n').encode('utf-8')
        sock.sendall(dict_pub)

        bob_pub = sock.recv(8192)
        bob_pub = json.loads(bob_pub)['pub']
        print('Bob pub is {}'.format(bob_pub))

        enc_key, hmac_key = challenge33.dh_gen_shared(bob_pub, priv, p)
        data = enc_msg(msg, enc_key) + b'\n'
        sock.sendall(data)
        print('Enc msg sent : {}'.format(data.decode('utf-8')))
        
        data = sock.recv(8192)
        dec = dec_msg(data, enc_key)

        print('Received back our message "{}"'.format(dec.decode('utf-8')))

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        srv_addr = ('0.0.0.0', 1234)
        with TCPServer(srv_addr, BobHandler) as server:
            server.serve_forever()
    elif sys.argv[1] == 'alice':
        ip = '127.0.0.1'
        port = 1235
        p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        g = 2
        alice(ip, port, p, g)
    elif sys.argv[1] == 'mitm':
        if len(sys.argv) > 2:
            FORCED_G = int(sys.argv[2])

        srv_addr = ('0.0.0.0', 1235)
        with TCPServer(srv_addr, MitmHandler) as server:
            server.serve_forever()
        

