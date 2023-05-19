import secrets
import hashlib

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def power_mod(b, e, m):
    x = 1
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )

    return x

def diffie_hellman(p=None, g=2):
    if not p:
        p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

    a = secrets.randbelow(p)
    A = power_mod(g, a, p)
    
    b = secrets.randbelow(p)
    B = power_mod(g, b, p)

    s1 = power_mod(B, a, p)
    s2 = power_mod(A, b, p)
    assert s1 == s2
    
    s = hashlib.sha256(int_to_bytes(s1)).hexdigest()
    enc_key, hmac_key = s[:len(s) // 2], s[len(s) // 2:]

    return a, A, b, B, enc_key, hmac_key

def dh_gen_keypair(p, g):
    priv = secrets.randbelow(p)
    pub = power_mod(g, priv, p)
    
    return pub, priv

def dh_gen_shared(pubB, privA, p):
    s = power_mod(pubB, privA, p)
    s = hashlib.sha256(int_to_bytes(s)).digest()
    enc_key, hmac_key = s[:len(s) // 2], s[len(s) // 2:]
    
    return enc_key, hmac_key

if __name__ == '__main__':
    diffie_hellman()
    
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    A, a = dh_gen_keypair(p, g)
    B, b = dh_gen_keypair(p, g)
    
    assert dh_gen_shared(B, a, p) == dh_gen_shared(A, b, p)
    print('Success !')

