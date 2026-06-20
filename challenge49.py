import sys
import secrets
import binascii

from challenge5 import xor
from challenge10 import aes_cbc_encrypt
from challenge15 import pad_pkcs7

from Crypto.Cipher import AES
from hmac import compare_digest
from urllib.parse import quote, unquote, parse_qs

KEY = secrets.token_bytes(32)

def calc_signature(m, iv = None, gen_iv = False):
    if gen_iv:
        iv = secrets.token_bytes(AES.block_size)
    elif not iv:
        iv = b'\x00' * AES.block_size

    m = pad_pkcs7(m, AES.block_size)
    signature = aes_cbc_encrypt(m, KEY, iv)[-AES.block_size:]
   
    if gen_iv:
        return iv, signature
    else:
        return signature

def check_signature(m, s, iv = None):
    candidate = calc_signature(m, iv)
    return compare_digest(s, candidate)

## Start code for forgery with controlled IV

def client_gen_tx_v1(from_id, to_id, amount):
    if from_id != 'attacker':
        print("Can't send money from any other account than attacker")
        return

    if amount < 0:
        print("Can't send negative amounts")
        return

    msg = f'from={quote(from_id)}&to={quote(to_id)}&amount={quote(str(amount))}'
    
    iv, s = calc_signature(msg, gen_iv=True)
    return msg.encode() + binascii.hexlify(iv + s)

def extract_tx_v1(tx):
    m = tx[:-4 * AES.block_size]
    iv = binascii.unhexlify(tx[-4 * AES.block_size:-2 * AES.block_size])
    s = binascii.unhexlify(tx[-2 * AES.block_size:])
    return m, iv, s

def server_handle_tx_v1(tx):
    m, iv, s = extract_tx_v1(tx)
    if check_signature(m, s, iv):
        d = parse_qs(m)
        from_id = d[b'from'][0].decode()
        to_id = d[b'to'][0].decode()
        amount = int(d[b'amount'][0].decode())
        print(f'Successfully sent {amount} spacebucks from {from_id} to {to_id}')
    else:
        print("Invalid signature, couldn't proceed with transaction")

def forgery_1(tx):
    m, iv, s = extract_tx_v1(tx)
    
    flipper1 = b'from=attacker&to'
    flipper2 = b'from=BobAlice&to'
    
    iv = xor(iv, flipper1)
    iv = xor(iv, flipper2)
    
    m = flipper2 + m[len(flipper2):]
    return m + binascii.hexlify(iv + s)

## End code for forgery with controlled IV
########################################################
## Start code for forgery without controlled IV

def client_gen_tx_v2(from_id, transactions, for_interception=False):
    if not for_interception and from_id == 'victim_user':
        print("Can't send money from victim_user")
        return

    for to, amount in transactions:
        if amount < 0:
            print("Can't send negative amounts")
            return

    transactions = ';'.join([to + ':' + str(amount) for to, amount in transactions])
    msg = f'from={quote(from_id)}&tx_list={quote(transactions)}'
    
    s = calc_signature(msg)
    return msg.encode() + binascii.hexlify(s)

def extract_tx_v2(tx):
    m = tx[:-2 * AES.block_size]
    s = binascii.unhexlify(tx[-2 * AES.block_size:])
    return m, s

def server_handle_tx_v2(tx):
    import codecs
    tx = codecs.escape_decode(tx)[0]
    m, s = extract_tx_v2(tx)
    if check_signature(m, s):
        d = parse_qs(m)
        from_id = d[b'from'][0].decode()
        tx_list = d[b'tx_list'][0]
        
        print(f'{from_id} successfully sent:')
        for tx in tx_list.split(b';'):
            try:
                to_id, amount = tx.split(b':')
                amount = int(amount.strip())
                print(f'{amount} spacebucks to {to_id.decode()}')
            except ValueError:
                print('ERROR: Invalid transaction, proceeding with the next ones')
    else:
        print("Invalid signature, couldn't proceed with transaction")

def forgery_2(tx):
    m, s = extract_tx_v2(tx)
    m = pad_pkcs7(m, AES.block_size)
    last_block = m[-AES.block_size:]
    
    # 0123456789abcdef 0123456789abcdef 0123456789abcdef
    # from=victim_user &tx_list=someone %3A1234ttttttttt
    #    enc(^ X 0)      enc(^ X aaa)     enc(^ X bbb)
    # aaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbb ssssssssssssssss
    
    print("Let's find a valid account ID without url encoding")
    # 0123456789abcdef
    # from=garbagedata;attacker:12345...
    garbage_account_id = b''
    for s_c in s[5:]:
        for i in range(256):
            tmp = s_c ^ i
            # avoiding url encoding
            if i > 0x32 and i < 0x7f and i not in (ord('"'), ord('&'), ord('='), ord(';'), ord('?'), ord('/'), ord('#')):
                garbage_account_id += bytes([i])
                break

    if len(garbage_account_id) != len(s) - len('from='):
        print("Couldn't find valid utf8 xored account ID")
        print('Try with a different intercepted transaction')
        exit()
    
    print('Found ID:', garbage_account_id)
    print('-' * 88)
    print("Let's do a transaction with that ID")
    my_tx = client_gen_tx_v2(garbage_account_id + b';attacker:12345678922222;someone_else:55555555555', [('attacker', 1234567890)])
    my_m, my_s = extract_tx_v2(my_tx)

    my_blocks = [my_m[i:i + AES.block_size] for i in range(0, len(my_m), AES.block_size)]
    my_blocks[0] = xor(my_blocks[0], s)
    
    return m + b''.join(my_blocks) + binascii.hexlify(my_s)

## End code for forgery without controlled IV

if __name__ == '__main__':
    version = '2'
    if len(sys.argv) >= 2:
        version = sys.argv[1]

    # Code for forgery with controlled IV
    if version == '1':
        while True:
            try:
                from_id = input('Enter the account ID from which to take money: ').strip()
                to_id = input('Enter the account ID where to send money: ').strip()
                amount = int(input('Enter amount: ').strip())
                
                m = client_gen_tx_v1(from_id, to_id, amount)
                print("Here's the signed transaction you can pass to the server:")
                print(m.decode())
            
                tx = input('For forgery, enter a legitimate signed transaction: ').strip().encode()
                tx = forgery_1(tx)

                print('Here is the forged transaction:')
                print(tx.decode())
            except ValueError:
                print('Invalid values enterred, try again...')

            tx = input('Enter the transaction to send to the server: ').strip().encode()
            
            server_handle_tx_v1(tx)
    else: # Code for forgery without controlled IV
        try:
            from_id = 'victim_user'
            to_id = 'someone'
            amount = 123456
            
            transactions = []
            transactions.append((to_id, amount))
                
            m = client_gen_tx_v2(from_id, transactions, for_interception=True)
            
            print("Here's the signed transaction we intercepted from victim_user to someone:")
            print(m.decode())
            print('-' * 88)
            
            tx = input('For forgery, enter a legitimate signed transaction: ').strip().encode()
            print('=' * 88)
            tx = forgery_2(tx)

            print('~' * 88)
            print('Here is the forged transaction:')
            print(tx)
            print('_' * 88)
        except (ValueError, UnicodeDecodeError):
            print('Invalid values enterred, try again...')

        tx = input('Enter the transaction to send to the server: ').strip().encode()
       
        print('.' * 88)
        server_handle_tx_v2(tx)
        print('-' * 88)
