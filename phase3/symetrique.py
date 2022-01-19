from Crypto.Cipher import DES, AES
import random
import base64

def pad(text, length):
    while len(text) % length != 0:
        text += ' '
    return text

def generate_key(length):
    key = random.randint(0, pow(2, length)-1)
    f = open("key.txt", "w")
    f.write(str(key))
    f.close()
    return key

def switch_func_encrypt(hash, message):
    return {
        'des': lambda message: encrypt_DES(message),
        'aes': lambda message: encrypt_AES(message),
    }.get(hash)(message)

def encrypt(algo=''):
    print('Saisir le message a enrypter avec l algorithm : ', algo,'\n')
    message = input()
    print('\nLe resultat est : \n', switch_func_encrypt(algo, message))

def switch_func_decrypt(hash, message, key):
    return {
        'des': lambda message: decrypt_DES(message, int(key)),
        'aes': lambda message: decrypt_AES(message, int(key)),
    }.get(hash)(message)

def decrypt(algo=''):
    print('Saisir le message a decrypter avec l algorithm : ', algo,'\n')
    message = input()
    print('\nSaisir la clé : \n')
    key = input()
    print('\nLe resultat est : \n', switch_func_decrypt(algo, message, key))

# DES algorithm
def encrypt_DES(message):
    key = generate_key(8)
    key_bytes = key.to_bytes(8, 'big')
    des = DES.new(key_bytes, DES.MODE_ECB)
    pad_string = pad(message, 8).encode('utf8')
    crypt = des.encrypt(pad_string)
    return base64.b64encode(crypt).decode('utf8'), key

def decrypt_DES(encrypted_message, key):
    key_bytes = key.to_bytes(8, 'big')
    des = DES.new(key_bytes, DES.MODE_ECB)
    encrypted_message = base64.b64decode(encrypted_message.encode())
    return des.decrypt(encrypted_message).decode('utf8')

# AES algorithm
def encrypt_AES(message):
    key = generate_key(16)
    key_bytes = key.to_bytes(16, 'big')
    aes = AES.new(key_bytes, AES.MODE_ECB)
    pad_string = pad(message, 16).encode('utf8')
    crypt = aes.encrypt(pad_string)
    return base64.b64encode(crypt).decode('utf8'), key

def decrypt_AES(encrypted_message, key):
    key_bytes = key.to_bytes(16, 'big')
    aes = AES.new(key_bytes, AES.MODE_ECB)
    encrypted_message = base64.b64decode(encrypted_message.encode())
    return aes.decrypt(encrypted_message).decode('utf8')

