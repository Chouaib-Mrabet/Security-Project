import hashlib
import sys
import time
from itertools import product


def switch_func(hash, message):
    return {
        'md5': lambda message: md5(message),
        'sh1': lambda message: sh1(message),
        'sha256': lambda message: sha256(message)
    }.get(hash)(message)


def hashage(hash):
    print('Saisir le message a hacher avec : ', hash, ': ')
    message = input()
    print('Le message hacher est : ', switch_func(hash, message))


def md5(message):
    hashMD5 = hashlib.md5(message.encode('ascii'))
    return hashMD5.hexdigest()


def sh1(message):
    hashSHA1 = hashlib.sha1(message.encode())
    return hashSHA1.hexdigest()

def sha256(message):
    hashSHA256 = hashlib.sha256(message.encode())
    return hashSHA256.hexdigest()



