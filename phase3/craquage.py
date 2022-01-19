import hashlib
import sys
import time
from itertools import product


def get_algorithm(type):

    def algorithm(string):
        h = type()
        h.update(string.encode('utf-8'))
        return h.hexdigest()

    return algorithm


TYPES_DICT = {
    32: get_algorithm(hashlib.md5),
    40: get_algorithm(hashlib.sha1),
    64: get_algorithm(hashlib.sha256)
}


class Craquage(object):

    def __init__(self):
        self.decrypt_method = None
        self.decrypted_hash = None
        self.user_file = None
        self.PATH = r"C:\Users\chouaib\Desktop\PROJECT SECURITE\phase3\wordlist.txt"

    def dictionary_attack_call(self):
        self.user_hash = self.get_hash()

        while self.decrypted_hash == None:

            self.wordlist = self.gen_wordlist()
            self.decrypted_hash = self.dict_attack()

            if self.decrypted_hash != None:
                self.elapsed = (time.time() - self.start)
                print('Hash craqué en ' + str(self.elapsed) +
                      ' secondes. Le mot hashé est : \n' + self.decrypted_hash)
            else:
                print('aucun mot trouvé')
                break

    def get_hash(self):
        while True:
            hash_input = input('Saisir le hash :\n')

            if hash_input.isalnum():
                length = len(hash_input)

                if TYPES_DICT.get(length, None):
                    self.hashtype = TYPES_DICT[length]
                    return hash_input
                else:
                    print('hash invalide')
            else:
                print('hash invalide')

    def gen_wordlist(self):
        self.filename = self.PATH
        self.user_file = open(self.filename, 'r', encoding='utf-8')

        words = self.user_file.read()
        self.user_file.close()
        return words.split()

    def dict_attack(self):
        self.start = time.time()

        print('En cours...\n\n')

        for word in self.wordlist:
            test = self.hashtype(word)
            if test == self.user_hash:
                return word


def crack_hash_dictionary_attack():
    run_it = Craquage()
    run_it.dictionary_attack_call()


