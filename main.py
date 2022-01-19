import re
import bcrypt
from phase12 import phase12
from phase3 import asymetric, codage_decodage, craquage, hachage, symetrique


def choix_menu_principale():
    while True:
        choix = input("Votre choix: ")

        if not choix in ["1", "2", "31a", "31b", "32a", "32b", "32c", "33a", "33b", "33c", "34a", "34b", "35a", "35b", "36", "99"]:
            print("-----------------------------------------------")
            print(" Votre choix est invalide.")
            print("-----------------------------------------------")
            print_menu_principale()
        else:
            return choix


def print_menu_principale():
    print("-----------------------------------------------")
    print("                   Phase 1                     ")
    print("-----------------------------------------------")
    print("1. Ajouter un utilisateur")

    print("-----------------------------------------------")
    print("                   Phase 2                     ")
    print("-----------------------------------------------")
    print("2. Authentification")

    print("-----------------------------------------------")
    print("                   Phase 3                     ")
    print("-----------------------------------------------")
    print("3-1. Codage et décodage d'un message")
    print("     a. Codage ")
    print("     b. Decodage")

    print("3-2. Hashage d'un message")
    print("     a. Md5 ")
    print("     b. SHA1")
    print("     c. SHA256")

    print("3-3. Craquage d'un message hashé")
    print("     a. Md5 ")
    print("     b. SHA1")
    print("     c. SHA256")

    print("3-4. Chiffrement et déchiffrement symétrique")
    print("     a. DES ")
    print("     b. AES256")

    print("3-5. Chiffrement et déchiffrement asymétrique")
    print("     a. RSA ")
    print("     b. Elgamal")

    print("3-6. Communication sécurisé entre deux clients (ChatRoom)")

    print("-----------------------------------------------")

    print("99. Quitter")


def redirection():
    choice = int(input('\nChoisir : 1- Retour Menu principal     2- Exit \n'))
    if choice == 1:
        main_program()
    else:
        exit()


def main_program():
    choix = 0
    print_menu_principale()
    choix = choix_menu_principale()

    if choix == 1:
        phase12.enregistrement()
        redirection()
    elif choix == 2:
        phase12.Authentification()
        redirection()

    elif choix == "31a":
        codage_decodage.codage()
        redirection()

    elif choix == "31b":
        codage_decodage.decodage()
        redirection()
    elif choix == "32a":
        hachage.hashage("md5")
        redirection()

    elif choix == "32b":
        hachage.hashage("sh1")
        redirection()

    elif choix == "32c":
        hachage.hashage("sha256")
        redirection()

    elif choix == "33a":
        craquage.crack_hash_dictionary_attack()
        redirection()

    elif choix == "33b":
        craquage.crack_hash_dictionary_attack()
        redirection()

    elif choix == "33c":
        craquage.crack_hash_dictionary_attack()
        redirection()

    elif choix == "34a":
        symetrique.encrypt("des")
        print("----------------------------------------")
        symetrique.decrypt("des")

        redirection()

    elif choix == "34b":
        symetrique.encrypt("aes")
        print("----------------------------------------")
        symetrique.decrypt("aes")

        redirection()
    elif choix == "35a":
        asymetric.generate_key("rsa")

        print("----------------------------------------")

        asymetric.encrypt_asym("rsa")
        print("----------------------------------------")
        asymetric.decrypt_asym("rsa")
        print("\n----------------------------------------")
        print("----------------------------------------")

        asymetric.sign_asym("rsa")
        print("----------------------------------------")
        asymetric.verify_asym("rsa")

        redirection()

    elif choix == "35b":
        asymetric.generate_key("dsa")

        print("----------------------------------------")

        asymetric.encrypt_asym("dsa")
        print("----------------------------------------")
        asymetric.decrypt_asym("dsa")
        print("\n----------------------------------------")
        print("----------------------------------------")

        asymetric.sign_asym("dsa")
        print("----------------------------------------")
        asymetric.verify_asym("dsa")

        redirection()

    elif choix == "36":
        redirection()

    elif choix == 99:
        print("Merci pour utiliser notre program :)")
        exit()


main_program()
