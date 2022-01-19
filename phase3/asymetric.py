from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from base64 import b64decode, b64encode

def generate_key(algorithm):
    pwd = input('Saisir votre password pour generer les clés :  \n')

    if algorithm == 'rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    elif algorithm == 'dsa':
        private_key = dsa.generate_private_key(
            key_size=2048
        )

    public_key = private_key.public_key()

    # private key
    serial_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            pwd.encode('utf-8'))
    )
    with open(algorithm + '_private_key.pem', 'wb') as f:
        f.write(serial_private)

    # public key
    serial_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(algorithm + '_public_key.pem', 'wb') as f:
        f.write(serial_pub)

    print("Les deux clés sont generé ")

    return public_key, private_key


def read_private_key(algorithm):
    pwd = input('Saisir votre password :  \n')

    with open(algorithm + "_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=pwd.encode('utf-8'),
            backend=default_backend()
        )

    return private_key


def read_public_key(algorithm):

    with open(algorithm + "_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    return public_key


def sign_asym(algorithm):
    message = input("Saisir votre message pour le signer \n")

    signature = True
    private_key = read_private_key(algorithm)
    message = message.encode()

    if algorithm == 'rsa':
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    elif algorithm == 'dsa':
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )

    print("messgae signé avec l'algorithm : ", algorithm, "\n")
    print(b64encode(signature).decode('utf8'))

    return b64encode(signature).decode('utf8')


def verify_asym(algorithm):
    message = input("Entrer le message a verifier : \n")
    signature = input("Entrer la signature a utiliser : \n")

    try:
        verif = None
        public_key = read_public_key(algorithm)
        signature = b64decode(signature)
        message = message.encode()

        if algorithm == 'rsa':
            verif = public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256(),
            )
        elif algorithm == 'dsa':
            verif = public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
    except:
        print("\nLe message n'est pas verifié avec l'agorithm : ", algorithm)

        return False

    print("\nLe message est verifié avec l'agorithm : ", algorithm)

    return True


def encrypt_asym(algorithm):
    message = input("Entrer le message a encrypter: \n")
    encrypted_message = None
    public_key = read_public_key(algorithm)
    message = message.encode()

    if algorithm == 'rsa':
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    print("message encrypte avec l'algorithm", algorithm, "\n")
    print(b64encode(encrypted_message).decode('utf-8'))

    return b64encode(encrypted_message).decode('utf-8')


def decrypt_asym(algorithm):
    encrypted_message = input("Entrer le message a decrypter : \n")
    message = None
    private_key = read_private_key(algorithm)
    encrypted_message = b64decode(encrypted_message)

    if algorithm == 'rsa':
        message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    print("message decrypte avec l'algorithm", algorithm, "\n")
    print(message.decode('utf8'))

    return message.decode('utf8')



