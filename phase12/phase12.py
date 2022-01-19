import re
import hashlib
import mysql.connector
import getpass


def estValide(email):
    regex = re.compile(r'^\w+.\w+@insat.ucar.tn$')

    if re.fullmatch(regex, email):
        return True
    else:
        return False


def saisir_mail():
    while True:
        email = input("Saisir Email: ")

        if not estValide(email):
            print("Email invalide")
        else:
            if getUser(email) is None:
                return email
            else:
                print("Cette utilisateur existe deja!")


def saisir_mot_de_pass():
    while True:
        password1 = getpass.getpass('Saisir mot de passe: ')

        if(len(password1) < 4):
            print("Le mot de passe doit avoir au moins 4 caractere : ")
            continue

        while True:
            password2 = getpass.getpass("Confirmer votre mot de passe: ")
            if(password1 != password2):
                print("mot de passe incorrect: ")
            else:
                return password1


def ajouter_utilisateur(nom, prenom, email, password):
    mydb = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="projet_ssi"
    )

    mycursor = mydb.cursor()

    insert_query = "INSERT INTO user (nom, prenom, email, password) VALUES (%s, %s, %s, %s)"
    values = (nom, prenom, email, password)

    mycursor.execute(insert_query, values)

    mydb.commit()


def getUser(email):
    mydb = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="projet_ssi"
    )

    mycursor = mydb.cursor()

    select_query = "SELECT * FROM user where email = %s"
    values = (email,)

    mycursor.execute(select_query, values)

    return mycursor.fetchone()


def enregistrement():
    print("---------------- Enregistrement -------------------")

    email = saisir_mail()
    password = saisir_mot_de_pass()

    nom, prenom = email.split("@")[0].split(".")

    hashed = hashlib.sha512(password.encode()).hexdigest()

    ajouter_utilisateur(nom, prenom, email, hashed)


def Authentification():
    print("---------------- Authentification -------------------")

    while True:
        email = input("Saisir Email: ")
        password = getpass.getpass('Saisir votre mot de passe: ')

        user = getUser(email)

        if user is None:
            print("Votre email et/ou mot de pass est incorrect")
            continue
        else:
            hashed = hashlib.sha512(password.encode()).hexdigest()
            # print(hashed)

            if hashed == user[4]:
                print("Authentification reussite")
                print("Bienvenue : " + user[1] + " " + user[2])
                break
