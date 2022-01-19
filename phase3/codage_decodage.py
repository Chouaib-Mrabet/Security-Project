import base64

def codage():
    message = input('Saisir le message a coder : ')

    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    print(message + " encode en base64 : " + base64_message)

def decodage():
    base64_message = input('Saisir le message a decoder : ')

    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    print(base64_message + " decoder en  : " + message)


