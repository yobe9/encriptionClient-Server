# Gal Ben Arush, 208723791, Yoav Berger, 313268393

import socket
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from datetime import datetime

if len(sys.argv) != 4:
    print("Wrong amount of arguments")
    exit(1)

#opening socket to every IP and given port
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', int(sys.argv[3])))
server.listen(300)


while True:
    #receiving message
    client_socket, client_address = server.accept()
    data = client_socket.recv(2048)

    # getting out needed parameters for decryption
    password = str.encode(sys.argv[1])
    salt = str.encode(sys.argv[2])
    # decripting the data
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    k = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(k)
    decryptMsg = f.decrypt(data).decode()

    #printing the decypher data
    now = datetime.now()
    print(decryptMsg, now.strftime("%H:%M:%S"))
    #close socket
    client_socket.close()

