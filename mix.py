import socket
import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import threading
import time

# code for loading secret key and decrypting cypher text


#
# serverPrivateKey = load_pem_private_key(serverPrivateKey.encode(), password=None, backend=default_backend())
# plaintext = serverPrivateKey.decrypt(
#     ciphertext,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )

# print(plaintext)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Wrong amount of arguments")
        exit(1)

    y = sys.argv[1]

    # open ips.txt and extracting the port
    ipsFile = open("ips.txt", "r")
    counter = 1
    serverPort = None
    for line in ipsFile:
        if counter == int(y):
            serverPort = int(line.split(" ")[1])
        counter+=1

    #opening the sk file and extracting the secret key
    skFile = "sk" + y + ".pem"
    skFile = open(skFile, "r")
    serverPrivateKey = skFile.read()





