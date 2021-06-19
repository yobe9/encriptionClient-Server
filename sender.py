# id1 name1, id2 name2
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

class myThread (threading.Thread):
   def __init__(self,givenRound, ip, port, cipher):
       threading.Thread.__init__(self)
       self.givenRound = givenRound
       self.ip = ip
       self.port = port
       self.cipher = cipher
   def run(self):

       time.sleep(int(self.givenRound) * 5)
       print("in run")
       s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       s.sendto(self.cipher, (self.ip, int(self.port)))
       s.close()


if __name__ == '__main__':
    # check correct number of arguments
    if len(sys.argv) != 2:
        print("Wrong amount of arguments")
        exit(1)
    x = sys.argv[1]

    #open ips.txt and storing the servers data
    ipsFile = open("ips.txt", "r")
    servers = []
    for line in ipsFile:
        servers.append(line.split(" ")) #end line extract with \n *****************
    # open messages file according to input
    fileName = "messages" + x + ".txt"
    openFile = open(fileName, "r")
    # parse messages into array
    messages = []
    for line in openFile:
        messages.append(line.split(" "))#end line extract with \n *******

    # for each message
    for message in messages:
        #getting out needed parameters for encryption
        password = str.encode(message[3])
        salt = str.encode(message[4])
        info = str.encode(message[0])
        #encripting the data
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        k = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(k)
        data = f.encrypt(info)
        #getting out the port and convert to bytes format
        bobPort = int(message[6])
        bobPort = bobPort.to_bytes(2, 'big')
        #getting out the IP and convert to bytes format
        bobIP = message[5]
        bobIP = bobIP.split(".")
        temp = b''
        for num in bobIP:
            temp += int(num).to_bytes(1, 'big')
        bobIP = temp
        #concating the msg
        msg = bobIP+bobPort+data

        #getting the servers public key according to number
        path = message[1]
        path = path.split(",")
        pathLen = len(path)

        pkFile = "pk" + path[pathLen - 1] + ".pem"
        pkFile = open(pkFile, "r")
        serverPublicKey = pkFile.read()
        serverPublicKey = load_pem_public_key(serverPublicKey.encode(), backend=default_backend())
        ciphertext = serverPublicKey.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #creating copy of servers IP and port arr
        serversCopy = servers.copy()

        while pathLen > 1:
            #poping the handeld server from the end
            path.pop()
            pathLen -= 1
            #getting the ip and port of current server
            currentServerIP = serversCopy[0][0]
            currentServerIP = currentServerIP.split(".")
            segment = b''
            for num in currentServerIP:
                segment+= int(num).to_bytes(1, 'big')
            currentServerIP = segment

            currentServerPort = serversCopy[0][1]
            currentServerPort = int(currentServerPort)
            currentServerPort = currentServerPort.to_bytes(2, 'big')
            #concating ip port cypher
            msg = currentServerIP + currentServerPort + ciphertext

            pkFile = "pk" + path[pathLen - 1] + ".pem"
            pkFile = open(pkFile, "r")
            serverPublicKey = pkFile.read()
            serverPublicKey = load_pem_public_key(serverPublicKey.encode(), backend=default_backend())
            ciphertext = serverPublicKey.encrypt(
                msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            #poping the server Ip and port info from the begining
            serversCopy.pop(0)

        #sending the message to the first server in the given path
        targetServerIP = serversCopy[0][0]
        targetServerPort = serversCopy[0][1]
        givenRound = message[2]
        print(targetServerIP, targetServerPort, givenRound, ciphertext)
        #sending the information to the server according to round, with thread so we handle all the message at once
        thread = myThread("1", targetServerIP, targetServerPort, ciphertext)
        thread.start()



