# Gal Ben Arush, 208723791, Yoav Berger, 313268393
import socket
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import threading
import time

# global stop
STOP = False
# array to saving the messages recived in the passed minute
messagesToSend = []

class myThread (threading.Thread):
   def __init__(self, messagesToSend):
       threading.Thread.__init__(self)
       self.messagesToSend = messagesToSend
   def run(self):
       #sending the message after 62 seconds * round to the server
       time.sleep(60)
       for message in self.messagesToSend:
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.connect((message[0], message[1]))
           s.send(message[2])
           s.close()
       global STOP
       STOP = False
       global messagesToSend
       messagesToSend = []


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

    #opening the sk file and extracting the secret key and loading it
    skFile = "sk" + y + ".pem"
    skFile = open(skFile, "r")
    serverPrivateKey = skFile.read()
    serverPrivateKey = load_pem_private_key(serverPrivateKey.encode(), password=None, backend=default_backend())

    #opening socket to every IP and given port
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', serverPort))
    server.listen(300)

    while True:
        # receiving message
        client_socket, client_address = server.accept()
        data = client_socket.recv(16384)

        #code for loading secret key and decrypting cypher text
        plaintext = serverPrivateKey.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #slicing the port, IP and message from decipher message
        nextNodeIP = plaintext[:4]
        nextNodePort = plaintext[4:6]
        nextNodeMessage = plaintext[6:]
        #converting byte message to int
        temp = ""
        for byt in nextNodeIP:
            temp += str(byt) + "."
        nextNodeIP = temp[:-1]
        nextNodePort = int.from_bytes(nextNodePort, byteorder='big')
        #inserting the message to the messages to sent array
        node = [nextNodeIP, nextNodePort, nextNodeMessage]
        messagesToSend.append(node)

        #activates the thread to send the messages in the array every minute
        if STOP == False:
            STOP = True
            thread = myThread(messagesToSend)
            thread.start()


