import os
import socket
import time

HOST = '10.0.0.41'

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost' , 9998))

file = open('thekey.key','rb')
file_size = os.path.getsize('thekey.key')

client.send("thekey.key".encode())
time.sleep(3)
client.send(str(file_size).encode())
time.sleep(3)

data = file.read()
client.sendall(data)
client.send(b"<END>")

file.close()
client.close()