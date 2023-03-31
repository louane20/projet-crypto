import socket
import threading

choice=input('Bonsoir si tu veux etre le serveur tape 1 et si tu veux etre le client tape 2 :')

if(choice=='1'):
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind(("192.168.43.201",4444))
    server.listen()
    
    client, _ =server.accept()
elif(choice=='2'):
    client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.43.201",4444))
else:
    exit()
    
def sending_messages(c):
    while True:
        message=input("")
        c.send(message.encode())
        print("You: " + message)


def receiving_messages(c):
    while True:
        print("Partener: " + c.recv(1024).decode())


threading.Thread(target=sending_messages,args=(client,)).start()
threading.Thread(target=receiving_messages,args=(client,)).start()