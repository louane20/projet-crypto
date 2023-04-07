import socket
import threading
import rsa_fun


#Public_key , Private_key=rsa_fun.generateKey(1024)
#Public_partener=None
#print(Public_key , Private_key)

choice=input('Bonsoir si tu veux etre le serveur tape 1 et si tu veux etre le client tape 2 :')

if(choice=='1'):
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind(("192.168.1.7",4444))
    server.listen()
    
    client, _ =server.accept()
    #client.send()
elif(choice=='2'):
    client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.1.7",4444))
else:
    exit()
    
def sending_messages(c):
    while True:
        message=input("")
        message_crypt=rsa_fun.encryptAndWriteToFile ("nour_increption_chat.txt","nour_pubkey.txt",message)
        c.send(message_crypt.encode())
        
        print("You: " + message)


def receiving_messages(c):
    while True:
        #print("Partener: " + rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"nour_privkey.txt"))
        message_clair=rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"nour_privkey.txt")
        print("Partener: "+ message_clair )
        #print("Partener: " + c.recv(1024).decode())

threading.Thread(target=sending_messages,args=(client,)).start()
threading.Thread(target=receiving_messages,args=(client,)).start()