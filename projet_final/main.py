import socket
from tkinter import *
from tkinter import filedialog
import tkinter.ttk as ttk
from datetime import datetime , timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL.crypto
from OpenSSL import crypto
from datetime import datetime , timedelta
import rsa_fun
import socket
import threading
import os
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
######################################## FUNCTION #######################################

########################## generation des cles ################
# generation des cles pour le client
def generation_cles(user):
    
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    client_public_key=client_key.public_key()
    
    os.makedirs("D:/SSI/s2/crypto/projet/projet_final/users/"+ user)
    client_key_path="D:\SSI\s2\crypto\projet\projet_final/users/"+user+"/"+user+".key"
    with open(client_key_path, "wb") as f:
     f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    return client_public_key

########################################################################
################function pour envoyer le nom de l'utilisateur ##########################
def send_user():
    user=userstr=entryUser.get()
    user= bytes(user, encoding="utf-8")
    user=len(user).to_bytes(4, byteorder="big")+ user
    client_socket.sendall(user)
    
    return userstr 
###################################################################

################function pour envoyer la cles publique de l'utilisateur ##########################
def send_key_public(user):
    
    
    public_key=generation_cles(user)
    
    pub_key_bytes = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    client_socket.sendall(pub_key_bytes)
    return public_key 
###################################################################

################function pour envoyer le cetificat ##########################

def send_certif(user):    
    
# Chemin vers le fichier à envoyer FILE_PATH
# Taille du buffer pour l'envoi des données
   BUFFER_SIZE = 4096
   FILE_PATH="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+user+".crt"  
   # Envoi du nom de fichier au serveur
   #filename = FILE_PATH.split("/")[-1]
   #client_socket.sendall(filename.encode())

   # Ouverture du fichier en mode binaire
   with open(FILE_PATH, 'rb') as file:
       # Lecture du fichier par blocs et envoi sur le réseau
        data = file.read(BUFFER_SIZE)
        client_socket.sendall(data)
        file.close()

#########################################################

######################## recevoir le certificat##############################


def recv_certificat(user):
    # Réception du nom de fichier
    #filename = client_socket.recv(BUFFER_SIZE).decode()
    
    filename ="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+user+".crt"
    # Ouverture du fichier en mode binaire pour écriture
    with open(filename, 'wb') as file:
        # Réception des données et écriture dans le fichier
        data = client_socket.recv(BUFFER_SIZE)
        file.write(data)
        file.close()

    print(f"Le fichier {filename} a été reçu avec succès.")
    return filename

###################################################################
############################## recevoir le message de verification########################

def recv_verif():
    text_v=client_socket.recv(1024).decode()
    labelUserErr.config(text=text_v)

##################### registration ###############################
def registration():
    dis='1'    
    client_socket.sendall(dis.encode())
    user=send_user()
    send_key_public(user)
    recv_certificat(user)
#######################################################################
############## connexion##########################
def connexion():
   dis='2'    
   client_socket.sendall(dis.encode())
   user=send_user()
   send_certif(user)
   recv_verif()
#####################################################

# Adresse IP et numéro de port du serveur
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345
# Taille maximale du buffer pour la réception des données
BUFFER_SIZE = 4096
# Création du socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connexion au serveur
client_socket.connect((SERVER_IP, SERVER_PORT))
#registration()
#connexion()


fenetreLogin = Tk()
fenetreLogin.title("LOGIN")
fenetreLogin.configure(width=1800, height=800)
fenetreLogin.configure(bg='white')

labelTitle = Label(fenetreLogin, text='CHAT-QT', fg='#89b0ae', bg='white')
labelTitle.config(font=('times', 40, 'bold'))
labelTitle.grid(row=0, column=1, padx=50, pady=30)

labelUser = Label(fenetreLogin, text="User", font=("Arial", 10), bg='white', fg='#555B6E').grid(row=1, column=1)
entryUser = Entry(fenetreLogin)


entryUser.grid(row=2, column=1, padx=50, pady=30)


labelUserErr = Label(fenetreLogin, text=" ", font=("Arial", 10), bg='white', fg='red')
labelUserErr.grid(row=3, column=1)

role = IntVar()



buttonRegister = Button(fenetreLogin, text='Register', borderwidth=1, height=2, width=10, bg='#BEE3DB',command=registration) 
buttonRegister.grid(row=6, column=0, padx=50, pady=30)

buttonConnect = Button(fenetreLogin, text='Connect', borderwidth=1, height=2, width=10, bg='#BEE3DB',command=connexion) 
buttonConnect.grid(row=6, column=2, padx=50, pady=30)

fenetreLogin.mainloop()


# Fermeture de la connexion avec le serveur
client_socket.close()

