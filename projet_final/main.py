import socket
from tkinter import *
from tkinter import filedialog
import tkinter as tk
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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers

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
    client_key_path="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+user+".key"
    with open(client_key_path, "wb") as f:
     f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    return client_public_key

#######################################################################

####################### generation de cles avec notre RSA###########################
def notre_generation_cles(user):  
    publicKey, privateKey=rsa_fun.generateKey(2048)
    # Créer une instance de RSAPublicNumbers
    public_numbers = RSAPublicNumbers(publicKey[0], publicKey[1])

    # Créer une instance de backend
    backend = default_backend()

    # Créer une instance de RSAPublicKey
    public_key = public_numbers.public_key(backend)
    
    private_numbers=RSAPrivateNumbers(privateKey[0],privateKey[1])
    backend = default_backend()
    private_key=private_numbers.private_key(backend)
    
    os.makedirs("D:/SSI/s2/crypto/projet/projet_final/users/"+ user)
    client_key_path="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+user+".key"
    with open(client_key_path, "wb") as f:
     f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    return public_key

########################################################################
################function pour envoyer le nom de l'utilisateur ##########################
def send_user():
    user=userstr=entryUser.get()
    user= bytes(user, encoding="utf-8")
    user=len(user).to_bytes(4, byteorder="big")+ user
    print(user)
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
   

   # Ouverture du fichier en mode binaire
   with open(FILE_PATH, 'rb') as file:
       # Lecture du fichier par blocs et envoi sur le réseau
       while True:
           # Lecture du prochain bloc de données
           data = file.read(BUFFER_SIZE)
           # Fin de fichier atteinte
           if not data:
               break
           # Envoi des données sur le réseau
           client_socket.sendall(data)

##########################################################

######################## recevoir le certificat##############################
def recv_certificat(user):
    # Réception du nom de fichier
    
    filename ="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+user+".crt"
    
    # Ouverture du fichier en mode binaire pour écriture
    with open(filename, 'wb') as file:
        # Réception des données et écriture dans le fichier
    
    
        # Réception du prochain bloc de données
        data = client_socket.recv(BUFFER_SIZE)
        
        print("received")
        # Fin de fichier atteinte

        # Écriture des données dans le fichier
        file.write(data)
        print("write")
        file.close()
    print(f"Le fichier {filename} a été reçu avec succès.")
def recv_certificat_chat(user,name):
    # Réception du nom de fichier
    
    filename ="D:/SSI/s2/crypto/projet/projet_final/users/"+user+"/"+name+".crt"
    
    # Ouverture du fichier en mode binaire pour écriture
    with open(filename, 'wb') as file:
        # Réception des données et écriture dans le fichier
    
    
        # Réception du prochain bloc de données
        data = client_socket.recv(BUFFER_SIZE)
        
        print("received")
        # Fin de fichier atteinte

        # Écriture des données dans le fichier
        file.write(data)
        print("write")
        file.close()
    print(f"Le fichier {filename} a été reçu avec succès.")

############################################################################
def recv_verif():
    text_v=client_socket.recv(1024).decode()
    labelUserErr.config(text=text_v)
    return text_v
def recv_permission():
    text=client_socket.recv(1024).decode()
    return text
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

   print("cert sent")
   recv_verif()
   cert=recv_certificat_chat(user,"chat")
   text=recv_permission()

   openchat(text,user)

#####################################################
####################### deconnect####################
def decconect():
    fenetreChat.destroy()
    fenetreLogin.destroy()

#####################################################
class TextScrollCombo(ttk.Frame):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

    # ensure a consistent GUI size
        self.grid_propagate(False)
    # implement stretchability
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    # create a Text widget
        self.txt = Text(self)
        self.txt.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

    # create a Scrollbar and associate it with txt
        scrollb = ttk.Scrollbar(self, command=self.txt.yview)
        scrollb.grid(row=0, column=1, sticky='nsew')
        self.txt['yscrollcommand'] = scrollb.set
########################################################

################ envoyer les messages ##############################
def send():
    cert_path="D:/SSI/s2/crypto/projet/projet_final/users/"+name
    message=entryText.get()
    if message!="":
      textk = "You: "+ message  + "\n"
      message=rsa_fun.encryptAndWriteToFile ("chat_increption_chat.txt",cert_path+"/pub_key_partener.txt",message)
      client_socket.sendall(message.encode())
      #affichage dans l'interface
      comboK.txt.insert(END, textk)
      entryText.delete(0, tk.END)
      return message 

##########################################################

################ recevoir les messages ##############################

def recv():
    cert_path="D:/SSI/s2/crypto/projet/projet_final/users/"+name
    while True:
            # Réception des données du serveur
            
            message=rsa_fun.readFromFileAndDecryptmesage (client_socket.recv(1024).decode(),cert_path+"/my_priv_key.txt")
            # Affichage des données reçues
            textk = "Partener: "+ message  + "\n"
            #print("Partener: " + c.recv(1024).decode())
            comboK.txt.insert(END, textk)

############################ RSA ###################################
############################# Extraire la cles publique #################
def extract_pubkey():
  cert_path="D:/SSI/s2/crypto/projet/projet_final/users/"+name
  with open(cert_path+"/chat.crt", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    f.close()
  # Extraire la clé publique
  public_key = cert.public_key() 
    # extraire les nombres premiers p et q de la clé publique
 
  n = public_key.public_numbers().n
  e = public_key.public_numbers().e
  with open(cert_path+"/pub_key_partener.txt", "w") as f:
    f.write('%s,%s,%s' % (2048, n, e))
    f.close()
    
########################################################################

############################# Extraire la cles privé #################
def extract_privkey():
  cert_path="D:/SSI/s2/crypto/projet/projet_final/users/"+name
  
  # Charger la clé privée à partir d'un fichier PEM
  with open(cert_path+"/"+name+".key", 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    f.close()
  # Extraire les nombres privés (d) et publics (n) de la clé privée
  d = private_key.private_numbers().d
  n = private_key.private_numbers().public_numbers.n
  with open(cert_path+"/my_priv_key.txt", "w") as f:
    f.write('%s,%s,%s' % (2048, n, d))
    f.close()
    ################################################################

#############################""""
def openchat(text,user):
    global entryText,comboK,name,fenetreChat
    if(text == 'you can connect'):
        fenetreLogin.withdraw()
        name=user
        fenetreChat = Tk()
        fenetreChat.title(user)
        fenetreChat.configure(width=600, height=600)
        fenetreChat.configure(bg='white')

        labelTitle = Label(fenetreChat, text='SECURE-CHAT', fg='#89b0ae', bg='white')
        labelTitle.config(font=('times', 20, 'bold'))
        labelTitle.place(x=200, y=0)
        extract_privkey()
        extract_pubkey()

        frameChat = Frame(fenetreChat, bg="white")
        frameChat.place(relheight=0.5, relwidth=1, relx=0, rely=0.1)

        textk = "" 

        comboK = TextScrollCombo(frameChat)
        comboK.pack(fill="both", expand=True)
        comboK.config(width=100, height=200)
        comboK.txt.config(undo=True, wrap='word')
        comboK.txt.insert(END, textk)

        frameText = Frame(fenetreChat, bg="white")
        frameText.place(relheight=0.1, relwidth=0.8, relx=0, rely=0.85)

        entryText = Entry(frameText)
        entryText.place(relheight=0.8, relwidth=0.8, relx=0.010, rely=0.1)
        
        buttonSend = Button(frameText, text='Send', borderwidth=1, height=1, width=10, bg='#BEE3DB',command=send) 
        buttonSend.place(relx=0.85, rely=0.2)
        buttonDisconnect = Button(fenetreChat, text='Disconnect', borderwidth=1, height=2, width=10, bg='#BEE3DB',command=decconect) 
        buttonDisconnect.place(x=500, y=20)

        t = threading.Thread(target=recv)
        t.start()

        fenetreChat.mainloop()

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

labelTitle = Label(fenetreLogin, text='SECURE-CHAT', fg='#89b0ae', bg='white')
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

