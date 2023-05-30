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
import OpenSSL.crypto
import time
from OpenSSL import crypto
import rsa_fun
import socket
import threading
import os
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, load_privatekey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_public_key


###################################################    FUNCTION  #######################################

###############  generation de certificatpour les users  #######################
def create_certificat(client_public_key,user):
        # Charger le certificat de l'AC et sa clé privée
    with open(ca_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    #creation du certificat du client     
    client_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, f"{user}")
    ])
    ).issuer_name(ca_cert.subject).public_key(
        client_public_key
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_public_key),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    ).sign(
        private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
         
    client_path="D:\SSI\s2\crypto\projet\projet_final/CA/crt/"+user+".crt"    
    # Enregistrer la clé privée et le certificat du client
    with open(client_path, "wb") as f:
        f.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))

###################################################################

################ function pour envoyer le cetificat ##########################
def send_certif(user,client_socket):    
    
# Chemin vers le fichier à envoyer FILE_PATH
# Taille du buffer pour l'envoi des données
   BUFFER_SIZE = 4096
   FILE_PATH="D:\SSI\s2\crypto\projet\projet_final/CA/crt/"+user+".crt"    
   # Envoi du nom de fichier au serveur
   #filename = FILE_PATH.split("/")[-1]
   #client_socket.sendall(filename.encode())

   # Ouverture du fichier en mode binaire
   with open(FILE_PATH, 'rb') as file:
       # Lecture du fichier par blocs et envoi sur le réseau
        data = file.read(BUFFER_SIZE)
        client_socket.sendall(data)
        file.close()
        
##########################################################
################function pour recevoir le nom de l'utilisateur ##########################
 
def recv_user(client_socket):
    len=client_socket.recv(4)
    len = int.from_bytes(len, byteorder='big')
    print(len)
    user=client_socket.recv(len)
    user=str(user, encoding="utf-8") 
    print(user)
    return user


##############################################################################

################function pour recevoir la cles publique de l'utilisateur ##########################
def recv_key_public(user,client_socket):
    
    pub_key_bytes=client_socket.recv(BUFFER_SIZE)

    public_key = load_pem_public_key(pub_key_bytes, backend=default_backend())
    pub_key = serialization.load_pem_public_key(pub_key_bytes)
    
    return pub_key
    
    
###################################################################

######################## recevoir le certificat##############################
def recv_certificat(user,client_socket):
    # Réception du nom de fichier
    #filename = client_socket.recv(BUFFER_SIZE).decode()
    
    filename="D:/SSI/s2/crypto/projet/projet_final/CA/crt_envoyer/"+user+".crt"
    # Ouverture du fichier en mode binaire pour écriture
    with open(filename, 'wb') as file:
        # Réception des données et écriture dans le fichier
        data = client_socket.recv(BUFFER_SIZE)
        file.write(data)
        file.close()
        

    print(f"Le fichier {filename} a été reçu avec succès.")
    return filename
############################################################################


######################## verification de la signature ##################
def check_signature(cert_path):



   # Load the CA private key
   with open(ca_key_path, "rb") as f:
       ca_key_data = f.read()
       ca_key = load_privatekey(FILETYPE_PEM, ca_key_data)
   
   # Load the CA certificate
   with open(ca_path, 'rb') as f:
       ca_cert_data = f.read()
       ca_cert = load_pem_x509_certificate(ca_cert_data, default_backend())
   
   # Load the certificate to verify
   with open(cert_path, 'rb') as f:
       cert_data = f.read()
       cert = load_pem_x509_certificate(cert_data, default_backend())
   
   # Extract the TBS bytes from the certificate
   tbs_bytes = cert.tbs_certificate_bytes
   
   # Extract the signature from the certificate
   signature = cert.signature
   
   # Verify the signature using the CA public key
   try:
       ca_pub_key = ca_cert.public_key()
       ca_pub_key.verify(
           signature,
           tbs_bytes,
           padding.PKCS1v15(),
           cert.signature_hash_algorithm,
       )
       return True
   except Exception as e:
       return False

#################################################################

######################## Verification complete de certificat #######################
def verif(cert_path,user,client_socket):
    
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open(cert_path).read()
    )
    
    def notAfter_to_str(notAfter):

        notAfter = str(notAfter)
        notAfter = notAfter[2:-2]

        return notAfter
    
    

    def is_valid(cert):

        now = datetime.utcnow()
        now = datetime_to_str(now)
        date_exp = cert.get_notAfter()
        date_exp = notAfter_to_str(date_exp)

        if (now >= date_exp):
            return False
        else:
            return True
    
    def check_issuer(cert):

        issuer = str(cert.get_issuer())
        issuer = issuer.split('/')
        iss = issuer[1].split("'")
        iss = iss[0]
        iss = iss[3:]

        if (iss == 'My CA'):
            return True
        else:
            return False
    def check_user(cert,user):

        owner = str(cert.get_subject())
        owner = owner.split('/')
        own = owner[1].split("'")
        own = own[0]
        own = own[3:]

        if (own == user):
            return True
        else:
            return False
        
    def datetime_to_str(date):

        date = str(date)
        date = date.split(' ')
        date[0] = date[0].split('-')
        date[1] = date[1].split(':')

        datestr = date[0][0] + date[0][1] + date[0][2] + date[1][0] + date[1][1] + date[1][2]
        datestr = datestr.split('.')
        datestr = datestr[0]

        return datestr
    if not check_signature(cert_path):
            text='This certificate was not issued by CA'
            
    elif not check_issuer(cert):
            text='This certificate was not issued by CA'
            
    elif not check_user(cert,user):
            text='This certificate is not for this user'
            
    elif not is_valid(cert):
            text='This certificate is expired'
            
    else:
            text='This certificate is good wait for another client'
    client_socket.sendall(text.encode())
    return text

######################################################################################

################################## registration ##################################
def registration(client_socket):
    user=recv_user(client_socket)
    print(f"inscription de {user} en court")
    pub_key=recv_key_public(user,client_socket)
    create_certificat(pub_key,user)
    send_certif(user,client_socket)
    print(f"fin d'inscription de {user} ")
    return("fin")

#####################################################################################
################################## connexion ##################################
def connexion(client_socket):

    user=recv_user(client_socket)
    print(f"connexion de {user} en court")
    cert=recv_certificat(user,client_socket)
    text=verif(cert,user,client_socket)
    openchatpermission(user,client_socket,text) 
    descution(client_socket) 
    
#####################################################################################
def openchatpermission(user,client_socket,text):
        print("here")
        if (text == "This certificate is good wait for another client"):
            clients.append(client_socket)
            print("there")
            while True:
                if (len(clients) == 2):
                    for client in clients:
                           if client_socket != client:
                               print("hehe")
                               
                               print(user)
                               send_certif(user,client)
                               time.sleep(2.4)                 
                    break
        text="you can connect"
        client_socket.sendall(text.encode())
def handle_client(client_socket,client_address):
    while True:
    
# Attente d'une connexion entrante
   
        dis=client_socket.recv(256).decode()

        print(dis)
        if dis=="1":
            registration(client_socket)
        else :
            connexion(client_socket)


########################## discution ##############################
    
def descution(client_socket):

    # Boucle principale de la fonction
    while True:
   
            # Réception des données du client
            data = client_socket.recv(1024).decode()


            # Transmission des données à tous les autres clients
            for client in clients:
                if client != client_socket:
                    client.sendall(data.encode())

        
########################################################
        
########################################################

ca_path = "D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.crt"
ca_key_path= "D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.key"

# Adresse IP et numéro de port du serveur
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345

# Taille maximale du buffer pour la réception des données
BUFFER_SIZE = 4096

# Création du socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Attribution de l'adresse IP et du port au socket
server_socket.bind((SERVER_IP, SERVER_PORT))

# Mise en attente de connexions entrantes
server_socket.listen()

print(f"Serveur en écoute sur {SERVER_IP}:{SERVER_PORT}...")


clients=[]
client_socket, client_address = server_socket.accept()
print(f"Connexion établie avec {client_address[0]}:{client_address[1]}")
thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
thread.start()

client_socket2, client_address2 = server_socket.accept()
print(f"Connexion établie avec {client_address2[0]}:{client_address2[1]}")
thread2 = threading.Thread(target=handle_client, args=(client_socket2, client_address2))
thread2.start()


