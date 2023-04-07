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
from OpenSSL import crypto
import rsa_fun
import socket
import threading
import os
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, load_privatekey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

ca_path = "D:\SSI\s2\crypto\projet\projet_final\CA/my_ca/my_ca.crt"
ca_key_path= "D:\SSI\s2\crypto\projet\projet_final\CA/my_ca/my_ca.key"

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
def verif(cert_path,user):
    
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
        print('This certificate was not issued by CA')
        return False
    if not check_issuer(cert):
        print('This certificate was not issued by CA')
        return False
    if not check_user(cert,user):
        print('This certificate is not for this user')
        return False
    if not is_valid(cert):
        print('This certificate is expired')
        return False
    print('This certificate is good')
    return True
user="houda"
cert_path= "D:\SSI\s2\crypto\projet\projet_final/CA/crt/"+user+".crt"
##############################################################################

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
pub,priv=rsa_fun.generateKey(2048)
public_numbers =  RSAPublicNumbers(pub[0], pub[1])
#print(pub[0])
#print(pub[1])
public_key = RSAPublicKey.public_numbers(public_numbers)
user='mohamed'
create_certificat(public_key,user)


#verif(cert_path,user)