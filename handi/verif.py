from OpenSSL.crypto import load_certificate, FILETYPE_PEM, load_privatekey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

cert_path = "D:\SSI\s2\crypto\projet\projet-crypto\intfchat/CA/crt/nour.crt"

def check_signature(cert_path):

   ca_path = "D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.crt"
   ca_key_path= "D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.key"

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


print(check_signature(cert_path))