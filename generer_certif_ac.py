import OpenSSL.crypto
import os

# Générer une paire de clés pour l'AC
key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

# Créer une demande de certificat pour l'AC
req = OpenSSL.crypto.X509Req()
subject = req.get_subject()
subject.CN = "My CA"
req.set_pubkey(key)
req.sign(key, "sha256")

# Créer un certificat autosigné pour l'AC
cert = OpenSSL.crypto.X509()
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(31536000) # Durée de validité d'un an
cert.set_issuer(subject)
cert.set_subject(subject)
cert.set_pubkey(key)
cert.set_version(2)
cert.add_extensions([
    OpenSSL.crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    OpenSSL.crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
    OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
])
cert.sign(key, "sha256")

# Écrire la clé privée et le certificat autosigné dans des fichiers PEM
os.makedirs("D:\SSI\s2\crypto\projet\projet-crypto\intfchat/CA/my_ca", exist_ok=True)
with open("D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.key", "wb") as f:
    f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
with open("D:\SSI\s2\crypto\projet\projet-crypto\intfchat\CA/my_ca/my_ca.crt", "wb") as f:
    f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
