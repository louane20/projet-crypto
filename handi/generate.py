from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Charger le certificat de l'AC et sa clé privée
with open("my_ca.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

with open("my_ca.key", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Créer un nouveau certificat pour le client
client_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

client_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"nom_du_client")
    ])
).issuer_name(ca_cert.subject).public_key(
    client_key.public_key()
).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=365)
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
    critical=False
).add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
    critical=False
).sign(
    private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend()
)

# Enregistrer la clé privée et le certificat du client
with open("client.crt", "wb") as f:
    f.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))

with open("client.key", "wb") as f:
    f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
