from datetime import datetime , timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


server_IP = '18.224.18.157'
h_name = 'ca_server'


key = rsa.generate_private_key(public_exponent= 65537, key_size=2048, backend=default_backend())

iname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, h_name)])
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'youmn')])

alt_names = [x509.DNSName(h_name)]
alt_names.append(x509.DNSName(server_IP))

basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
now = datetime.utcnow()

cert = (
    x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(iname)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=5))
        .add_extension(basic_contraints,True)
        .add_extension(x509.SubjectAlternativeName(alt_names),False)
        .sign(key, hashes.SHA256(), default_backend())
)

my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
my_key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

with open('youmn.crt', 'wb') as c:
    c.write(my_cert_pem)

with open('youmn.key', 'wb') as k:
    k.write(my_key_pem)

print(cert.not_valid_after)