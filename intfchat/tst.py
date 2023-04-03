import os
from tkinter import filedialog


user = 'tst'

cert_path = 'CA/crt/' + user + '.crt'
key_path = 'CA/key/' + user + '.key'
with open(cert_path, 'wb') as c:
    c.write(b'my_cert_pem')

with open(key_path, 'wb') as k:
    k.write(b'my_key_pem')

filename = filedialog.askopenfilename(initialdir='CA/crt/', title="Open File", filetypes=(("executables","*.txt"), ("allfiles","*.*")))