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
from datetime import datetime , timedelta
import rsa_fun
import socket
import threading
import os
import signal

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



def register():
    server_IP = '18.224.18.157'
    h_name = 'ca_chat-qt'

    user = entryUser.get()


    key = rsa.generate_private_key(public_exponent= 65537, key_size=2048, backend=default_backend())

    iname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, h_name)])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user)])

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

    cert_path = 'CA/crt/' + user + '.crt'
    key_path = 'CA/key/' + user + '.key'

    with open(cert_path, 'wb') as c:
        c.write(my_cert_pem)

    with open(key_path, 'wb') as k:
        k.write(my_key_pem)

    entryUser.delete(0,END)

def connect():

    user = entryUser.get()
    certname = filedialog.askopenfilename(initialdir='CA/crt/', title="Choose Certificate", filetypes=(("executables","*.crt"), ("allfiles","*.*")))


    def datetime_to_str(date):

        date = str(date)
        date = date.split(' ')
        date[0] = date[0].split('-')
        date[1] = date[1].split(':')

        datestr = date[0][0] + date[0][1] + date[0][2] + date[1][0] + date[1][1] + date[1][2]
        datestr = datestr.split('.')
        datestr = datestr[0]

        return datestr


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

        if (iss == 'ca_chat-qt'):
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


    def verif(cert, user):
        if not check_issuer(cert):
            labelUserErr.config(text='This certificate was not issued by CA')
            return False
        if not check_user(cert,user):
            labelUserErr.config(text='This certificate is not for this user')
            return False
        if not is_valid(cert):
            labelUserErr.config(text='This certificate is expired')
            return False

        return True
    
    def receiving_messages(c):
        while True:
            #print("Partener: " + rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"nour_privkey.txt"))
            message_clair=rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"chat_privkey.txt")
            textk = "Partener: "+ message_clair  + "\n"
            #print("Partener: " + c.recv(1024).decode())
            comboK.txt.insert(END, textk)

    def send():
    
        message=entryText.get()
        message_crypt=rsa_fun.encryptAndWriteToFile ("chat_increption_chat.txt","chat_pubkey.txt",message)
        client.send(message_crypt.encode())

        textk = "You: " + message + "\n"
        comboK.txt.insert(END, textk)
        entryText.delete(0,END)
        pass

    def disconnect():
        
        if choice == 1:
            server.close()
        elif choice == 2:
            client.close()
        
        fenetreLogin.deiconify()
        fenetreChat.destroy()
        fenetreLogin.destroy()

        process = os.getpid()

        os.kill(process,9)
    


    
    

    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open(certname).read()
    )

    if verif(cert,user):
        entryUser.delete(0,END)
        labelUserErr.config(text='')
        fenetreLogin.withdraw()

        HOST = 'localhost'

        Public_key , Private_key=rsa_fun.generateKey(1024)
        Public_partener=None

        choice = role.get()

        fenetreChat = Tk()
        fenetreChat.title("CHAT-QT")
        fenetreChat.configure(width=1800, height=800)
        fenetreChat.configure(bg='white')

        labelTitle = Label(fenetreChat, text='CHAT-QT', fg='#89b0ae', bg='white')
        labelTitle.config(font=('times', 20, 'bold'))
        labelTitle.place(x=600, y=0)


        frameChat = Frame(fenetreChat, bg="white")
        frameChat.place(relheight=0.7, relwidth=1, relx=0, rely=0.1)

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

        buttonSend = Button(frameText, text='Send', borderwidth=1, height=1, width=10, bg='#BEE3DB', command=send) 
        buttonSend.place(relx=0.85, rely=0.2)



        buttonDisconnect = Button(fenetreChat, text='Disconnect', borderwidth=1, height=2, width=10, bg='#BEE3DB', command=disconnect) 
        buttonDisconnect.place(x=1600, y=700)

        if(choice==1):
            server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            server.bind((HOST,4444))
            server.listen()
            client, _ =server.accept()
            public_key_str=('%s,%s,%s' % (1024, Public_key[0], Public_key[1]))
            client.send(public_key_str.encode())
            Public_partener=client.recv(1024)
            fo = open('client_pubkey.txt', 'w')
            fo.write('%s,%s,%s' % (1024, Public_partener[0], Public_partener[1]))
            fo.close()
        elif(choice==2):
            client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((HOST,4444))
            Public_partener=client.recv(1024)
            fo = open('server_pubkey.txt', 'w')
            fo.write('%s,%s,%s' % (1024, Public_partener[0], Public_partener[1]))
            fo.close()
            public_key_str=('%s,%s,%s' % (1024, Public_key[0], Public_key[1]))
            client.send(public_key_str.encode())
        else:
            exit()

        #threading.Thread(target=sending_messages,args=(client,)).start()
        threading.Thread(target=receiving_messages,args=(client,)).start()



        fenetreChat.mainloop()
        
    


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

radroleServer = Radiobutton(fenetreLogin, text='Server', padx=20, variable=role, value=1, bg='white').grid(row=4, column=1)
radroleClient = Radiobutton(fenetreLogin, text='Client', padx=20, variable=role, value=2, bg='white').grid(row=5, column=1)

buttonRegister = Button(fenetreLogin, text='Register', borderwidth=1, height=2, width=10, bg='#BEE3DB',command=register) 
buttonRegister.grid(row=6, column=0, padx=50, pady=30)

buttonConnect = Button(fenetreLogin, text='Connect', borderwidth=1, height=2, width=10, bg='#BEE3DB', command=connect) 
buttonConnect.grid(row=6, column=2, padx=50, pady=30)

fenetreLogin.mainloop()