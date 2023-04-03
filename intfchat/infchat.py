from tkinter import *
import tkinter.ttk as ttk
import socket
import threading
import rsa_fun

HOST = 'localhost'

Public_key , Private_key=rsa_fun.generateKey(1024)
Public_partener=None
#print(Public_key , Private_key)

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

def mainloop():
    fenetreChat.mainloop()

def sending_messages(c):
    while True:
        message=entryText.get()
        message_crypt=rsa_fun.encryptAndWriteToFile ("chat_increption_chat.txt","chat_pubkey.txt",message)
        c.send(message_crypt.encode())
        
        textk = "You: " + message  + "\n"
        comboK.txt.insert(END, textk)


def receiving_messages(c):
    while True:
        #print("Partener: " + rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"nour_privkey.txt"))
        message_clair=rsa_fun.readFromFileAndDecryptmesage (c.recv(1024).decode(),"chat_privkey.txt")
        textk = "Partener: "+ message_clair  + "\n"
        #print("Partener: " + c.recv(1024).decode())
        comboK.txt.insert(END, textk)

def disconnect():
    fenetreChat.deiconify()
    fenetreChat.destroy()



def send():
    
    message=entryText.get()
    message_crypt=rsa_fun.encryptAndWriteToFile ("chat_increption_chat.txt","chat_pubkey.txt",message)
    client.send(message_crypt.encode())
    
    textk = "You: " + message + "\n"
    comboK.txt.insert(END, textk)
    entryText.delete(0,END)
    pass

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

choice = 2

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

