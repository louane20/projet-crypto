import socket

HOST = '10.0.0.16'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost' , 9999))

server.listen()

while True:

    client , addr = server.accept()

    msg = client.recv(1024)

    if msg == b"<RQST>":
        print("req")
        import sender
    else:
        file = open('thekey.key','wb')

        key = msg

        file.write(key)

        file.close()
        client.close()
        #server.close()