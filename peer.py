import select
import errno
import getpass
import sys
import hashlib
import socket
import os

HEADER_LENGTH = 10

IP = socket.gethostbyname(socket.gethostname())

PORT = 1234

PORT2= 1235

ADDRESS = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"


def receive_message(cs):

    try:

        # Get our header which contains message length
        header = cs.recv(HEADER_LENGTH)
        # In case of no data is received, then this will return false
        if not len(header):
            return False
        # Here we are converting header to an int value
        msg_length = int(header.decode('utf-8').strip())
        return {'header': header, 'data': cs.recv(msg_length)}

    except:
        return False
'''
The receive() function receives messages from the client. This function receives the message header
containing the length of the message, and then the actual data. In case, there is no data in the header,
then the function returns false. 
'''
def receive(ip,port):
    my_username = input("Username: ")
    cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cs.connect((IP, PORT))
    cs.setblocking(False)

    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    cs.send(username_header + username)

    while True:

       
        message = input(f'{my_username} > ')

        if message:

            message = message.encode('utf-8')
            header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            cs.send(header + message)

        try:
            while True:

                username_header = cs.recv(HEADER_LENGTH)

                if not len(username_header):
                    print('Connection closed by the server')
                    sys.exit()

                username_length = int(username_header.decode('utf-8').strip())

                username = cs.recv(username_length).decode('utf-8')

                header = cs.recv(HEADER_LENGTH)
                msg_length = int(header.decode('utf-8').strip())
                message = cs.recv(msg_length).decode('utf-8')

                print(f'{username} > {message}')

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:

                print('error: {}'.format(str(e)))
                sys.exit()

            continue

        except Exception as e:
        
            print('error: '.format(str(e)))

            sys.exit()

'''
The send() function sets up server and also listens for incoming connections from clients. This function
takes IP address and port number as input from the user. When a client connects, the function accepts
the connection and adds the client's socket to the list of sockets being monitored for incoming messages. 
The function then receives messages from clients and sends them to all the other connected clients.
'''

def send():
    print(f"New Peer at address has connected.")
    ss = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ss.bind((IP, PORT))

    ss.listen()
    slist = [ss]
    clients = {}

    print(f'Listening for connections on {IP}:{PORT}...')
    slist = [ss]
    clients = {}
    while True:
        read_sockets, _, exception_sockets = select.select(slist, [], slist)
        for nsocket in read_sockets:
        
            if nsocket == ss:
                cs, client_address = ss.accept()
    
                user = receive_message(cs)
    
                if user is False:
                    continue
                slist.append(cs)
    
                clients[cs] = user
    
                print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))
    
            else:

                message = receive_message(nsocket)

                if message is False:
                    print('Closed connection from: {}'.format(clients[nsocket]['data'].decode('utf-8')))

                    slist.remove(nsocket)

                    del clients[nsocket]

                    continue

                user = clients[nsocket]

                print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')

                for cs in clients:

                    if cs != nsocket:

                        cs.send(user['header'] + user['data'] + message['header'] + message['data'])

        for nsocket in exception_sockets:

            slist.remove(nsocket)

            del clients[nsocket]
def listening():
    
    send()

def main():
    op=input("Do you want to receive message from peers:[Y/N]\n>")
    if(op=="Y"):
        i=input("Enter the IP of the node you want to connect to:")
        p=int(input("Enter the port number of the node you want to connect to:"))
        
        password = getpass.getpass("Enter password: ")
        password = password.encode()
        password = hashlib.sha384(password).hexdigest()
        
        if p==1234:
            if password == "0cccd75cf243a7ad2bc51e236670a21a4bc6f1c865e6ba85b4b0e0b941cff187e5cd98f63e2be979c29552c305b2a4e1":
                receive(i,p)
            else:
                print("Wrong Password")
                main()
    else: 
        listening()
if __name__ == "__main__":
    main()