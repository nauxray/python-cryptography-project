import socket
import hashlib
import uuid

users = {}
check = True

try:
    with open('login/shadow.txt','r') as i:
        for line in i:
            (key,val) = line.split('::')
            users[key] = val
except ValueError:
    print('Credentials file empty, please contact system admin')
    check = False

if check == True:
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('0.0.0.0', 8089))
    print(f'{"":-^40}')
    print(f'{"Login Server is listening...": ^40}')
    print(f'{"":-^40}')
    serversocket.listen(2)
    while True:
        con, address = serversocket.accept()
        print(f'{"Connection received!": ^40}')
        print(f'{"":-^40}')
        
        buf = con.recv(255)
        buf1 = con.recv(255)
        if buf == b'username':
            userinput = buf1.decode()
            if userinput in users:
                print(f'{"Username found in database": ^40}')
                print(f'{"":-^40}')
                con.send(b'found')
                con.close()
                print(f'{"Connection is closed": ^40}')
                print(f'{"":-^40}')
            else:
                print(f'{"Username not found in database": ^40}')
                print(f'{"":-^40}')
                con.send(b'notfound')
                con.close()
                print(f'{"Connection is closed": ^40}')
                print(f'{"":-^40}')

        if buf == b'password':
            pwdinput = buf1.decode()
            realsalt, realpassword = (users[userinput]).split('$$')
            hashcheck = hashlib.sha512(pwdinput.encode() + realsalt.encode()).hexdigest()
            if hashcheck == realpassword:
                print(f'{"Password is correct": ^40}')
                print(f'{"":-^40}')
                con.send(b'correct')
                con.close()
            else:
                print(f'{"Password is wrong": ^40}')
                print(f'{"":-^40}')
                con.send(b'wrong')
                con.close()
