import hashlib
import uuid

users = {}
check = True

def createuser():
    print(f'{"Creating new user...": ^40}')
    print(f'{"":-^40}')

    username = input('Enter your username here\n>> ')
    print(f'{"":-^40}')
    password = input('Input password here\n>> ')
    print(f'{"":-^40}')
    salt = uuid.uuid4().hex
    hashed_password = hashlib.sha512(password.encode() + salt.encode()).hexdigest()
    writetext = '\n%s::%s$$%s' % (username, salt, hashed_password)
    credentials = open('login/shadow.txt', 'a')
    credentials.write(writetext)
    print(f'{"User created!": ^40}')
    print(f'{"":-^40}')
    
try:
    with open('login/shadow.txt','r') as i:
        for line in i:
            (key,val) = line.split('::')
            users[key] = val
except ValueError:
    print(f'{"Credentials file empty, please contact system admin": ^40}')
    check = False

if check == True:
    print(f'{"":-^40}')
    print(f'{"Please login before": ^40}')
    print(f'{"creating new account...": ^40}')

    print(f'{"":-^40}')
    userinput = input('Username: ')
    if userinput in users:
        print(f'{"":-^40}')
        print(f'{"Username found": ^40}')
        print(f'{"":-^40}')
        pwdinput = input('Password: ')
        print(f'{"":-^40}')
        realsalt, realpassword = (users[userinput]).split('$$')
        hashcheck = hashlib.sha512(pwdinput.encode() + realsalt.encode()).hexdigest()
        if hashcheck == realpassword:
            print(f'{"Password is correct": ^40}')
            print(f'{"":-^40}')
            createuser()
        else:
            print(f'{"Password is wrong": ^40}')
            print(f'{"":-^40}')
            print(f'{"Closing Program...": ^40}')
            print(f'{"":-^40}')
    else:
        print(f'{"":-^40}')
        print(f'{"Username not found": ^40}')
        print(f'{"":-^40}')
        print(f'{"Closing Program...": ^40}')
        print(f'{"":-^40}')
        pass
