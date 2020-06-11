import socket,datetime,time,sys
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "client/menu_today.txt"
default_save_base = "result-"
# for AES encryption
BLOCK_SIZE = 16
keysize = 32

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection(conn, ip, MAX_BUFFER_SIZE)
    conn.close()
    print('Connection ' + ip + ':' + port + " ended")
    print(f'{"":-^40}')
    print("\n")

def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)

    while net_bytes != b'':
        if blk_count == 0:
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd:  
                src_file = open(default_menu,"rb")
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE) 

                    if read_bytes == b'':
                        break
                    # generating AES key to encrypt menu
                    print(f'{"":-^40}')
                    print(f'{"Generating AES key...": ^40}') 
                    key = get_random_bytes(keysize)
                    print(f'{"Done!": ^40}') 
                    print(f'{"":-^40}')
                    print(f'{"Encrypting data...": ^40}') 
                    cipher = AES.new(key,AES.MODE_ECB)
                    encrypted_menu = cipher.encrypt(pad(read_bytes,BLOCK_SIZE))
                    print(f'{"Done!": ^40}')
                    print(f'{"":-^40}')
                    # import client public key to encrypt AES key
                    print(f'{"Encrypting AES key...": ^40}')
                    time.sleep(10)
                    pubkey_bytes = open("../deployment-files/AESpublickey.pem","r").read()
                    pubkey = RSA.import_key(pubkey_bytes)
                    cipher = PKCS1_OAEP.new(pubkey)
                    encrypted_key = cipher.encrypt(key)
                    print(f'{"Done!": ^40}')
                    print(f'{"":-^40}')
                    conn.send(encrypted_key)
                    time.sleep(3)
                    conn.send(encrypted_menu) 
                    # sending menu_today.txt data to client
                src_file.close()
                print(f'{"Processed SEND menu": ^40}') 
                print(f'{"":-^40}')
                return
            elif cmd_END_DAY in usr_cmd: 

                # generating RSA key pair
                print(f'{"":-^40}')
                print(f'{"Generating RSA key pair...": ^40}') 
                aes_rsa_keypair = RSA.generate(2048)
                print(f'{"Done!": ^40}')
                print(f'{"":-^40}')

                # exporting public key for AES encryption
                print(f'{"Exporting the public key...": ^40}')
                AESpubkey = aes_rsa_keypair.publickey().exportKey()
                try:
                    open("../deployment-files/AESpublickey2.pem","wb").write(AESpubkey)
                    print(f'{"Done!": ^40}')
                except:
                    print(f'{"Oops! Failed to export the public key": ^40}')
                    print(f'{"":-^40}')
                    sys.exit(-1)

                # receive key and closing info
                time.sleep(3)
                closing_key = conn.recv(8192)
                time.sleep(3)
                closing_info = conn.recv(4096)

                # decrypting key and closing info
                closing_cipher = PKCS1_OAEP.new(aes_rsa_keypair)
                decrypt_closekey = closing_cipher.decrypt(closing_key)
                endday_cipher = AES.new(decrypt_closekey, AES.MODE_ECB)
                decrypted_closing = unpad(endday_cipher.decrypt(closing_info),BLOCK_SIZE) 

                time.sleep(7)

                # importing public key for digital signature
                print(f'{"":-^40}')
                print(f'{"Getting public key...": ^40}')
                DSpubkey_bytes = open("../deployment-files/DSpublickey.pem","r").read()
                DSpubkey = RSA.import_key(DSpubkey_bytes)
                print(f'{"Done!": ^40}')
                print(f'{"":-^40}')
                
                print(f'{"Verifying the Signature...": ^40}')
                print(f'{"":-^40}')
                verifier = pkcs1_15.new(DSpubkey)

                try:
                    time.sleep(3)
                    signature = conn.recv(9126)
                    # generating digest 
                    digest = SHA256.new(decrypted_closing)
                    # verifying signature
                    verifier.verify(digest,signature)
                    print(f'{"The signature is valid!": ^40}')
                    print(f'{"":-^40}')
                    now = datetime.datetime.now()
                    filename = "../source-files/results/" + default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
                    dest_file = open(filename,"wb")
                    dest_file.write(decrypted_closing)
                except:
                    print(f'{"Oh no! The signature is invalid!": ^40}')
                    print(f'{"":-^40}')
                blk_count += 1
        else: 
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file.close()
    print(f'{"Processed CLOSING": ^40}') 
    print(f'{"":-^40}')


def login():
    while True:
        clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsocket.connect(('localhost', 8089))
        print(f'{"":-^40}')
        print(f'{"LOGIN": ^40}')
        print(f'{"":-^40}')
        username = input('Please enter your username:\n>> ')
        print(f'{"":-^40}')
        clientsocket.send(b'username')
        clientsocket.send(username.encode())
        buf = clientsocket.recv(255)
        if buf == b'found':
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsocket.connect(('localhost', 8089))
            password = input('Please enter your password:\n>> ')
            print(f'{"":-^40}')
            clientsocket.send(b'password')
            clientsocket.send(password.encode())
            buf1 = clientsocket.recv(255)
            if buf1 == b'correct':
                print(f'{"Logged in successfully!": ^40}')
                print(f'{"Program will start now...": ^40}')
                print(f'{"":-^40}')
                print("\n")
                check = 1
                return True
            else:
                print(f'{"":-^40}')
                print(f'{"Incorrect password": ^40}')
                print(f'{"Please try again": ^40}')
                print(f'{"":-^40}')
                return False
        else:
            print(f'{"":-^40}')
            print(f'{"Username not found": ^40}')
            print(f'{"Disconnecting...": ^40}')
            print(f'{"":-^40}')
            return False

def start_server():
    import socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f'{"":-^40}')
    print(f'{"Socket created": ^40}')
    print(f'{"":-^40}')

    try:
        soc.bind(("localhost", 8888))
        print(f'{"Socket bind complete": ^40}')
        print(f'{"":-^40}')

    except socket.error as msg:
        import sys
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    # Start listening on socket, max 10 connections at a time
    soc.listen(10)
    print(f'{"Socket now listening...": ^40}')

    # for handling task in separate jobs we need threading
    from threading import Thread

    # this will make an infinite loop needed for 
    # not reseting server for every client
    while True:
        conn, addr = soc.accept()
        ip, port = str(addr[0]), str(addr[1])
        print(f'{"":-^40}')
        print('Accepting connection from ' + ip + ':' + port)
        print(f'{"":-^40}')
        print("\n")
        try:
            Thread(target=client_thread, args=(conn, ip, port)).start()
        except:
            print("Terible error!")
            import traceback
            traceback.print_exc()
    soc.close()

if login() == True:
    start_server()  