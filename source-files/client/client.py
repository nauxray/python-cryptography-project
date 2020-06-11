import sys,socket,xlsxwriter,time
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad

HOST = 'localhost'
PORT = 8888
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "server/menu.xlsx"
return_file = "server/day_end.csv"
# for AES encryption
BLOCK_SIZE = 16
keysize = 32

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

if login() == True:

    # first connection - get menu

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
        my_socket.connect((HOST, PORT))
        print(f'{"":-^40}')
        print(f'{"Connected!": ^40}')
        print(f'{"":-^40}')
        my_socket.sendall(cmd_GET_MENU)
        
        # generating RSA key pair
        print(f'{"Generating RSA key pair...": ^40}') 
        aes_rsa_keypair = RSA.generate(2048)
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')

        # exporting public key for AES encryption
        print(f'{"Exporting the public key...": ^40}')
        AESpubkey = aes_rsa_keypair.publickey().exportKey()
        try:
            open("../deployment-files/AESpublickey.pem","wb").write(AESpubkey)
            print(f'{"Done!": ^40}')
        except:
            print(f'{"Oops! Failed to export the public key": ^40}')
            print(f'{"":-^40}')
            sys.exit(-1)

        key = my_socket.recv(8192)       # receives encrypted AES key
        time.sleep(3)
        data = my_socket.recv(4096)      # receives encrypted menu
        
        print(f'{"":-^40}')
        print(f'{"Received menu!": ^40}')
        print(f'{"":-^40}')
        print(f'{"Decrypting menu...": ^40}')
        
        # decrypting AES key to decrypt menu
        cipher = PKCS1_OAEP.new(aes_rsa_keypair)
        decrypted_key = cipher.decrypt(key)

        my_cipher = AES.new(decrypted_key,AES.MODE_ECB)
        decrypted_menu = unpad(my_cipher.decrypt(data),BLOCK_SIZE)
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')
        print(f'{"Processing menu...": ^40}')
        
        menu_bytes = decrypted_menu.decode()
        menu_list = []
        menu_list = menu_bytes.split("\n")
        # opening menu.xlsx
        workbook = xlsxwriter.Workbook(menu_file)
        menuws = workbook.add_worksheet("menu")

        for i in range(0,len(menu_list)):
            menuws.write(i,0,menu_list[i])
        # protecting worksheet from modifications by unauthorized persons
        menuws.protect("password")
        workbook.close()

        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')
        my_socket.close()
        print(f'{"Connection closed": ^40}')
        print(f'{"":-^40}')
        print("\n")

    # second connection - end day

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:

        # connect to server
        my_socket.connect((HOST, PORT))
        print(f'{"":-^40}')
        print(f'{"Connected!": ^40}')
        print(f'{"":-^40}')
        out_file = open(return_file, "rb")
        file_bytes = out_file.read(1024)

        my_socket.sendall(cmd_END_DAY)

        # Generating AES key
        print(f'{"Generating AES key...": ^40}')
        AESkey = get_random_bytes(keysize)
        print(f'{"Done!": ^40}') 
        print(f'{"":-^40}')
        print(f'{"Encrypting data...": ^40}') 
        AEScipher = AES.new(AESkey, AES.MODE_ECB)
        encrypted_closing = AEScipher.encrypt(pad(file_bytes, BLOCK_SIZE))
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')
        print(f'{"Encrypting AES key...": ^40}')
        time.sleep(9)
        # importing server public key to encrypt AES key
        try:
            pubkey2_bytes = open("../deployment-files/AESpublickey2.pem","r").read()
            pubkey2 = RSA.import_key(pubkey2_bytes)
        except:
            print(f'{"Oops! Failed to import the public key": ^40}')
            print(f'{"":-^40}')
            sys.exit(-1)

        # Encrypt key
        cipher = PKCS1_OAEP.new(pubkey2)
        encrypted_key = cipher.encrypt(AESkey)
        print(f'{"Done!": ^40}') 
        my_socket.send(encrypted_key)

        time.sleep(3)
        
        print(f'{"":-^40}')
        print(f'{"Sent ENCRYPTED AES KEY": ^40}')
        print(f'{"":-^40}')
        my_socket.send(encrypted_closing)
        print(f'{"Sent CLOSING-DAY INFORMATION": ^40}')

        # generate RSA key pair for digital signature
        print(f'{"":-^40}')
        print(f'{"Generating RSA key pair...": ^40}')
        DSrsakey_pair = RSA.generate(2048)
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')

        # exporting public key
        print(f'{"Exporting the public key...": ^40}')
        DSpubkey = DSrsakey_pair.publickey().exportKey()

        try:
            open("../deployment-files/DSpublickey.pem","wb").write(DSpubkey)
            print(f'{"Done!": ^40}')
        except:
            print(f'{"Oops! Failed to export the public key": ^40}')
            print(f'{"":-^40}')
            sys.exit(-1)

        # generating digest 
        print(f'{"":-^40}')
        print(f'{"Generating SHA256 hash...": ^40}')
        digest = SHA256.new(file_bytes)
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')

        # generating signer
        signer = pkcs1_15.new(DSrsakey_pair)

        # signing digest
        print(f'{"Signing digest...": ^40}')
        signature = signer.sign(digest)
        print(f'{"Done!": ^40}')
        print(f'{"":-^40}')

        # time.sleep(3)
        my_socket.sendall(signature)    # send signature
        print(f'{"Sent DIGITAL SIGNATURE": ^40}')
        print(f'{"":-^40}')

        # reset file_bytes to be empty
        file_bytes = out_file.read(1024)
        out_file.close()
        my_socket.close()
        print(f'{"Connection closed": ^40}')
        print(f'{"":-^40}')
        print("\n")