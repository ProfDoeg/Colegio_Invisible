##################################################################################
# este guión extraerá una clave pública ECC desde un archivo cifrado con AES que contiene la clave privada (el archivo protegido por password)
# la clave pública estará escrita a un archivo protegido/cifrado con AES que contiene la clave pública 
#
# iniciar en el terminal utilizando el siguiente 
# > python ecc_pubkey_extract.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <PUBKEY_PATH> <PUBKEY_PASSWORD> 
# <PRIVKEY_PATH>: el camino al archivo de la clave privada 
# <PRIVKEY_PASSWORD>: password para el archivo que contiene la clave privada
# <PUBKEY_PATH>: el camino al archivo nuevamente generado de la clave pública
# <PUBKEY_PASSWORD>: password para el archivo nuevamente generado de la clave pública
#
#EJEMPLO:
#>python ecc_pubkey_extract.py key/privkey.bin pass1 key/pubkey.bin pass2
#
# SI <PRIVKEY_PASSWORD> Y <PUBKEY_PASSWORD> NO ESTáN INCLUIDOS EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA
##################################################################################
##################################################################################
# this script will extract an ECC public key from an AES encrypted (password protected) private key file
# the public key will be written to an AES encrypted (password protected) public key file
#
# run at the terminal using the following
# > python ecc_pubkey_extract.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <PUBKEY_PATH> <PUBKEY_PASSWORD> 
# <PRIVKEY_PATH>: path to private key file
# <PRIVKEY_PASSWORD>: password for private key file
# <PUBKEY_PATH>: path to newly generated public key file
# <PUBKEY_PASSWORD>: password for newly generated public key file
#
#EXAMPLE:
#>python ecc_pubkey_extract.py key/privkey.bin pass1 key/pubkey.bin pass2
#
# IF <PRIVKEY_PASSWORD> AND <PUBKEY_PASSWORD> ARE NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib
from Crypto.PublicKey import ECC


if len(argv)==5:
    _, privkey_path, privkey_password, pubkey_path, pubkey_password = argv
elif len(argv)==3:
    _, privkey_path, pubkey_path = argv[:3]
    privkey_password = getpass.getpass("Input password for private key file:\nIngresar password para acceder al archivo del la clave privada:")


    while True:
        pubkey_password = getpass.getpass("Input password for public key file:\nIngresar password para acceder al archivo del la clave pública: ")
        pubkey_password_2 = getpass.getpass("Repetir (Repeat): ")
        if pubkey_password==pubkey_password_2:
            print('\nPasswords match...')
            print('\nPasswords son iguales...')
            break
        else:
            print('\nPasswords do not match...')
            print('\nPasswords no son iguales...')
else:
    print('Incorrect number of arguments. 2 or 4 expected')
    print('Cantidad de argumentos es incorrecto. 2 or 4 esperado')
    print('> python ecc_pubkey_extract.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <PUBKEY_PATH> <PUBKEY_PASSWORD>')
    print('IF <PRIVKEY_PASSWORD> AND <PUBKEY_PASSWORD> ARE NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY')
    print('SI <PRIVKEY_PASSWORD> Y <PUBKEY_PASSWORD> NO ESTáN INCLUIDOS EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA')
    exit()

def import_privKey(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),cipher_text=f.read())
    privKey=eth_keys.keys.PrivateKey(decrypted_bytes)
    f.close()
    return privKey

def get_pubKey(privKey):
    return eth_keys.keys.private_key_to_public_key(privKey)

def save_key(key,path,password):
    if type(password)!=bytes:
        password=password.encode()
    encrypted_bytes=ecies.aes_encrypt(key=hashlib.sha256(password).digest(),plain_text=key.to_bytes())
    f=open(path,'wb')
    f.write(encrypted_bytes)
    f.close()
    return encrypted_bytes


try:
    privKey=import_privKey(privkey_path,privkey_password)
except Exception as E:
    print(E)
    if type(E)==ValueError:
        print('Password incorrecto')
    exit()

pubKey=get_pubKey(privKey)
encrypted_bytes=save_key(pubKey,pubkey_path,pubkey_password)

print('Extracción de la clave pública terminada desde\n(Completed public key extraction from):', privkey_path) 
print('La clave pública está cifrada y escrita en archivo binario\n(Public key encrypted and written to binary file):', pubkey_path)
print(encrypted_bytes.hex())