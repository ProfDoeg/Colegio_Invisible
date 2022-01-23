##################################################################################
# este guión generará una clave ECC privada o pública utilizando la entrada del teclado
# la clave está guardada en un archivo cifrado con AES (protegido con password)
#
# iniciar en el terminal utilizando el siguiente 
# > python ecc_keyboard.py <KEY_PATH> <KEY_PASSWORD> <KEY_HEX>
# <KEY_PATH>: el camino al archivo de la clave hecho por la entrada del teclado 
# <KEY_PASSWORD>: password para el archivo de la clave 
# <KEY_HEX>: clave hex (64 valores hex para la clave privada y 128 valores hex para la clave pública)
#
#EJEMPLO:
#>python ecc_keyboard.py keys\privkey.bin password123 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#
# SI <KEY_PASSWORD> Y <KEY_HEX> NO ESTáN INCLUIDOS EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA 
##################################################################################
##################################################################################
# this script will generate an ECC private or public key from keyboard input
# the key is saved to an AEC encrypted (password protected) file
#
# run at the terminal using the following
# > python ecc_keyboard.py <KEY_PATH> <KEY_PASSWORD> <KEY_HEX>
# <KEY_PATH>: path to keyboard input key file
# <KEY_PASSWORD>: password for key file
# <KEY_HEX>: hex key (64 hex values for private key and 128 hex values for public key)
#
#EXAMPLE:
#>python ecc_keyboard.py keys\privkey.bin password123 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#
# IF <KEY_PASSWORD> AND <KEY_HEX> ARE NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib
from Crypto.PublicKey import ECC
#from Crypto.Random import get_random_bytes


if len(argv)==4:
    _, key_path,  key_password, key_hex = argv
elif len(argv)==2:
    _, key_path = argv
    while True:
        key_password = getpass.getpass("Input password for encrypting key file:\nIngresar password para cifrar el archivo de la clave:  ")
        key_password_2 = getpass.getpass("Repetir (Repeat): ")
        if key_password==key_password_2:
            print('\nPasswords match...')
            print('\nPasswords son iguales...')
            break
        else:
            print('\nPasswords do not match...')
            print('\nPasswords no son iguales...')
    while True:
        key_hex = getpass.getpass("Input key in hex:\nIngresar la clave hex: ")
        key_hex_2 = getpass.getpass("Repetir (Repeat):")
        if key_hex==key_hex_2:
            print('\nHex keys match...')
            print('\n Claves hex son iguales...')
            break
        else:
            print('\nHex keys do not match...')
            print('\nClaves hex no son iguales...')
else:
    print('Wrong number arguments. 1 or 3 expected.')
    print('Cantidad de argumentos es incorrecto. 1 or 3 esperado.')
    print('>python ecc_keyboard.py <KEY_PATH> <KEY_PASSWORD> <KEY_HEX>')
    print('IF <KEY_PASSWORD> AND <KEY_HEX> ARE NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY')
    print('SI <KEY_PASSWORD> Y <KEY_HEX> NO ESTáN INCLUIDOS EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA')
    exit()


def make_key(keyhex):
    if len(keyhex)==64:
        return eth_keys.keys.PrivateKey( bytes.fromhex(keyhex) ) 
    elif len(keyhex)==128:
        return eth_keys.keys.PublicKey( bytes.fromhex(keyhex) )
    else:
        print('Bad key length: 64 hex for private or 128 hex for public.')
        print('Longitud de la clave es incorrecto. Requiere 64 hex para la clave privada o 128 hex para la clave pública.')
        exit()

def save_key(key,path,password):
    if type(password)!=bytes:
        password=password.encode()
    encrypted_bytes=ecies.aes_encrypt(key=hashlib.sha256(password).digest(),plain_text=key.to_bytes())
    f=open(path,'wb')
    f.write(encrypted_bytes)
    f.close()
    return encrypted_bytes

#make key
key=make_key(key_hex)

#generate password protected file
encrypted_bytes=save_key(key,key_path,key_password)

print('Key generation complete') 
print('Generación de la clave está hecho') 
print('La clave esta cifrada y escrita en un archivo binario:\nKey encrypted and written to binary file:', key_path)
print(encrypted_bytes.hex())