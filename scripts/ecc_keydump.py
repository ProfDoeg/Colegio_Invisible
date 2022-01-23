##################################################################################
# este guión tirará los contenidos del keyfile (el archivo de la clave)
#
# iniciar en el terminal utilizando el siguiente
# > python ecc_address_extract.py <PUBKEY_PATH> <PUBKEY_PASSWORD>
# <KEY_PATH>: el camino al archivo de la clave pública
# <KEY_PASSWORD>: password para el archivo de la clave
#
#EJEMPLO:
#>python ecc_keydump.py key/pubkey.bin password123
#
# SI <KEY_PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA
#################################################################################
##################################################################################
# this script will dump the keyfile contents
#
# run at the terminal using the following
# > python ecc_address_extract.py <PUBKEY_PATH> <PUBKEY_PASSWORD>
# <KEY_PATH>: path to public key file
# <KEY_PASSWORD>: password for key file
#
#EXAMPLE:
#>python ecc_keydump.py key/pubkey.bin password123
#
# IF <KEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY
#################################################################################

from sys import argv
import getpass
import os
import ecies
import eth_keys
import hashlib
import cryptos

if len(argv)==3:
    _, key_path, key_password = argv
elif len(argv)==2:
    _, key_path  = argv
    key_password = getpass.getpass("Input password for key file: ")
    key_password = getpass.getpass("Ingresar password para el archivo de la clave: ")
else:
    print('Incorrect number of arguments. 1 or 2 expected')
    print('Cantidad de argumentos es incorrecto. 1 or 2 esperada')
    print('> python ecc_keydump.py <KEY_PATH> <KEY_PASSWORD>')
    print('IF <KEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER THEM SECURELY')
    print('SI <KEY_PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA')
    exit()

def print_Key(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),cipher_text=f.read())
    print(decrypted_bytes.hex())

print_Key(key_path,key_password)


