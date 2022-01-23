##################################################################################
# Este guión generará una clave privada ECC desde un numero arbitrario de 256 bit generado por computadora
# la clave está guardada en un archivo cifrado con AES (protegido con password)
#
# iniciar en el terminal utilizando el siguiente 
# > python ecc_generate.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD>
# <PRIVKEY_PATH>: el camino para generar la clave privada
# <PRIVKEY_PASSWORD>: password para la clave privada
#
#EJEMPLO:
#>python ecc_generate.py keys\privkey.bin password123
#
# SI <PRIVKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA 
##################################################################################
##################################################################################
# this script will generate an ECC private key from a computer generate 256 bit random number
# the key is saved to an AEC encrypted (password protected) file
#
# run at the terminal using the following
# > python ecc_generate.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD>
# <PRIVKEY_PATH>: path to generated private key
# <PRIVKEY_PASSWORD>: password for private key file
#
#EXAMPLE:
#>python ecc_generate.py keys\privkey.bin password123
#
# IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes


if len(argv)==3:
    _, privkey_path, privkey_password = argv
elif len(argv)==2:
    _, privkey_path = argv
    while True:
        privkey_password = getpass.getpass("Input password for encrypting keyfile: ")
        privkey_password = getpass.getpass("Ingresar password para cifrar el archivo de la clave: ")C
        privkey_password_2 = getpass.getpass("Repeat password for encrypting keyfile: ")
        privkey_password_2 = getpass.getpass("Repetir password para cifrar el archivo de la clave: ")
        if privkey_password==privkey_password_2:
            print('\nPasswords match...')
            print('\nPasswords son iguales...')
            break
        else:
            print('\nPasswords do not match...')
            print('\nPasswords no son iguales...')
else:
    print('Wrong number arguments. 1 or 2 expected.')
    print('Numero de argumentos es incorrecto. 1 or 2 esperado.')
    print('>python ecc_generate.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD>')
    print('IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    print('SI <PRIVKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA ')
    exit()

def gen_privKey():
    privKey=eth_keys.keys.PrivateKey(get_random_bytes(32) )
    return privKey

def save_key(key,path,password):
    if type(password)!=bytes:
        password=password.encode()
    encrypted_bytes=ecies.aes_encrypt(key=hashlib.sha256(password).digest(),plain_text=key.to_bytes())
    f=open(path,'wb')
    f.write(encrypted_bytes)
    f.close()
    return encrypted_bytes

#generate key
privKey=gen_privKey()

#generate password protected file
encrypted_bytes=save_key(privKey,privkey_path,privkey_password)

print('Private key generation complete') 
print('Generación de la clave privada está terminada') 
print('Private key encrypted and written to binary file:', privkey_path)
print('La clave privada está cifrada y escrita en un archivo binario:', privkey_path)
print(encrypted_bytes.hex())