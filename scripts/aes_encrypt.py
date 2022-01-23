##################################################################################
# este guión va a cifrar un archivo utilizando AES para crear un archivo protegido con password
#
# iniciar en el terminal utilizando el siguiente
# > python aes_encrypt.py <PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>
# <PASSWORD>: password usado para generar la clave AES
# <PLAINTEXT_PATH>: el camino al archivo que estará cifrado
# <CIPHERTEXT_PATH>: el camino para llegar al archivo cifrado que acaba de generar
#
#EJEMPLO:
#>python aes_encrypt.py Password123 file2enc.jpg cipher.aes
#
# SI <PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA 
##################################################################################
##################################################################################
# this script will encrypt a file using AES to create a password protected file
# the AES key is the SHA256 hash of the user provided password
#
# run at the terminal using the following
# > python aes_encrypt.py <PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>
# <PASSWORD>: password used to generate AES key
# <PLAINTEXT_PATH>: path to file that will be encrypted
# <CIPHERTEXT_PATH>: path to newly generated encrypted file
#
#EXAMPLE:
#>python aes_encrypt.py Password123 file2enc.jpg cipher.aes
#
# IF <PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib


if len(argv)==4:
    _, password, plaintext_path, ciphertext_path = argv
elif len(argv)==3:
    _, plaintext_path, ciphertext_path  = argv
    while True:
        password = getpass.getpass("Ingresar password para cifrar:\nInput password for encryption: ")
        password_2 = getpass.getpass("Repetir (Repeat): ")
        if password==password_2:
            print('\nPasswords match...')
            print('\nPasswords son iguales...')
            break
        else:
            print('\nPasswords do not match...')
            print('\nPasswords no son iguales...')
else:
    print('Incorrect number of arguments. 2 or 3 expected')
    print('Cantidad de argumentos es incorrecto. 2 o 3 esperado')
    print('> python aes_encrypt.py <PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>')
    print('IF <PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    print('SI <PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA')
    exit()

def aes_encrypt_file(plainfile_path,cipherfile_path,password):
    plain = open(plainfile_path,'rb').read()
    bytekey = hashlib.sha256( password.encode() ).digest()
    cipher = ecies.aes_encrypt(key=bytekey,plain_text=plain)
    open(cipherfile_path,'wb').write(cipher)



aes_encrypt_file(plaintext_path,ciphertext_path,password)
print('Éxito (Success):',plaintext_path, 'AES cifrado está terminado (encryption complete)')
print('Escrito a (Written to):', ciphertext_path)

