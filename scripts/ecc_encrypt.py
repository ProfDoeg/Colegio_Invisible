##################################################################################
# este guión utiliza ECIES para cifrar usando una clave pública ECC y una clave session de AES 
#
# iniciar en el terminal utilizando el siguiente
# > python ecc_encrypt.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>
# <PUBKEY_PATH>: el camino para llegar a la clave pública ECC protegida por una password
# <PUBKEY_PASSWORD>: password para la clave pública ECC
# <PLAINTEXT_PATH>: el camino al archivo que será cifrado
# <CIPHERTEXT_PATH>: el camino al nuevo archivo cifrado

#EJEMPLO:
#>python ecc_encrypt.py keys\pubkey.bin pass1 message2enc.bin cipher.enc
#
# SI <PUBKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA 
##################################################################################
# this script employs ECIES encription using a password protected ECC public key and AES session key
#
# run at the terminal using the following
# > python ecc_encrypt.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>
# <PUBKEY_PATH>: path to password protected ECC public key
# <PUBKEY_PASSWORD>: password for ECC public key
# <PLAINTEXT_PATH>: path to file that will be encrypted
# <CIPHERTEXT_PATH>: path to newly generated encrypted file
#
#EXAMPLE:
#>python ecc_encrypt.py keys\pubkey.bin pass1 message2enc.bin cipher.enc
#
# IF <PUBKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib


if len(argv)==5:
    _, pubkey_path, pubkey_password, plaintext_path, ciphertext_path = argv
elif len(argv)==4:
    _, pubkey_path, plaintext_path, ciphertext_path  = argv
    pubkey_password = getpass.getpass("Input password for public key file: ")
    pubkey_password = getpass.getpass("Ingresar password para acceder al archivo de la clave pública: ")
else:
    print('Incorrect number of arguments. 3 or 4 expected')
    print('Cantidad de argumentos es incorrecto. 3 o 4 esperado')
    print('> python ecc_encrypt.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <PLAINTEXT_PATH> <CIPHERTEXT_PATH>')
    print('IF <PUBKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    print('SI <PUBKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA ')
    exit()

def import_pubKey(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),
                                     cipher_text=f.read())
    pubKey=eth_keys.keys.PublicKey(decrypted_bytes)
    f.close()
    return pubKey

def encrypt_message(pubKey,message):
    if type(message)!=bytes:
        message=message.encode()
    return ecies.encrypt(pubKey.to_hex(),message)

def encrypt_file(pubkey_path,pubkey_password,plaintext_path,ciphertext_path):
    try:
        f_in=open(plaintext_path,'rb')
        message=f_in.read()
        f_in.close()
    except():
        f_in=open(plaintext_path,'r')
        message=f_in.read()
        f_in.close()
    try:
        pubKey=import_pubKey(pubkey_path,pubkey_password)
    except Exception as E:
        print(E)
        print('key import failed :(')
        print('la importación de la clave ha fallado :(')
        exit()
    ciphertext=encrypt_message(pubKey,message)
    f_out=open(ciphertext_path,'wb')
    f_out.write(ciphertext)
    f_out.close()

try:
    encrypt_file(pubkey_path,pubkey_password,plaintext_path,ciphertext_path)
    print('Success:',plaintext_path, 'encryption complete using', pubkey_path)
    print('Exito:',plaintext_path, 'cifrado con éxito usando', pubkey_path)
    print('Written to:', ciphertext_path)
    print('Escrito a:', ciphertext_path)
except Exception as E:
    print('Fail whale',E)
    print('Fallada',E)

