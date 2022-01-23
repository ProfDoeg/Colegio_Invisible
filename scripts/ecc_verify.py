##################################################################################
# este guión verifica la integridad de una firma ECDSA de un archivo, el archivo
# y la clave pública ECC que está relacionada
#
# iniciar en el terminal utilizando el siguiente 
# > python ecc_verify.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <FILE_PATH> <SIGNATURE_PATH> 
# <PUBKEY_PATH>: el camino a la clave pública que está protegido por password
# <PUBKEY_PASSWORD>: password para la clave pública
# <FILE_PATH>: el camino al archivo que estaba firmado
# <SIGNATURE_PATH>: el camino al archivo firmado
#
#EJEMPLO:
#>python python ecc_verify.py keys\pubkey.bin pass1 note.txt signature.sig
#
# SI <PUBKEY_PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA
##################################################################################
##################################################################################
# this script verifies the integrity of an ECDSA signature of a file, the file,
# and associated ECC public key
#
# run at the terminal using the following
# > python ecc_verify.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <FILE_PATH> <SIGNATURE_PATH> 
# <PUBKEY_PATH>: path of password protected public key
# <PUBKEY_PASSWORD>: password for public key
# <FILE_PATH>: path of file that was signed
# <SIGNATURE_PATH>: path of signature file
#
#EXAMPLE:
#>python python ecc_verify.py keys\pubkey.bin pass1 note.txt signature.sig
#
# IF <PUBKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib


if len(argv)==5:
    _, pubkey_path, pubkey_password, file_path, signature_path = argv
elif len(argv)==4:
    _, pubkey_path, file_path, signature_path  = argv
    pubkey_password = getpass.getpass("Input password for public key file: ")
    pubkey_password = getpass.getpass("Ingresar password para acceder al archivo de la clave pública: ")

else:
    print('Incorrect number of arguments. 3 or 4 expected')
    print('Cantidad de argumentos es incorrecto. 3 or 4 esperado')
    print('> python ecc_verify.py <PUBKEY_PATH> <PUBKEY_PASSWORD> <FILE_PATH> <SIGNATURE_PATH>')
    print('IF <PUBKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    print('SI <PUBKEY_PASSWORD> NO ESTá INCLUIDO EL USUARIO ESTARá APUNTADO A INGRESARLO DE UNA MANERA SEGURA')
    exit()

#import private key
def import_pubKey(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),cipher_text=f.read())
    pubKey=eth_keys.keys.PublicKey(decrypted_bytes)
    f.close()
    return pubKey

def verify_message(pubKey,signature,message):
    if type(message)!=bytes:
        message=message.encode()
    if type(signature)==bytes:
        signature=eth_keys.datatypes.Signature(signature)
    return signature.verify_msg(message,pubKey)

def verify_file(pubkey_path, pubkey_password, file_path, signature_path):
    try:
        pubKey=import_pubKey(pubkey_path,pubkey_password)
    except Exception as E:
        print(E)
        print('Error importing public key')
        print('Error con la importación de la clave pública')
        exit()
    message=open(file_path,'rb').read()
    signature=open(signature_path,'rb').read()
    try:    
        return verify_message(pubKey,signature,message)
    except Exception as E:
        print(E)
        print('Error verifying signature')
        print('Error con la verificación de la firma')
        exit()

if verify_file(pubkey_path, pubkey_password, file_path, signature_path):
    print('Success:',pubkey_path, file_path,'and', signature_path, 'agree')
    print('Exito:',pubkey_path, file_path,'y', signature_path, 'están de acuerdo')
    print('Signature is valid')
    print('Firma válida')
else:
    print('Invalid:',pubkey_path, file_path,'and', signature_path, 'do NOT agree')
    print('Inválido:',pubkey_path, file_path,'y', signature_path, 'NO están de acuerdo')