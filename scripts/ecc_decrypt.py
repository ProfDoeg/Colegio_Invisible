##################################################################################
# este guión generará un archivo binario decifrado desde un archivo ECIES ciphertext
# y la adecuada clave privada protegido por password
#
# iniciar en el terminal utilizando el siguiente
# > python ecc_decrypt.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <CIPHERTEXT_PATH> <PLAINTEXT_PATH>
# <PRIVKEY_PATH>: el camino a la clave privada protegido por password
# <PRIVKEY_PASSWORD>: password para la clave privada
# <CIPHERTEXT_PATH>: el camino al archivo cifrado
# <PLAINTEXT_PATH>: el camino para llegar al archivo que acaba de estar decifrado
#
#EJEMPLO:
#>python ecc_decrypt.py privkey.bin pass1 cipher.enc dec_text.bin
#
# SI <PRIVKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA 
##################################################################################
# this script generates a decrypted binary file from an ECIES ciphertext file
# and the appropriate password protected private key
#
# run at the terminal using the following
# > python ecc_decrypt.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <CIPHERTEXT_PATH> <PLAINTEXT_PATH>
# <PRIVKEY_PATH>: path to password protected private key 
# <PRIVKEY_PASSWORD>: password to private key
# <CIPHERTEXT_PATH>: path to encrypted file
# <PLAINTEXT_PATH>: path to newly generated decrypted file
#
#EXAMPLE:
#>python ecc_decrypt.py privkey.bin pass1 cipher.enc dec_text.bin
#
# IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib

if len(argv)==5:
    _, privkey_path, privkey_password, ciphertext_path, plaintext_path = argv
elif len(argv)==4:
    _, privkey_path, ciphertext_path, plaintext_path = argv
    privkey_password = getpass.getpass("Input password for keyfile: ")
    privkey_password = getpass.getpass("Ingresar password para el archivo de la clave: ")
else:
    print('Incorrect number of arguments. 3 or 4 expected')
    print('Cantidad de argumentos es incorrecto. 3 or 4 esperado')
    print('> python ecc_decrypt.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <CIPHERTEXT_PATH> <PLAINTEXT_PATH>')
    print('IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    print('SI <PRIVKEY_PASSWORD> NO ESTÁ INCLUIDO EL USUARIO ESTARÁ APUNTADO A INGRESARLO DE UNA MANERA SEGURA ')
    exit()

#import private key
def import_privKey(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),
                                     cipher_text=f.read())
    privKey=eth_keys.keys.PrivateKey(decrypted_bytes)
    f.close()
    return privKey

def decrypt_message(privKey,ciphertext):
    if type(ciphertext)!=bytes:
        ciphertext=cyphertext.encode()
    return ecies.decrypt(privKey.to_hex(),ciphertext)

def decrypt_file(privkey_path,privkey_password,ciphertext_path,plaintext_path):
    f_in=open(ciphertext_path,'rb')
    message=f_in.read()
    f_in.close()
    try:
        privKey=import_privKey(privkey_path,privkey_password)
    except Exception as E:
        print(E)
        print('key import failed :(')
        print('la importación de la clave ha fallado:(')
        exit()
    try:
        plaintext=decrypt_message(privKey,message)
    except Exception as E:
        print(E)
        print('decryption failed :(')
        print('no decifrado exitosamente:(')
        exit()
    f_out=open(plaintext_path,'wb')
    f_out.write(plaintext)
    f_out.close()


try:
    decrypt_file(privkey_path,privkey_password,ciphertext_path,plaintext_path)
    print('Success:',ciphertext_path, 'decryption complete using', privkey_path)
    print('Exito:',ciphertext_path, 'decifrado usando', privkey_path)
    print('Written to:', plaintext_path)
    print('Escrito a:', plaintext_path)
except Exception as E:
    print('Fail whale',E)
    print('Fallada',E)

