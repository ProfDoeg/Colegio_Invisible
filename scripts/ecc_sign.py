##################################################################################
# this script uses ECDSA to sign a file with a password protected private key
# it generates a signature binary file
#
# run at the terminal using the following
# > python ecc_sign.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <FILE_PATH> <SIGNATURE_PATH> 
# <PRIVKEY_PATH>: path of password protected private key
# <PRIVKEY_PASSWORD>: password for private key
# <FILE_PATH>: path of file to be signed
# <SIGNATURE_PATH>: path of newly generated signature file
#
#EXAMPLE:
#>python python ecc_sign.py keys\privkey.bin pass1 note.txt signature.sig
#
# IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib


if len(argv)==5:
    _, privkey_path, privkey_password, file_path, signature_path = argv
elif len(argv)==4:
    _, privkey_path, file_path, signature_path  = argv
    privkey_password = getpass.getpass("Input password for private key file: ")
else:
    print('Incorrect number of arguments. 3 or 4 expected')
    print('> python ecc_sign.py <PRIVKEY_PATH> <PRIVKEY_PASSWORD> <FILE_PATH> <SIGNATURE_PATH>')
    print('IF <PRIVKEY_PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    exit()

#import private key
def import_privKey(path,password):
    if type(password)!=bytes:
        password=password.encode()
    f=open(path,'rb')
    decrypted_bytes=ecies.aes_decrypt(key=hashlib.sha256(password).digest(),cipher_text=f.read())
    privKey=eth_keys.keys.PrivateKey(decrypted_bytes)
    f.close()
    return privKey

def sign_message(privKey,message):
    if type(message)!=bytes:
        message=message.encode()
    signature= privKey.sign_msg(message)
    return signature.to_bytes()

def sign_file(privkey_path, privkey_password, file_path, signature_path):
    try:
        privKey=import_privKey(privkey_path,privkey_password)
    except Exception as E:
        print(E)
        print('Error importing private key')
        exit()
    f_in=open(file_path,'rb')
    message=f_in.read()
    f_in.close()
    signature=sign_message(privKey,message)
    f_out=open(signature_path,'wb')
    f_out.write(signature)
    f_out.close()
    return signature.hex()

try:
    signature_hex=sign_file(privkey_path, privkey_password, file_path, signature_path)
    print('Success:',file_path, 'signature complete using', privkey_path)
    print('Written to:', signature_path)
    print(signature_hex)
except Exception as E:
    print('Fail whale',E)