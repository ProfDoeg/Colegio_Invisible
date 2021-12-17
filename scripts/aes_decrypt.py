##################################################################################
# this script will decrypt an AES password protected file
# the AES key is the SHA256 hash of the user provided password
#
# run at the terminal using the following
# > python aes_decrypt.py <PASSWORD> <CIPHERTEXT_PATH> <PLAINTEXT_PATH> 
# <PASSWORD>: password used to generate AES key
# <CIPHERTEXT_PATH>: path to encrypted file that will be decrypted
# <PLAINTEXT_PATH>: path to newly generated decrypted file 
# 
#
#EXAMPLE:
#>python aes_decrypt.py Password123 cipher.aes dec_file.jpg
#
# IF <PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY
##################################################################################

from sys import argv
import getpass
import ecies
import eth_keys
import hashlib


if len(argv)==4:
    _, password, ciphertext_path, plaintext_path = argv
elif len(argv)==3:
    _, ciphertext_path, plaintext_path   = argv
    password = getpass.getpass("Input password for decryption: ")
else:
    print('Incorrect number of arguments. 2 or 3 expected')
    print('> python aes_decrypt.py <PASSWORD> <CIPHERTEXT_PATH> <PLAINTEXT_PATH> ')
    print('IF <PASSWORD> IS NOT INCLUDED USER WILL BE PROMPTED TO ENTER IT SECURELY')
    exit()

def aes_decrypt_file(cipherfile_path,extractfile_path,password):
    cipher = open(cipherfile_path,'rb').read()
    bytekey = hashlib.sha256( password.encode() ).digest()
    extract = ecies.aes_decrypt(key=bytekey,cipher_text=cipher)
    open(extractfile_path,'wb').write(extract)

try:
    aes_decrypt_file(ciphertext_path,plaintext_path,password)
    print('Success:',ciphertext_path, 'decryption complete' )
    print('Written to:', plaintext_path)
except Exception as E:
    print('Decryption failed',E)
