##################################################################################
# este guión generará un SHA256 hash de lo que está ingresado
#
# inicia en el terminal usando el siguiente 
# > python sha_256.py <FILE_PATH> 
# <FILE_PATH>: el camino al archivo 
#
#EJEMPLO:
#>python sha_256.py files/file_to_hash.bin
#
##################################################################################
##################################################################################
# this script will generate an SHA256 hash of input
#
# run at the terminal using the following
# > python sha_256.py <FILE_PATH> 
# <FILE_PATH>: path to file
#
#EXAMPLE:
#>python sha_256.py files/file_to_hash.bin
#
##################################################################################

from sys import argv
import hashlib


if len(argv)==2:
    _, file_path= argv
elif len(argv)!=2:
    print('Wrong number arguments. 1 expected.')
    print('Cantidad de argumentos es incorrecto. 1 esperado.')
    print('> python sha_256.py <FILE_PATH> ')
    exit()


def sha256_file(path):
  bytestring = open(path,'rb').read()
  return hashlib.sha256( bytestring ).hexdigest()

#generate sha256 hash
file_hash=sha256_file(file_path)

print('Hashing complete') 
print('Hashing terminado')
print('SHA256 of :', file_path)
print('SHA256 de :', file_path)
print(file_hash)