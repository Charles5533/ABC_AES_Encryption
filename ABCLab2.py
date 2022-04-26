#Encryption

from Crypto.Cipher import AES
import hashlib

password = "secretpassword".encode()
key = hashlib.sha256 (password).digest()

mode = AES.MODE_CBC
IV =  'This is an IV256'

def pad_message():
    while len (message) % 16 != 0:
    message = message  + " "
    return message

cipher = AES.new(key, mode, IV)

message = "This message should be encrypted "
padded_message = pad_message (message)

encrypted_message = cipher.encrypt (padded_message)

print (encrypted_message)


 # Decryption
from Crypto.Cipher import AES
import hashlib

password =  b'secretpassword'
key = hashlib.sha256 (password).digest()
mode = AES.MODE_CBC
IV = 'This is an IV256'

cipher = AES.new (key, mode, IV)

decrypted_text = cipher.decrypt (encrypted_message)

print (decrypted_text.rstrip().decode())
