from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES
import base64

def encryptECB(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    message = pad(message, DES.block_size)
    return cipher.encrypt(message)

def decryptECB(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, DES.block_size)

def encryptCBC(message, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    message = pad(message, DES.block_size)
    return cipher.encrypt(message)

def decryptCBC(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, DES.block_size)

#key = Random.new().read(DES.block_size)
##convert hex to bytes
key = bytearray.fromhex('0e329232ea6d0d73')
##convert string to bytes
#key = 'key'
#key = padtext(key).encode('utf-8')

#iv = Random.new().read(DES.block_size)
iv = bytearray.fromhex('538aaa095e71e27b')

##convert hex to bytes
#plaintext = bytearray.fromhex('8787878787878787')
##convert string to bytes
plaintext = 'Huynh Truong Minh Quang'
plaintext =  plaintext.encode()

enc = encryptECB(plaintext, key)
dec = decryptECB(enc, key)
#enc = encryptCBC(plaintext, key, iv)
##decrypt from bytes
#dec = decryptCBC(enc, key, iv)
##convert bytes to hex()
print("Key: ", key.hex())
print("iv: ", iv.hex())
print("Cipher: ", enc.hex())
##convert bytes to base64
print("Cipher (base64): ", base64.b64encode(enc))
##convert bytes to string (using when plaintext is string)
print("Plain: ", dec.decode())

##decrypt from hex
ciphertext = bytearray.fromhex('a7a926cccdd6ee146fd90527ec113503a571d977e9a1349c')
cipher = DES.new(key, DES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(plaintext.decode())
