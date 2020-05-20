from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES
import base64

def padtext(text):
    while len(text) % 8 != 0:
        text += ' '
    return text
def encryptECB(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message, DES.block_size))

def decryptECB(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)

def encryptCBC(message, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(message, DES.block_size))

def decryptCBC(ciphertext, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)

#key = Random.new().read(DES.block_size)
key = bytearray.fromhex('0E329232EA6D0D73')
#key = 'key'
#key = padtext(key).encode()

#iv = Random.new().read(DES.block_size)
iv = bytearray.fromhex('538aaa095e71e27b')

plaintext = bytearray.fromhex('8787878787878787')
#plaintext = '8787878787878787'
#plaintext =  plaintext.encode()

enc = encryptECB(plaintext, key)
dec = decryptECB(enc, key)
#enc = encryptCBC(plaintext, key)
#dec = decryptCBC(enc, key)
print("Key: ", key.hex())
#print("iv: ", iv.hex())
print("Cipher: ", enc.hex())
print("Cipher (base64): ", base64.b64encode(enc))
print("Plain: ", dec.hex())
#print("Plain: ", dec.decode())
