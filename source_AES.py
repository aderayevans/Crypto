#!/usr/bin/python3
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import AES
import binascii
import base64

def encryptECB(message, key, key_size=256):
    cipher = AES.new(key, AES.MODE_ECB)
    message = pad(message, AES.block_size)
    return cipher.encrypt(message)

def decryptECB(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

def encryptCBC(message, key, key_size=256):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = pad(message, AES.block_size)
    return cipher.encrypt(message)

def decryptCBC(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encryptCBC(plaintext, key)
    with open(file_name + '.enc', 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decryptCBC(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)


#key = Random.new().read(AES.block_size)
#key = bytearray.fromhex('6ab9f619a67b90f58d590e466f8b3f33')
key = '1234567890123456'.encode()
#iv = Random.new().read(AES.block_size)
iv = bytearray.fromhex('af7bc4709ae803b616b3b6f161e2b409')
plaintext = 'Huynh Truong Minh Quang'.encode()
enc = encryptCBC(plaintext, key)
dec = decryptCBC(enc, key)

print("Key: ", key.hex())
print("IV: ", iv.hex())
print("Cipher: ", enc.hex())
print("Cipher (base64): ", base64.b64encode(enc))
print("Plain: ", dec.decode())
print(dec.hex())

file = 'input.jpg'
encrypt_file(file, key)
decrypt_file('input.jpg.enc', key)

##decrypt from hex
ciphertext = bytearray.fromhex('0bd77995a9e5f022ac46fad44e815d91ce20adaef47eb6563844ea77dc55bf63')

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
plaintext = unpad(plaintext, AES.block_size)

print(plaintext.hex())
print(plaintext.decode())