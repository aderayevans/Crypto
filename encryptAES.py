#!/usr/bin/python3
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import AES
import base64

def encrypt(message, key, key_size=256):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message, 32))

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, 32)

def encryptCBC(message, key, key_size=256):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message, 32))

def decryptCBC(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, 32)

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + '.enc', 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)


key = Random.new().read(AES.block_size)
#key = bytearray.fromhex('6ab9f619a67b90f58d590e466f8b3f33')

iv = Random.new().read(AES.block_size)
#iv = bytearray.fromhex('af7bc4709ae803b616b3b6f161e2b409')
plaintext = ('Quang').encode()
enc = encrypt(plaintext, key)
dec = decrypt(enc, key)

print("Key: ", key.hex())
print("IV: ", iv.hex())
print("Cipher: ", enc.hex())
print("Cipher (base64): ", base64.b64encode(enc))
print("Plain: ", dec.decode())
file = 'D:/Workplace/Crypto/test.txt'
encrypt_file(file, key)
#decrypt_file('test.txt.enc', key)
