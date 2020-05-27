from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_2
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA1, SHA256
# -*- coding: utf8 -*-
from tkinter import *
import tkinter.ttk
from tkinter import filedialog

def generate_key(file_contains_public, file_contains_private, mode, size):
    key = RSA.generate(size)
    with open(file_contains_private, 'wb') as file:
        file.write(key.exportKey(mode))
    with open(file_contains_public, 'wb') as file:
        file.write(key.publickey().exportKey(mode))
def encrypt_rsa(plaintext, file_contains_key, mode):
    with open(file_contains_key, 'rb') as file:
        key = RSA.importKey(file.read())
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(plaintext)
def decrypt_rsa(ciphertext, file_contains_key, mode):
    with open(file_contains_key, 'rb') as file:
        key = RSA.importKey(file.read())
    plaintext = PKCS1_v1_5.new(key)
    return plaintext.decrypt(ciphertext,'sentinel')
def verify_sign(data_to_verify, file_contains_signature, file_contains_key):
    with open(file_contains_signature, 'rb') as file:
        signature = file.read()
    key = RSA.importKey(open(file_contains_key, "rb").read())
    verifier = PKCS1_v1_5_2.new(key)
    hashingtext = SHA256.new(data_to_verify)
    print(hashingtext.hexdigest().encode())
    print(signature)
    if verifier.verify(hashingtext, signature):
        print ("OK")
    else:
        print ("Invalid")
def sign_digital(hashingtext, file_contains_key):
    with open(file_contains_key, 'rb') as file:
        key = RSA.importKey(file.read())
    cipher = PKCS1_v1_5_2.new(key)
    signature = cipher.sign(hashingtext)
    print(signature)
    with open('signature.sig', 'wb') as file:
        file.write(signature)

#plaintext = 'Huynh Truong Minh Quang'.encode()
#hashingtext = SHA1.new(plaintext)
with open('input.jpg', 'rb') as file:
    plaintext = file.read()
#print(hashingtext.hexdigest().encode())

#Mode = ['DER', 'PEM']
#generate_key('rsapub.' + Mode[1], 'rsapri.' + Mode[1], Mode[1], 1024)
#enc = encrypt_rsa(plaintext, 'rsapub.' + Mode[1], Mode[1])
#plain = enc.hex()
#print(plain)
#dec = decrypt_rsa(bytearray.fromhex(plain), 'rsapri.' + Mode[1], Mode[1])
#print(dec.decode())

#sign_digital(hashingtext, 'rsapri.der')
verify_sign(plaintext, 'firstsig.sig', 'rsapub.der')


