from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES

def encrypt(message, key, key_size=256):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message, 32))

def decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, 32)

def encryptCBC(message, key, key_size=256):
    iv = Random.new().read(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decryptCBC(ciphertext, key):
    iv = ciphertext[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[DES.block_size:])
    return plaintext.rstrip(b'\0')

key = Random.new().read(DES.block_size)
plaintext = "Hello world !"
plaintext =  plaintext.encode()
enc = encrypt(plaintext, key)
dec = decrypt(enc, key)

print("Key: ", key.hex())
print("Cipher: ", enc.hex())
print("Plain: ", dec.decode())
