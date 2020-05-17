from Crypto.Cipher import AES
from Crypto import Random

def encrypt_file(file_name, output_file, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
        
    cipher = AES.new(key, AES.MODE_CFB, iv)
    enc_data = cipher.encrypt(plaintext)

    enc_file = open(output_file, 'wb')
    enc_file.write(enc_data)
    enc_file.close()

def decrypt_file(file_name, output_file, key):
    enc_file2 = open(file_name, 'rb')
    enc_data2 = enc_file2.read()
    enc_file2.close()

    decipher = AES.new(key, AES.MODE_CFB, iv)
    plain_data = decipher.decrypt(enc_data2)

    output_file = open(output_file, 'wb')
    output_file.write(plain_data)
    output_file.close()
    
key = Random.new().read(AES.block_size)
iv = Random.new().read(AES.block_size)
encrypt_file('input.jpg', 'jpg.enc',  key)
decrypt_file('jpg.enc', 'output.jpg', key)
    

    
