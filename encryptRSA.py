from Crypto.Cipher import PKCS1_OAEP

publickey = ('0E329232EA6D0D73').hex()
encryptor = PKCS1_OAEP.new(publickey)
encrypted = encryptor.encrypt(b'encrypt this message')

key = bytearray.fromhex('0E329232EA6D0D73')
decryptor = PKCS1_OAEP.new(key)
decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))
