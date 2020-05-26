from Crypto.Hash import SHA256, MD5, SHA1, SHA224, SHA384, SHA512

def hashing(func, str):
    if func == 0:
        result = MD5.new(str)
        return result.hexdigest()
    if func == 1:
        result = SHA1.new(str)
        return result.hexdigest()
    if func == 2:
        return SHA256.new(str).hexdigest()
    if func == 3:
        result = SHA224.new(str)
        return result.hexdigest()
    if func == 4:
        result = SHA384.new(str)
        return result.hexdigest()
    if func == 5:
        result = SHA512.new(str)
        return result.hexdigest()
str = "Quang"
#hashing('sha256', str.encode())
print(hashing(0, str.encode()))
print ("\r")

a_file = open("signature.sig", "rb")
content = a_file.read()
print(hashing(5, content))
a_file.close()
