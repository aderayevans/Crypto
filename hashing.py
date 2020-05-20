import hashlib 

def hashing(func, str):
    if func == 0:
        result = hashlib.md5(str) 
        return result.hexdigest()
    if func == 1:
        result = hashlib.sha1(str) 
        return result.hexdigest()
    if func == 2:
        return hashlib.sha256(str).hexdigest()
    if func == 3:
        result = hashlib.sha224(str) 
        return result.hexdigest()
    if func == 4:
        result = hashlib.sha384(str) 
        return result.hexdigest()
    if func == 5:
        result = hashlib.sha512(str) 
        return result.hexdigest()
str = "Quang"
#hashing('sha256', str.encode())
print(hashing(0, str.encode()))
print ("\r")

a_file = open("test.txt", "rb")
content = a_file.read()
print(hashing(2, content))
a_file.close()
