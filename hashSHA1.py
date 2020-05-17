import hashlib 

def hashing(str):
    result = hashlib.sha256()
    print("The hexadecimal equivalent of SHA256 is : ") 
    print(result.hexdigest()) 
      
    print ("\r")

    result = hashlib.sha384(str)
    print("The hexadecimal equivalent of SHA384 is : ") 
    print(result.hexdigest()) 
      
    print ("\r")

    result = hashlib.sha224(str)
    print("The hexadecimal equivalent of SHA224 is : ") 
    print(result.hexdigest()) 
      
    print ("\r") 

    result = hashlib.sha512(str) 
    print("The hexadecimal equivalent of SHA512 is : ") 
    print(result.hexdigest()) 
      
    print ("\r") 

    result = hashlib.sha1(str)
    print("The hexadecimal equivalent of SHA1 is : ") 
    print(result.hexdigest()) 


str = "Quang"
hashing(str.encode())

print ("\r")

a_file = open("test.txt", "rb")
content = a_file.read()
hashing(content)
