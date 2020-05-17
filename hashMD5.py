import hashlib 

def hashing(str):
    

    result = hashlib.md5(str) 

    print("The hexadecimal equivalent of MD5 is : ", end ="") 
    print(result.hexdigest())

str = "Quang"
hashing(str.encode())
print ("\r")
a_file = open("input.jpg", "rb")
content = a_file.read()
hashing(content)
a_file.close()


