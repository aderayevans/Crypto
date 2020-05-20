# -*- coding: utf8 -*-
from tkinter import *
import tkinter.ttk
from tkinter import filedialog
import hashlib 

root = Tk()
root.title("Chương trình mã hóa đơn giản")
root.geometry('800x700')

intro_frame = Frame(root)
intro_text_frame = Frame(root)
top_frame = Frame(root)
center_frame = Frame(root)
bottom_frame = Frame(root)

intro_frame.pack()
intro_text_frame.pack()
top_frame.pack()
center_frame.pack()
bottom_frame.pack(side = BOTTOM)
#Giới thiệu chương trình
def Char2Num(c): return ord(c)-65
def Num2Char(n): return chr(n+65)
def xgcd(a,m):						#b, a
    temp = m						#a
    x0, x1, y0, y1 = 1, 0, 0, 1
    while m!=0:						#a
    	q, a, m = a // m, m, a % m	#q, b, a = b // a, a, b % a
    	x0, x1 = x1, x0 - q * x1
    	y0, y1 = y1, y0 - q * y1
    if x0 < 0: x0 = temp+x0
    return x0
def encrypt():
    a,b,m = int(affine_key01.get()),int(affine_key02.get()),26
    en_txt = ""
    for c in plain_txt.get():
    	e = (a*Char2Num(c)+b )%m	#e = [a*(char - 65) + b] mod 26
    	en_txt = en_txt+Num2Char(e)			#r = r + e + 65
    cipher_txt.delete(0,END)
    cipher_txt.insert(INSERT,en_txt)
    encrypt_toplevel = Toplevel()
    encrypt_toplevel.title('Mã hóa')
    encrypt_toplevel.geometry('200x40')
    encrypt_success_label = Label(encrypt_toplevel, text="Mã hóa thành công"
                    ,font=("Times New Roman Bold", 13))
    encrypt_success_label.pack()
def decrypt():
    a,b,m = int(affine_key01.get()),int(affine_key02.get()),26
    de_txt = ""
    a1 = xgcd(a,m)
    for c in cipher_txt.get():
        e = (a1*(Char2Num(c)-b ))%m
        de_txt = de_txt+Num2Char(e)
    plain_txt.delete(0,END)
    plain_txt.insert(INSERT,de_txt)
    encrypt_toplevel = Toplevel()
    encrypt_toplevel.title('Giải mã')
    encrypt_toplevel.geometry('200x40')
    decrypt_success_label = Label(encrypt_toplevel, text="Giải mã thành công"
                    ,font=("Times New Roman Bold", 13))
    decrypt_success_label.pack()
intro_label = Label(intro_frame, text="Cùng thử nghiệm chương trình mã hóa đơn giản (Affine) ^_^"
                    ,font=("Times New Roman Bold", 13))
intro_label.pack()
plain_label = Label(intro_text_frame, text="Nhập một đoạn văn bản (IN HOA): "
                    ,font=("Times New Roman", 13))
plain_label.grid(column=0, row=0)
plain_txt = Entry(intro_text_frame,width=80)   #
plain_txt.grid(column=1, row=0)
cipher_label = Label(intro_text_frame, text="Đoạn kí tự đã mã hóa: "
                     ,font=("Times New Roman", 13))
cipher_label.grid(column=0, row=1)
cipher_txt = Entry(intro_text_frame,width=80)   #
cipher_txt.grid(column=1, row=1)
affine_group = LabelFrame(top_frame, text = "Nhập hai kí tự khóa (số nguyên tố)"
                    ,font=("Times New Roman", 13))
affine_group.pack()
affine_key_Label0 = Label(affine_group, text="khóa a "
                        ,font=("Times New Roman", 13))
affine_key_Label0.pack(side = LEFT)
affine_key01 = Entry(affine_group,width=4)    #
affine_key01.pack(side = LEFT)
affine_key_Label1 = Label(affine_group, text=" khóa b "
                        ,font=("Times New Roman", 13))
affine_key_Label1.pack(side = RIGHT)
affine_key02 = Entry(affine_group,width=4)    #
affine_key02.pack(side = RIGHT)
key_group = LabelFrame(top_frame)
key_group.pack()
encrypt_button = Button(key_group, text="Mã hóa"
                        ,font=("Times New Roman", 11), command=encrypt)
encrypt_button.pack(side = LEFT)
decrypt_button = Button(key_group, text="Giải mã"
                        ,font=("Times New Roman", 11), command=decrypt)
decrypt_button.pack(side = RIGHT)
#Symmetric encryption algorithm
symmetric_group = LabelFrame(center_frame, text = "Mã hóa đối xứng"
                        ,font=("Times New Roman", 13))
symmetric_group.pack(side = TOP, fill="both", expand="yes")
explain_sym_label = Label(symmetric_group, text="Ta dùng đồng thời cùng một key để mã hóa và giải mã"
                        ,font=("Times New Roman", 13))
explain_sym_label.pack()
func_sym_group = LabelFrame(symmetric_group
                    , text = "Chọn thuật toán",font=("Times New Roman", 13))
func_sym_group.pack(side = LEFT, fill="both", expand="yes")
function_sym = IntVar()                     #
des_func = Radiobutton(func_sym_group, text = "DES"
            ,font=("Times New Roman", 11), variable = function_sym, value = 0)
des_func.pack(anchor=W)
aes_func = Radiobutton(func_sym_group, text = "AES"
            ,font=("Times New Roman", 11), variable = function_sym, value = 1)
aes_func.pack(anchor=W)
mode_sym_group = LabelFrame(symmetric_group, text = "Chọn chế độ hoạt động"
                        ,font=("Times New Roman", 13))
mode_sym_group.pack(side = LEFT, fill="both", expand="yes")
mode_sym = IntVar()                         #
ecb_mode = Radiobutton(mode_sym_group, text = "ECB (chế độ sách mã điện tử)"
                ,font=("Times New Roman", 11), variable = mode_sym, value = 0)
ecb_mode.pack(anchor=W)
cbc_mode = Radiobutton(mode_sym_group, text = "CBC (chế độ xích liên kết khối)"
                ,font=("Times New Roman", 11), variable = mode_sym, value = 1)
cbc_mode.pack(anchor=W)
def des_ecb_encrypt():
    des_ecb_encrypt_toplevel = Toplevel()
    des_ecb_encrypt_toplevel.title('Mã hóa')
    des_ecb_encrypt_toplevel.geometry('600x500')
def des_cbc_encrypt():
    des_ecb_encrypt_toplevel = Toplevel()
    des_ecb_encrypt_toplevel.title('Mã hóa')
    des_ecb_encrypt_toplevel.geometry('600x500')
def aes_ecb_encrypt():
    des_ecb_encrypt_toplevel = Toplevel()
    des_ecb_encrypt_toplevel.title('Mã hóa')
    des_ecb_encrypt_toplevel.geometry('600x500')
def aes_cbc_encrypt():
    des_ecb_encrypt_toplevel = Toplevel()
    des_ecb_encrypt_toplevel.title('Mã hóa')
    des_ecb_encrypt_toplevel.geometry('600x500')
def sym_encrypt():
    if function_sym == mode_sym_group and function_sym == 0:
        des_ecb_encrypt()
    elif function_sym == 0 and function_sym == 1:
        des_cbc_encrypt() 
    elif function_sym == mode_sym_group and function_sym == 1:
        aes_cbc_encrypt()
    else:
        aes_ecb_encrypt()
def sym_decrypt():
    sym_decrypt_toplevel = Toplevel()
    sym_decrypt_toplevel.title('Giải mã')
    sym_decrypt_toplevel.geometry('600x500')
sym_decrypt_button = Button(symmetric_group, text="Giải mã"
                            ,font=("Times New Roman", 11), command=sym_decrypt)
sym_decrypt_button.pack(side = RIGHT, fill="both", expand="yes")
sym_encrypt_button = Button(symmetric_group, text="Mã hóa"
                            ,font=("Times New Roman", 11), command=sym_encrypt)
sym_encrypt_button.pack(side = RIGHT, fill="both", expand="yes")
#Asymmetric encryption algorithm
asymmetric_group = LabelFrame(center_frame, text = "Mã hóa bất đối xứng"
                        ,font=("Times New Roman", 13))
asymmetric_group.pack(side = TOP, fill="both", expand="yes")
explain_asym_label = Label(asymmetric_group, text="Ta dùng một key để mã hóa và một key khác để giải mã"
                        ,font=("Times New Roman", 13))
explain_asym_label.pack()
func_asym_group = LabelFrame(asymmetric_group, text = "Chọn thuật toán",font=("Times New Roman", 13))
func_asym_group.pack(side = LEFT, fill="both", expand="yes")
function_sym = IntVar()                     #
diffie_hellman_func = Radiobutton(func_asym_group, text = "Diffie–Hellman"
                ,font=("Times New Roman", 11), variable = function_sym, value = 0)
diffie_hellman_func.pack(anchor=W)
rsa_func = Radiobutton(func_asym_group, text = "RSA"
                ,font=("Times New Roman", 11), variable = function_sym, value = 1)
rsa_func.pack(anchor=W)
def asym_encrypt():
    asym_encrypt_toplevel = Toplevel()
    asym_encrypt_toplevel.title('Mã hóa')
    asym_encrypt_toplevel.geometry('600x500')
def asym_decrypt():
    asym_decrypt_toplevel = Toplevel()
    asym_decrypt_toplevel.title('Giải mã')
    asym_decrypt_toplevel.geometry('600x500')
asym_decrypt_button = Button(asymmetric_group, text="Giải mã"
                        ,font=("Times New Roman", 11), command=asym_decrypt)
asym_decrypt_button.pack(side = RIGHT, fill="both", expand="yes")
asym_encrypt_button = Button(asymmetric_group, text="Mã hóa"
                        ,font=("Times New Roman", 11), command=asym_encrypt)
asym_encrypt_button.pack(side = RIGHT, fill="both", expand="yes")
#Hashing
hashing_group = LabelFrame(center_frame, text = "Băm"
                    ,font=("Times New Roman", 13))
hashing_group.pack(side = TOP, expand = True, fill = BOTH)
explain_hash_label = Label(hashing_group, text="Ta băm một đoạn kí tự hoặc file ra một đoạn kí tự bất kì, không thể giải mã"
                         ,font=("Times New Roman", 13))
explain_hash_label.pack()
func_hash_group = LabelFrame(hashing_group, text = "Chọn thuật toán"
                        ,font=("Times New Roman", 13))
func_hash_group.pack(side = LEFT, fill="both", expand="yes")
function_hash = IntVar()
md5_func = Radiobutton(func_hash_group, text = "Hash MD5"
            ,font=("Times New Roman", 11), variable = function_hash, value = 0)
md5_func.grid(row=0, column=0, sticky="W")
sha1_func = Radiobutton(func_hash_group, text = "Hash SHA1"
            ,font=("Times New Roman", 11), variable = function_hash, value = 1)
sha1_func.grid(row=0, column=1, sticky="W")
sha256_func = Radiobutton(func_hash_group, text = "Hash SHA256"
            ,font=("Times New Roman", 11), variable = function_hash, value = 2)
sha256_func.grid(row=1, column=0, sticky="W")
sha224_func = Radiobutton(func_hash_group, text = "Hash SHA224"
            ,font=("Times New Roman", 11), variable = function_hash, value = 3)
sha224_func.grid(row=1, column=1, sticky="W")
sha384_func = Radiobutton(func_hash_group, text = "Hash SHA384"
            ,font=("Times New Roman", 11), variable = function_hash, value = 4)
sha384_func.grid(row=2, column=0, sticky="W")
sha512_func = Radiobutton(func_hash_group, text = "Hash SHA512"
            ,font=("Times New Roman", 11), variable = function_hash, value = 5)
sha512_func.grid(row=2, column=1, sticky="W")
def open_hash_window():
    def browse():
        file = filedialog.askopenfilename(initialdir="D:/",
                        title="Open", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        file_link.delete(0,END)
        file_link.insert(INSERT, file)
    def hashing(func, str):
        if func == 0:
            return hashlib.md5(str).hexdigest()
        if func == 1:
            return hashlib.sha1(str).hexdigest()
        if func == 2:
            return hashlib.sha256(str).hexdigest()
        if func == 3:
            return hashlib.sha224(str).hexdigest()
        if func == 4:
            return hashlib.sha384(str).hexdigest()
        if func == 5:
            return hashlib.sha512(str).hexdigest()
    hash_toplevel = Toplevel()
    hash_toplevel.title('Băm')
    hash_toplevel.geometry('600x500')
    hash_plain_label = Label(hash_toplevel, text="Nhập một đoạn văn bản : "
                    ,font=("Times New Roman", 13))
    hash_plain_label.grid(column=0, row=0)
    hash_plain_txt = Entry(hash_toplevel,width=50)   #
    hash_plain_txt.grid(column=1, row=0)
    hash_cipher_label = Label(hash_toplevel, text="Đoạn kí tự đã băm: "
                         ,font=("Times New Roman", 13))
    hash_cipher_label.grid(column=0, row=1)
    hash_cipher_txt = Entry(hash_toplevel,width=50)   #
    hash_cipher_txt.grid(column=1, row=1)
    file_label = Label(hash_toplevel, text="File:",font=("Times New Roman", 13))
    file_label.grid(column=0, row=2)
    file_link = Entry(hash_toplevel,width=30)   #
    file_link.grid(column=1, row=2)
    file_button = Button(hash_toplevel, text="Chọn tệp", command=browse)
    file_button.grid(column=2, row=2)
    def running_hash():
        if  hash_plain_txt.get() != None:
            hash_cipher_txt.delete(0,END)
            hash_cipher_txt.insert(INSERT, hashing(function_hash.get()
                                        , hash_plain_txt.get().encode()))
        elif file_link.get() != None:
            a_file= open(file_link.get(),'rb')
            content = a_file.read()
            hash_cipher_txt.delete(0,END)
            hash_cipher_txt.insert(INSERT,hashing(function_hash, content))
        else:
            pass
    hash_button = Button(hash_toplevel, text="Băm", command=running_hash)
    hash_button.grid(column=0, row=3)
open_hash_window_button = Button(hashing_group, text="Băm"
                     , font=("Times New Roman", 11), command=open_hash_window)
open_hash_window_button.pack(side = RIGHT, fill = BOTH, expand="yes")
#Digital_signature
ds_group = LabelFrame(center_frame, text = "Chữ ký số"
                    ,font=("Times New Roman", 13))
ds_group.pack(side = TOP, expand = True, fill = BOTH)
explain_ds_label = Label(ds_group, text="Ký chữ ký số cho tệp tin và kiểm tra tính toàn vẹn của một tệp tin có chữ ký"
                         ,font=("Times New Roman", 13))
explain_ds_label.pack()
def create_digital_signature():
    create_digital_signature_toplevel = Toplevel()
    create_digital_signature_toplevel.title('Tạo chữ ký')
    create_digital_signature_toplevel.geometry('600x500')
def verify_digital_signature():
    verify_digital_signature_toplevel = Toplevel()
    verify_digital_signature_toplevel.title('Xác minh nguồn gốc tệp tin')
    verify_digital_signature_toplevel.geometry('600x500')
create_ds_button = Button(ds_group, text="Tạo chữ ký"
                          ,font=("Times New Roman", 11),command=create_digital_signature)
create_ds_button.pack(side = LEFT, fill="both", expand="yes")
verify_ds_button = Button(ds_group, text="Xác minh nguồn gốc tệp tin"
                          ,font=("Times New Roman", 11),command=verify_digital_signature)
verify_ds_button.pack(side = RIGHT, fill="both", expand="yes")
############
welcome_label = Label(bottom_frame, text="Chào mừng bạn đến với chương trình mã hóa đơn giản ver 1.2020"
                      ,font=("Times New Roman", 12))
welcome_label.pack()
def set_bgcolor(bgcolor):
    root['background']=bgcolor
    intro_text_frame['background']=bgcolor
    intro_label['background']=bgcolor
    plain_label['background']=bgcolor
    #plain_txt['background']=bgcolor
    cipher_label['background']=bgcolor
    #cipher_txt['background']=bgcolor
    top_frame['background']=bgcolor
    affine_group['background']=bgcolor
    affine_key_Label0['background']=bgcolor
    affine_key_Label1['background']=bgcolor
    symmetric_group['background']=bgcolor
    explain_sym_label['background']=bgcolor
    func_sym_group['background']=bgcolor
    des_func['background']=bgcolor
    aes_func['background']=bgcolor
    mode_sym_group['background']=bgcolor
    ecb_mode['background']=bgcolor
    cbc_mode['background']=bgcolor
    asymmetric_group['background']=bgcolor
    explain_asym_label['background']=bgcolor
    func_asym_group['background']=bgcolor
    diffie_hellman_func['background']=bgcolor
    rsa_func['background']=bgcolor
    hashing_group['background']=bgcolor
    explain_hash_label['background']=bgcolor
    func_hash_group['background']=bgcolor
    md5_func['background']=bgcolor
    sha1_func['background']=bgcolor
    sha256_func['background']=bgcolor
    sha224_func['background']=bgcolor
    sha384_func['background']=bgcolor
    sha512_func['background']=bgcolor
    ds_group['background']=bgcolor
    explain_ds_label['background']=bgcolor
    welcome_label['background']=bgcolor 
set_bgcolor('#cedbd2')
root.mainloop()
