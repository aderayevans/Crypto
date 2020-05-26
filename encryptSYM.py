# -*- coding: utf8 -*-
from tkinter import *
import tkinter.ttk
from tkinter import filedialog
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import AES
import binascii
import base64
import os

def success_message(informtext):
    success_toplevel = Toplevel()
    success_toplevel.title('Thông báo')
    success_toplevel.geometry('250x100')
    success_mes = Message(success_toplevel, text=informtext +
                    " thành công"
                    ,font=("Times New Roman Bold", 13), width=250)
    success_mes.pack()
    success_toplevel.after(1000, lambda: success_toplevel.destroy())
def error_message(informtext, mode):
    error_toplevel = Toplevel()
    error_toplevel.geometry('100x40')
    if mode == 0:
        padtext = '!!! Error '
    else:
        padtext = 'Warning '
    error_mes = Message(error_toplevel, text=padtext + informtext
                    ,font=("Times New Roman Bold", 13), width=700)
    error_mes.pack()
    error_toplevel.after(1000, lambda: error_toplevel.destroy())
def open_menu():
    menu_toplevel = Toplevel()
    menu_toplevel.title('Bảng tra cứu lỗi')
    menu_toplevel.geometry('500x400')
    menu_canvas = Canvas(menu_toplevel)
    menu_scrolling_y = Scrollbar(menu_toplevel, orient="vertical", command=menu_canvas.yview)
    menu_frame = Frame(menu_canvas)
    menu_mes = Message(menu_frame, text="Lỗi 01: Chưa nhập khóa\n\n"
                    "Cảnh báo 01: Chương trình không sử dụng kiểu mã hóa DES để mã hóa và giải mã tệp do vấn đề bảo mật\n\n"
                    "Lỗi 02: Chưa nhập bản gốc\n\n"
                    "Lỗi 03: Yêu cầu kiểm tra lại độ dài khóa\n\n"
                    "Lỗi 04: Chưa nhập iv, bạn bắt buộc nhập iv ở chế độ CBC\n\n"
                    "Lỗi 05: Chưa nhập đường dẫn tệp tin\n\n"
                    "Lỗi 06: Không tìm thấy tệp tin hay đường dẫn\n\n"
                    "Lỗi 07: Bảng mã hoặc khóa không đúng\n\n"
                    "Lỗi 08: Chưa nhập bảng mã\n\n"
                    "Lỗi 09: Đang sử dụng mã khóa của kiểu mã hóa khác (thường gặp ở chế độ ECB)\n\n"
                    "Lỗi 10: Đang sử dụng mã khóa hoặc iv của kiểu mã hóa khác (thường gặp ở chế độ CBC)\n\n"
                    "Lỗi 11: Không giải mã được tệp tin này\n\n"
                    "Lỗi 12: Yêu cầu kiểm tra lại độ dài bảng mã\n\n"
                    ,font=("Times New Roman", 13), width=450)
    menu_mes.pack(anchor="w")
    menu_canvas.create_window(0, 0, anchor='nw', window=menu_frame)
    menu_canvas.update_idletasks()
    menu_canvas.configure(scrollregion=menu_canvas.bbox('all'), 
                     yscrollcommand=menu_scrolling_y.set)
                     
    menu_canvas.pack(fill='both', expand=True, side='left')
    menu_scrolling_y.pack(fill='y', side='right')
def generate_key_DES():
    key = Random.new().read(DES.block_size)
    key_txt.delete(0,END)
    key_txt.insert(INSERT, key.hex())
def generate_key_AES():
    key = Random.new().read(AES.block_size)
    key_txt.delete(0,END)
    key_txt.insert(INSERT, key.hex())
def generate_key():
    if func_sym.get() == 0:
        generate_key_DES()
    else:
        generate_key_AES()
def generate_iv_DES():
    iv = Random.new().read(DES.block_size)
    iv_txt.delete(0,END)
    iv_txt.insert(INSERT, iv.hex())
def generate_iv_AES():
    iv = Random.new().read(AES.block_size)
    iv_txt.delete(0,END)
    iv_txt.insert(INSERT, iv.hex())
def generate_iv():
    if func_sym.get() == 0:
        generate_iv_DES()
    else:
        generate_iv_AES()
def browse():
    file = filedialog.askopenfilename(initialdir="D:/",
                    title="Open", filetypes=(("Text files", "*.txt"),
                                             ("Image files", "*.jpg"),
                                             ("Encoded files", "*.enc"),
                                             ("All files", "*.*")))
    link_txt.delete(0,END)
    link_txt.insert(INSERT, file)
##encrypt
def encrypt_ECB_DES(message, key):
    while True:
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            break
        except ValueError:
            error_message('09',0)
            raise
    message = pad(message, DES.block_size)
    return cipher.encrypt(message)
def encrypt_CBC_DES(message, key, iv):
    while True:
        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            break
        except ValueError:
            error_message('10',0)
            raise
    message = pad(message, DES.block_size)
    return cipher.encrypt(message)
def encrypt_ECB_AES(message, key):
    while True:
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            break
        except ValueError:
            error_message('09',0)
            raise
    message = pad(message, AES.block_size)
    return cipher.encrypt(message)
def encrypt_CBC_AES(message, key, iv):
    while True:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            break
        except ValueError:
            error_message('10',0)
            raise
    message = pad(message, AES.block_size)
    return cipher.encrypt(message)
def encrypt_file_ECB(file_name, key):
    while True:
        try:
            with open(file_name, 'rb') as fo:
                plaintext = fo.read()
            break
        except FileNotFoundError:
            error_message('06', 0)
            raise
    enc = encrypt_ECB_AES(plaintext, key)
    with open(file_name + '.enc', 'wb') as fo:
        fo.write(enc)
def encrypt_file_CBC(file_name, key):
    while True:
        try:
            if iv_txt.get() == '':
                raise ValueError('Value Error')
            iv = bytearray.fromhex(iv_txt.get())
            break
        except ValueError:
            error_message('04', 0)
            raise
    while True:
        try:
            with open(file_name, 'rb') as fo:
                plaintext = fo.read()
            break
        except FileNotFoundError:
            error_message('06', 0)
            raise
    enc = encrypt_CBC_AES(plaintext, key, iv)
    with open(file_name + '.enc', 'wb') as fo:
        fo.write(enc)
def encrypt_file(file_name, key):
    if mode_sym.get() == 0:
        encrypt_file_ECB(file_name, key)
    else:
        encrypt_file_CBC(file_name, key)
def encrypt_DES(key):
    while True:
        try:
            if plain_txt.get() == '':
                raise ValueError('Value Error')
            plaintext = plain_txt.get().encode()
            break
        except ValueError:
            error_message('02', 0)
            raise
    if mode_sym.get() == 0:
        ciphertext = encrypt_ECB_DES(plaintext, key)
        cipher_txt.delete(0,END)
        cipher_txt.insert(INSERT, ciphertext.hex())
    else:
        while True:
            try:
                if iv_txt.get() == '':
                    raise ValueError('Value Error')
                iv = bytearray.fromhex(iv_txt.get())
                break
            except ValueError:
                error_message('04', 0)
                raise
        ciphertext = encrypt_CBC_DES(plaintext, key, iv)
        cipher_txt.delete(0,END)
        cipher_txt.insert(INSERT, ciphertext.hex())
def encrypt_AES(key):
    while True:
        try:
            if plain_txt.get() == '':
                raise ValueError('Value Error')
            plaintext = plain_txt.get().encode()
            break
        except ValueError and UnboundLocalError:
            error_message('02', 0)
            raise
    if mode_sym.get() == 0:
        ciphertext = encrypt_ECB_AES(plaintext, key)
        cipher_txt.delete(0,END)
        cipher_txt.insert(INSERT, ciphertext.hex())
    else:
        while True:
            try:
                if iv_txt.get() == '':
                    raise ValueError('Value Error')
                iv = bytearray.fromhex(iv_txt.get())
                break
            except ValueError:
                error_message('04', 0)
                raise
        ciphertext = encrypt_CBC_AES(plaintext, key, iv)
        cipher_txt.delete(0,END)
        cipher_txt.insert(INSERT, ciphertext.hex())
def encrypt_sym():
    while True:
        try:
            if key_txt.get() == '':
                raise SyntaxError('Error')
            key = bytearray.fromhex(key_txt.get())
            break
        except SyntaxError:
            error_message('01', 0)
            raise
        except ValueError:
            error_message('03', 0)
            raise
    if func_sym.get() == 0:
        if file_val.get() == 1:
            error_message('01', 1)
        else:
            encrypt_DES(key)
            success_message('Mã hóa')
    else:
        if file_val.get() == 1:
            while True:
                try:
                    if link_txt.get() == '':
                        raise ValueError('Value Error')
                    linktext = link_txt.get()
                    break
                except ValueError:
                    error_message('05',0)
                    raise
            encrypt_file(linktext, key)
            head, tail = os.path.split(linktext)
            success_message('Mã hóa tệp ' + tail + ' thành tệp tin ' + tail + '.enc')
        else:
            encrypt_AES(key)
            success_message('Mã hóa')
##decrypt
def decrypt_ECB_DES(ciphertext, key):
    while True:
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            break
        except ValueError:
            error_message('09', 0)
            raise
    plaintext = cipher.decrypt(ciphertext)
    while True:
        try:
            final_plain =  unpad(plaintext, DES.block_size)
            break
        except ValueError:
            error_message('07', 0)
            raise
    return final_plain
def decrypt_CBC_DES(ciphertext, key, iv):
    while True:
        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            break
        except ValueError:
            error_message('10', 0)
            raise
    plaintext = cipher.decrypt(ciphertext)
    while True:
        try:
            final_plain =  unpad(plaintext, DES.block_size)
            break
        except ValueError:
            error_message('07', 0)
            raise
    return final_plain
def decrypt_DES(key):
    while True:
        try:
            if cipher_txt.get() == '':
                raise SyntaxError('Error')
            ciphertext = bytearray.fromhex(cipher_txt.get())
            break
        except ValueError or IndexError:
            error_message('12', 0)
            raise
        except SyntaxError:
            error_message('08', 0)
            raise
    if mode_sym.get() == 0:
        plaintext = decrypt_ECB_DES(ciphertext, key)
        plain_txt.delete(0,END)
        plain_txt.insert(INSERT, plaintext.decode())
    else:
        while True:
            try:
                if iv_txt.get() == '':
                    raise ValueError('Value Error')
                iv = bytearray.fromhex(iv_txt.get())
                break
            except ValueError:
                error_message('04', 0)
                raise
        plaintext = decrypt_CBC_DES(ciphertext, key, iv)
        plain_txt.delete(0,END)
        plain_txt.insert(INSERT, plaintext.decode())
def decrypt_ECB_AES(ciphertext, key):
    while True:
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            break
        except ValueError:
            error_message('09',0)
            raise
    plaintext = cipher.decrypt(ciphertext)
    while True:
        try:
            final_plain =  unpad(plaintext, AES.block_size)
            break
        except ValueError:
            error_message('07', 0)
            raise
    return final_plain
def decrypt_CBC_AES(ciphertext, key, iv):
    while True:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            break
        except ValueError:
            error_message('10',0)
            raise
    plaintext = cipher.decrypt(ciphertext)
    while True:
        try:
            final_plain =  unpad(plaintext, AES.block_size)
            break
        except ValueError:
            error_message('07', 0)
            raise
    return final_plain
def decrypt_AES(key):
    while True:
        try:
            if cipher_txt.get() == '':
                raise ValueError('Error')
            ciphertext = bytearray.fromhex(cipher_txt.get())
            break
        except ValueError or IndexError:
            error_message('08', 0)
            raise
    if mode_sym.get() == 0:
        plaintext = decrypt_ECB_AES(ciphertext, key)
        plain_txt.delete(0,END)
        plain_txt.insert(INSERT, plaintext.decode())
    else:
        while True:
            try:
                if iv_txt.get() == '':
                    raise ValueError('Value Error')
                iv = bytearray.fromhex(iv_txt.get())
                break
            except ValueError:
                error_message('04', 0)
                raise
        plaintext = decrypt_CBC_AES(ciphertext, key, iv)
        plain_txt.delete(0,END)
        plain_txt.insert(INSERT, plaintext.decode())
def decrypt_file_ECB(file_name, key):
    while True:
        try:
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()
            break
        except FileNotFoundError:
            error_message('06', 0)
            raise
    dec = decrypt_ECB_AES(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)
def decrypt_file_CBC(file_name, key):
    while True:
        try:
            if iv_txt.get() == '':
                raise ValueError('Value Error')
            iv = bytearray.fromhex(iv_txt.get())
            break
        except ValueError:
            error_message('04', 0)
            raise
    while True:
        try:
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()
            break
        except FileNotFoundError:
            error_message('06', 0)
            raise
    dec = decrypt_CBC_AES(ciphertext, key, iv)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)
def decrypt_file(file_name, key):
    if mode_sym.get() == 0:
        decrypt_file_ECB(file_name, key)
    else:
        decrypt_file_CBC(file_name, key)
def decrypt_sym():
    while True:
        try:
            if key_txt.get() == '':
                raise SyntaxError('Value Error')
            key = bytearray.fromhex(key_txt.get())
            break
        except SyntaxError:
            error_message('01', 0)
            raise
        except ValueError:
            error_message('03', 0)
            raise
    if func_sym.get() == 0:
        if file_val.get() == 1:
            error_message('01', 1)
        else:
            decrypt_DES(key)
            success_message('Giải mã')
    else:
        if file_val.get() == 1:
            while True:
                try:
                    if link_txt.get() == '':
                        raise ValueError('Value Error')
                    linktext = link_txt.get()
                    break
                except ValueError:
                    error_message('05',0)
                    raise
                except UnboundLocalError:
                    error_message('11',0)
                    raise
            decrypt_file(linktext, key)
            head, tail = os.path.split(linktext)
            success_message('Giải mã tệp ' + tail + ' thành tệp tin ' + tail[:-4])
        else:
            decrypt_AES(key)
            success_message('Giải mã')
root = Tk()
root.title("Chương trình mã hóa đối xứng")
root.geometry('600x600')

intro_frame = Frame(root)
func_frame = Frame(root)
text_frame = Frame(root)
mode_frame = Frame(root)
text_frame_2 = Frame(root)
button_frame = Frame(root)

intro_frame.pack()
func_frame.pack()
text_frame.pack()
mode_frame.pack()
text_frame_2.pack()
button_frame.pack()

intro_label = Label(intro_frame, text="Chương trình mã hóa đối xứng"
                    ,font=("Times New Roman Bold", 13))
intro_label.pack()
func_group = LabelFrame(func_frame, text = "Chọn kiểu mã hóa"
                        ,font=("Times New Roman", 13))
func_group.pack()
explain_func_mes = Message(func_group, text="!!! Kiểu DES không còn an toàn và đã bị crack thành công\n"
                     "Kiểu AES là kiểu mã hóa đối xứng đang phổ biến"
                     ,font=("Times New Roman", 13), width=700)
explain_func_mes.grid(column=0, row=0)
func_sym = IntVar()                     #
des_func = Radiobutton(func_group, text = "DES"
            ,font=("Times New Roman", 11), variable = func_sym, value = 0)
des_func.grid(column=0, row=1)
aes_func = Radiobutton(func_group, text = "AES"
            ,font=("Times New Roman", 11), variable = func_sym, value = 1)
aes_func.grid(column=0, row=2)
#
plain_label = Label(text_frame, text="Bản gốc: "
                    ,font=("Times New Roman", 13))
plain_label.grid(column=0, row=1, sticky="W")
plain_txt = Entry(text_frame,width=50)   #
plain_txt.grid(column=1, row=1)
cipher_label = Label(text_frame, text="Bản mã: "
                     ,font=("Times New Roman", 13))
cipher_label.grid(column=0, row=2, sticky="W")
cipher_txt = Entry(text_frame,width=50)   #
cipher_txt.grid(column=1, row=2)
key_label = Label(text_frame, text="Khóa: "
                     ,font=("Times New Roman", 13))
key_label.grid(column=0, row=3, sticky="W")
key_txt = Entry(text_frame,width=50)   #
key_txt.grid(column=1, row=3)
generate_key_button = Button(text_frame, text="Sinh khóa", command=generate_key)
generate_key_button.grid(column=2, row=3)
link_label = Label(text_frame, text="Đường dẫn: "
                     ,font=("Times New Roman", 13))
link_label.grid(column=0, row=4, sticky="W")
link_txt = Entry(text_frame,width=50)   #
link_txt.grid(column=1, row=4)
link_button = Button(text_frame, text="Chọn tệp", command=browse)
link_button.grid(column=2, row=4)
mode_group = LabelFrame(mode_frame, text = "Chọn chế độ mã hóa"
                        ,font=("Times New Roman", 13))
mode_group.grid(column=0, row=0)
explain_mode_mes = Message(mode_group, text="* Với chế độ ECB, không cần nhập iv(init. vector)\n"
                    "!!! ECB có nguy cơ nhận ra dữ liệu khi hai khối mã hóa giống nhau\n"
                    "* Chỉ nên sử dụng ECB khi mã hóa sử dụng một lần như mã xác nhận\n"
                    "* Với chế độ CBC, chế độ bảo mật hơn, bạn phải nhập thêm iv (init. vector)"
                    ,font=("Times New Roman", 13), width=700)
explain_mode_mes.grid(column=0, row=0)
mode_sym = IntVar()                     #
ecb_mode = Radiobutton(mode_group, text = "ECB"
            ,font=("Times New Roman", 11), variable = mode_sym, value = 0)
ecb_mode.grid(column=0, row=1)
cbc_func = Radiobutton(mode_group, text = "CBC"
            ,font=("Times New Roman", 11), variable = mode_sym, value = 1)
cbc_func.grid(column=0, row=2)
iv_label = Label(text_frame_2, text="IV: "
                 ,font=("Times New Roman", 13))
iv_label.grid(column=0, row=0)
iv_txt = Entry(text_frame_2,width=50)   #
iv_txt.grid(column=1, row=0)
generate_iv_button = Button(text_frame_2, text="Sinh iv", command=generate_iv)
generate_iv_button.grid(column=2, row=0)
button_group = LabelFrame(button_frame)
button_group.pack()
encrypt_button = Button(button_group, text="Mã hóa", command=encrypt_sym)
encrypt_button.grid(column=0, row=0)
decrypt_button = Button(button_group, text="Giải mã", command=decrypt_sym)
decrypt_button.grid(column=1, row=0)

file_val = IntVar()
file_check = Checkbutton(root, text = "Mã hóa/giải mã tệp tin"
                            ,variable = file_val ,onvalue = 1
                            ,offvalue = 0, height=5,width = 20)
file_check.pack()
error_menu_button = Button(root, text="Tra cứu lỗi", command=open_menu)
error_menu_button.pack()

root.mainloop()
