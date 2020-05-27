# -*- coding: utf8 -*-
import tkinter as tk
from tkinter import filedialog
import math
from Crypto.Hash import SHA256, MD5, SHA1, SHA224, SHA384, SHA512
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_2
from Crypto.Signature import PKCS1_PSS
import datetime
import pickle
import binascii
import base64
import os

class SuccessMessage(tk.Toplevel):
    def __init__(self, title):
        tk.Toplevel.__init__(self)
        self.title(title)
        self.geometry('250x100')
        self.success = tk.Label(self, text=title + ' thành công'
                        ,font=("Times New Roman Bold", 13))
        self.success.pack()
        self.after(1000, lambda: self.destroy())
class AcceptMessage(tk.Toplevel):
    def __init__(self):
        tk.Toplevel.__init__(self)
        self.geometry('250x100')
        self.accept = tk.Label(self, text='Chấp nhận tệp tin'
                        ,font=("Times New Roman Bold", 13))
        self.accept.pack()
        self.after(1000, lambda: self.destroy())
class RefuseMessage(tk.Toplevel):
    def __init__(self):
        tk.Toplevel.__init__(self)
        self.geometry('250x100')
        self.refuse = tk.Label(self, text='Từ chối tệp tin'
                        ,font=("Times New Roman Bold", 13))
        self.refuse.pack()
        self.after(1000, lambda: self.destroy())
class ErrorMessage(tk.Toplevel):
    def __init__(self, signal, mode):
        self.signal = signal
        self.mode = mode
        tk.Toplevel.__init__(self)
        self.geometry('100x40')
        if self.mode == 0:
            padtext = '!!! Error '
        else:
            padtext = 'Warning '
        self.error = tk.Message(self, text=padtext + self.signal,
                                font=("Times New Roman Bold", 13), fg='#f22a13', width=700)
        self.error.pack()
        self.after(1000, lambda: self.destroy())
class Affine(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.intro_frame = tk.Frame(self)
        self.intro_frame.pack()
        self.intro = tk.Label(self.intro_frame, text='Cùng thử nghiệm chương trình mã hóa đơn giản (Affine) ^_^'
                    ,font=('Times New Roman Bold', 13))
        self.intro.pack()
        self.inputs = tk.Frame(self)
        self.plain_label = tk.Label(self.inputs, text='Nhập một đoạn văn bản (IN HOA): '
                    ,font=('Times New Roman', 13))
        self.plain_label.grid(column=0, row=0)
        self.plain_text = tk.Entry(self.inputs,width=80)
        self.plain_text.grid(column=1, row=0)
        self.cipher_label = tk.Label(self.inputs, text='Đoạn kí tự đã mã hóa: '
                     ,font=('Times New Roman', 13))
        self.cipher_label.grid(column=0, row=1)
        self.cipher_text = tk.Entry(self.inputs,width=80)
        self.cipher_text.grid(column=1, row=1)
        self.keys = tk.LabelFrame(self, text = "Nhập hai kí tự khóa (số nguyên tố)"
                    ,font=("Times New Roman", 13))
        self.key_label_a = tk.Label(self.keys, text="khóa a "
                        ,font=("Times New Roman", 13))
        self.key_label_a.pack(side = tk.LEFT)
        self.key_a = tk.Entry(self.keys,width=4)    #
        self.key_a.pack(side = tk.LEFT)
        self.key_label_b = tk.Label(self.keys, text=" khóa b "
                                ,font=("Times New Roman", 13))
        self.key_label_b.pack(side = tk.RIGHT)
        self.key_b = tk.Entry(self.keys,width=4)    #
        self.key_b.pack(side = tk.RIGHT)
        self.group = tk.LabelFrame(self)
        self.encrypt_button = tk.Button(self.group, text="Mã hóa"
                        ,font=("Times New Roman", 11), command=self.encrypt)
        self.encrypt_button.pack(side = tk.LEFT)
        self.decrypt_button = tk.Button(self.group, text="Giải mã"
                                ,font=("Times New Roman", 11), command=self.decrypt)
        self.decrypt_button.pack(side = tk.RIGHT)
        self.inputs.pack()
        self.keys.pack()
        self.group.pack()
        self.group['background']=bgcolor
        self.inputs['background']=bgcolor
        self.keys['background']=bgcolor
        self.intro['background']=bgcolor
        self.plain_label['background']=bgcolor
        self.cipher_label['background']=bgcolor
        self.key_label_a['background']=bgcolor
        self.key_label_b['background']=bgcolor
    def get_key_a(self):
        return self.key_a.get()
    def get_key_b(self):
        return self.key_b.get()
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise ValueError('Value Error')
                plaintext = self.plain_text.get()
                break
            except ValueError:
                ErrorMessage('02',0)
                raise
        return plaintext
    def set_plain(self, text):
        self.plain_text.delete(0, tk.END)
        self.plain_text.insert(tk.INSERT,text)
    def get_cipher(self):
        while True:
            try:
                if self.cipher_text.get() == '':
                    raise ValueError('Value Error')
                ciphertext = self.cipher_text.get()
                break
            except ValueError:
                ErrorMessage('03',0)
                raise
        return ciphertext
    def set_cipher(self, text):
        self.cipher_text.delete(0,tk.END)
        self.cipher_text.insert(tk.INSERT,text)
    def Char2Num(self, c): return ord(c)-65
    def Num2Char(self, n): return chr(n+65)
    def xgcd(self, a, m):						
        temp = m						
        x0, x1, y0, y1 = 1, 0, 0, 1
        while m!=0:						
            q, a, m = a // m, m, a % m
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        if x0 < 0: x0 = temp+x0
        return x0
    def is_not_prime(self, number):
        if number < 1:
            return True
        elif number == 1:
            return False
        for i in range(2, int(math.sqrt(number) + 1)):
            if number % i == 0:
                return True
        return False
    def encrypt(self):
        while True:
            try:
                a,b,m = int(self.get_key_a()), int(self.get_key_b()), 26
                if self.is_not_prime(a) or self.is_not_prime(b):
                    raise ValueError('Error')
                break
            except ValueError:
                error_mes = ErrorMessage('04', 0)
                raise
        en_text = ""
        plaintext = self.get_plain()
        while True:
            try:
                for c in plaintext:
                    if ord(c) < 65 or ord(c) > 90:
                        raise ValueError('Error')
                    e = (a * self.Char2Num(c)+b )%m
                    en_text = en_text + self.Num2Char(e)
                break
            except ValueError:
                error_mes = ErrorMessage('05', 0)
                raise
        self.set_cipher(en_text)
        encrypt_mes = SuccessMessage('Mã hóa')
    def decrypt(self):
        while True:
            try:
                a,b,m = int(self.get_key_a()), int(self.get_key_b()), 26
                if self.is_not_prime(a) or self.is_not_prime(b):
                    raise ValueError('Error')
                break
            except ValueError:
                error_mes = ErrorMessage('04', 0)
                raise
        de_text = ""
        a1 = self.xgcd(a,m)
        ciphertext = self.get_cipher()
        while True:
            try:
                for c in ciphertext:
                    if ord(c) < 65 or ord(c) > 90:
                        raise ValueError('Error')
                    e = (a1*(self.Char2Num(c) - b))%m
                    de_text = de_text + self.Num2Char(e)
                break
            except ValueError:
                error_mes = ErrorMessage('06', 0)
                raise
        self.set_plain(de_text)
        decrypt_mes = SuccessMessage('Giải mã')
class EncryptSYMWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title("Chương trình mã hóa đối xứng")
        self.geometry('600x360')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.group = tk.LabelFrame(self)
        self.group.pack(fill='x', expand=True)
        self.plain_label = tk.Label(self.frame, text="Bản gốc: "
                    ,font=("Times New Roman", 13))
        self.plain_label.grid(column=0, row=0, sticky="W")
        self.plain_text = tk.Entry(self.frame,width=50) 
        self.plain_text.grid(column=1, row=0)
        self.cipher_label = tk.Label(self.frame, text="Bản mã: "
                             ,font=("Times New Roman", 13))
        self.cipher_label.grid(column=0, row=1, sticky="W")
        self.cipher_text = tk.Entry(self.frame,width=50)  
        self.cipher_text.grid(column=1, row=1)
        self.key_label = tk.Label(self.frame, text="Khóa: "
                             ,font=("Times New Roman", 13))
        self.key_label.grid(column=0, row=2, sticky="W")
        self.key_text = tk.Entry(self.frame,width=50)
        self.key_text.grid(column=1, row=2)
        self.generate_key_button = tk.Button(self.frame, text="Sinh khóa", command=self.generate_key)
        self.generate_key_button.grid(column=2, row=2)
        if self.parent.get_func() == 1:
            self.link_label = tk.Label(self.frame, text="Đường dẫn: "
                                 ,font=("Times New Roman", 13))
            self.link_label.grid(column=0, row=3, sticky="W")
            self.link_text = tk.Entry(self.frame,width=50)
            self.link_text.grid(column=1, row=3)
            self.link_button = tk.Button(self.frame, text="Chọn tệp", command=self.browse)
            self.link_button.grid(column=2, row=3)
        if self.parent.get_mode() == 1:
            self.iv_label = tk.Label(self.frame, text="IV: "
                             ,font=("Times New Roman", 13))
            self.iv_label.grid(column=0, row=4, sticky="W")
            self.iv_text = tk.Entry(self.frame,width=50)   #
            self.iv_text.grid(column=1, row=4)
            self.generate_iv_button = tk.Button(self.frame, text="Sinh iv", command=self.generate_iv)
            self.generate_iv_button.grid(column=2, row=4)
        self.encrypt_button = tk.Button(self, text="Mã hóa", command=self.encrypt)
        self.encrypt_button.pack()
        self.board_group = tk.LabelFrame(self)
        self.board_group.pack(side=tk.RIGHT)
        self.copy_button = tk.Button(self.board_group, text="Copy to clipboard", command=self.copy)
        self.copy_button.pack()
        self.paste_button = tk.Button(self.board_group, text="Paste", command=self.paste)
        self.paste_button.pack()
        if self.parent.get_func() == 1:
            self.file_val = tk.IntVar()
            self.file_check = tk.Checkbutton(self, text = "Mã hóa tệp tin"
                                        ,variable = self.file_val ,onvalue = 1
                                        ,offvalue = 0, height=5,width = 20)
            self.file_check.pack()
        if self.parent.get_func() == 0 and self.parent.get_mode() == 0:
            self.mes = tk.Message(self.group, text=
                "!!! Thuật toán DES không còn an toàn và đã bị crack thành công\n"
                "!!! Chế độ ECB có nguy cơ nhận ra dữ liệu khi hai khối mã hóa giống nhau\n"
                "* Chỉ nên sử dụng chế độ ECB khi mã hóa sử dụng một lần như mã xác nhận"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        elif self.parent.get_func() == 0 and self.parent.get_mode() == 1:
            self.mes = tk.Message(self.group, text=
                "!!! Thuật toán DES không còn an toàn và đã bị crack thành công\n"
                "* Chế độ CBC, là chế độ bảo mật cao sao khi nhập thêm iv (init. vector) biến đổi khóa"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        elif self.parent.get_func() == 1 and self.parent.get_mode() == 0:
            self.mes = tk.Message(self.group, text=
                "Thuật toán AES là kiểu mã hóa đối xứng đang phổ biến\n"
                "!!! Chế độ ECB có nguy cơ nhận ra dữ liệu khi hai khối mã hóa giống nhau\n"
                "* Chỉ nên sử dụng chế độ ECB khi mã hóa sử dụng một lần như mã xác nhận"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        else:
            self.mes = tk.Message(self.group, text=
                "Thuật toán AES là kiểu mã hóa đối xứng đang phổ biến\n"
                "* Chế độ CBC, là chế độ bảo mật cao sao khi nhập thêm iv (init. vector) biến đổi khóa"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def set_key(self, text):
        self.key_text.delete(0,tk.END)
        self.key_text.insert(tk.INSERT, text)
    def get_key(self):
        while True:
            try:
                if self.key_text.get() == '':
                    raise SyntaxError('Error')
                key = self.key_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return key
    def generate_key(self):
        if self.parent.get_func() == 0:
            self.set_key(Random.new().read(DES.block_size).hex())
        else:
            self.set_key(Random.new().read(AES.block_size).hex())
    def set_iv(self, text):
        self.iv_text.delete(0,tk.END)
        self.iv_text.insert(tk.INSERT, text)
    def get_iv(self):
        while True:
            try:
                if self.iv_text.get() == '':
                    raise SyntaxError('Error')
                iv = self.iv_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return iv
    def generate_iv(self):
        if self.parent.get_func() == 0:
            self.set_iv(Random.new().read(DES.block_size).hex())
        else:
            self.set_iv(Random.new().read(AES.block_size).hex())
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def set_plain(self, text):
        self.plain_text.delete(0,tk.END)
        self.plain_text.insert(tk.INSERT, text)
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise SyntaxError('Error')
                plaintext = self.plain_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return plaintext
    def set_cipher(self, text):
        self.cipher_text.delete(0,tk.END)
        self.cipher_text.insert(tk.INSERT, text)
    def get_cipher(self):
        while True:
            try:
                if self.cipher_text.get() == '':
                    raise SyntaxError('Error')
                cipher_text = self.cipher_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return cipher_text
    def encrypt_ECB_DES(self, message, key):
        while True:
            try:
                cipher = DES.new(key, DES.MODE_ECB)
                break
            except ValueError:
                ErrorMessage('09', 0)
                raise
        message = pad(message, DES.block_size)
        return cipher.encrypt(message)
    def encrypt_CBC_DES(self, message, key, iv):
        while True:
            try:
                cipher = DES.new(key, DES.MODE_CBC, iv)
                break
            except ValueError:
                ErrorMessage('10', 0)
                raise
        message = pad(message, DES.block_size)
        return cipher.encrypt(message)
    def encrypt_ECB_AES(self, message, key):
        while True:
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                break
            except ValueError:
                ErrorMessage('09', 0)
                raise
        message = pad(message, AES.block_size)
        return cipher.encrypt(message)
    def encrypt_CBC_AES(self, message, key, iv):
        while True:
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                break
            except ValueError:
                ErrorMessage('10', 0)
                raise
        message = pad(message, AES.block_size)
        return cipher.encrypt(message)
    def encrypt_file_ECB(self, file_name, key):
        while True:
            try:
                with open(file_name, 'rb') as fo:
                    plaintext = fo.read()
                break
            except FileNotFoundError:
                ErrorMessage('06', 0)
                raise
        enc = self.encrypt_ECB_AES(plaintext, key)
        save_file(enc, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("Encoded files", "*.enc")), ".enc")
    def encrypt_file_CBC(self, file_name, key):
        while True:
            try:
                iv = bytearray.fromhex(self.get_iv())
                break
            except ValueError:
                ErrorMessage('04', 0)
                raise
        while True:
            try:
                with open(file_name, 'rb') as fo:
                    plaintext = fo.read()
                break
            except FileNotFoundError:
                ErrorMessage('06', 0)
                raise
        enc = self.encrypt_CBC_AES(plaintext, key, iv)
        save_file(enc, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("Encoded files", "*.enc")), ".enc")
    def encrypt_file(self, file_name, key):
        if self.parent.get_mode() == 0:
            self.encrypt_file_ECB(file_name, key)
        else:
            self.encrypt_file_CBC(file_name, key)
    def encrypt_DES(self, key):
        plaintext = self.get_plain().encode()
        if self.parent.get_mode() == 0:
            ciphertext = self.encrypt_ECB_DES(plaintext, key)
            self.set_cipher(ciphertext.hex())
        else:
            while True:
                try:
                    iv = bytearray.fromhex(self.get_iv())
                    break
                except ValueError:
                    ErrorMessage('04', 0)
                    raise
            ciphertext = self.encrypt_CBC_DES(plaintext, key, iv)
            self.set_cipher(ciphertext.hex())
    def encrypt_AES(self, key):
        while True:
            try:
                plaintext = self.get_plain().encode()
                break
            except ValueError and UnboundLocalError:
                ErrorMessage('02', 0)
                raise
        if self.parent.get_mode() == 0:
            ciphertext = self.encrypt_ECB_AES(plaintext, key)
            self.set_cipher(ciphertext.hex())
        else:
            while True:
                try:
                    iv = bytearray.fromhex(self.get_iv())
                    break
                except ValueError:
                    ErrorMessage('04', 0)
                    raise
            ciphertext = self.encrypt_CBC_AES(plaintext, key, iv)
            self.set_cipher(ciphertext.hex())
    def encrypt(self):
        while True:
            try:
                key = bytearray.fromhex(self.get_key())
                break
            except ValueError:
                ErrorMessage('03', 0)
                raise
        if self.parent.get_func() == 0:
            self.encrypt_DES(key)
            SuccessMessage('Mã hóa')
        else:
            if self.file_val.get() == 1:
                linktext = self.get_link()
                self.encrypt_file(linktext, key)
                head, tail = os.path.split(linktext)
                SuccessMessage('Mã hóa tệp ' + tail)
            else:
                self.encrypt_AES(key)
                SuccessMessage('Mã hóa')
    def browse(self):
        self.set_link(browse_file())
    def back(self):
        root.deiconify()
        self.destroy()
    def copy(self):
        if self.file_val.get() == 0:
            self.parent.clipboard.set_plain(self.get_plain())
            self.parent.clipboard.set_cipher(self.get_cipher())
        self.parent.clipboard.set_key(self.get_key())
        if self.parent.get_mode() == 1:
            self.parent.clipboard.set_iv(self.get_iv())
    def paste(self):
        if self.file_val.get() == 0:
            self.set_plain(self.parent.clipboard.get_plain())
        self.set_key(self.parent.clipboard.get_key())
        if self.parent.get_mode() == 1:
            self.set_iv(self.parent.clipboard.get_iv())
class DecryptSYMWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title("Chương trình mã hóa đối xứng")
        self.geometry('600x360')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.group = tk.LabelFrame(self)
        self.group.pack(fill='x', expand=True)
        self.cipher_label = tk.Label(self.frame, text="Bản mã: "
                             ,font=("Times New Roman", 13))
        self.cipher_label.grid(column=0, row=0, sticky="W")
        self.cipher_text = tk.Entry(self.frame,width=50)  
        self.cipher_text.grid(column=1, row=0)
        self.plain_label = tk.Label(self.frame, text="Bản gốc: "
                    ,font=("Times New Roman", 13))
        self.plain_label.grid(column=0, row=1, sticky="W")
        self.plain_text = tk.Entry(self.frame,width=50) 
        self.plain_text.grid(column=1, row=1)
        self.key_label = tk.Label(self.frame, text="Khóa: "
                             ,font=("Times New Roman", 13))
        self.key_label.grid(column=0, row=2, sticky="W")
        self.key_text = tk.Entry(self.frame,width=50)
        self.key_text.grid(column=1, row=2)
        if self.parent.get_func() == 1:
            self.link_label = tk.Label(self.frame, text="Đường dẫn: "
                                 ,font=("Times New Roman", 13))
            self.link_label.grid(column=0, row=3, sticky="W")
            self.link_text = tk.Entry(self.frame,width=50)
            self.link_text.grid(column=1, row=3)
            self.link_button = tk.Button(self.frame, text="Chọn tệp", command=self.browse)
            self.link_button.grid(column=2, row=3)
        if self.parent.get_mode() == 1:
            self.iv_label = tk.Label(self.frame, text="IV: "
                             ,font=("Times New Roman", 13))
            self.iv_label.grid(column=0, row=4, sticky="W")
            self.iv_text = tk.Entry(self.frame,width=50)
            self.iv_text.grid(column=1, row=4)
        self.decrypt_button = tk.Button(self, text="Giải mã", command=self.decrypt)
        self.decrypt_button.pack()
        self.board_group = tk.LabelFrame(self)
        self.board_group.pack(side=tk.RIGHT)
        self.copy_button = tk.Button(self.board_group, text="Copy to clipboard", command=self.copy)
        self.copy_button.pack()
        self.paste_button = tk.Button(self.board_group, text="Paste", command=self.paste)
        self.paste_button.pack()
        if self.parent.get_func() == 1:
            self.file_val = tk.IntVar()
            self.file_check = tk.Checkbutton(self, text = "Giải mã tệp tin"
                                        ,variable = self.file_val ,onvalue = 1
                                        ,offvalue = 0, height=5,width = 20)
            self.file_check.pack()
        if self.parent.get_func() == 0 and self.parent.get_mode() == 0:
            self.mes = tk.Message(self.group, text=
                "!!! Thuật toán DES không còn an toàn và đã bị crack thành công\n"
                "!!! Chế độ ECB có nguy cơ nhận ra dữ liệu khi hai khối mã hóa giống nhau\n"
                "* Chỉ nên sử dụng chế độ ECB khi mã hóa sử dụng một lần như mã xác nhận"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        elif self.parent.get_func() == 0 and self.parent.get_mode() == 1:
            self.mes = tk.Message(self.group, text=
                "!!! Thuật toán DES không còn an toàn và đã bị crack thành công\n"
                "* Chế độ CBC, là chế độ bảo mật cao sao khi nhập thêm iv (init. vector) biến đổi khóa"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        elif self.parent.get_func() == 1 and self.parent.get_mode() == 0:
            self.mes = tk.Message(self.group, text=
                "Thuật toán AES là kiểu mã hóa đối xứng đang phổ biến\n"
                "!!! Chế độ ECB có nguy cơ nhận ra dữ liệu khi hai khối mã hóa giống nhau\n"
                "* Chỉ nên sử dụng chế độ ECB khi mã hóa sử dụng một lần như mã xác nhận"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        else:
            self.mes = tk.Message(self.group, text=
                "Thuật toán AES là kiểu mã hóa đối xứng đang phổ biến\n"
                "* Chế độ CBC, là chế độ bảo mật cao sao khi nhập thêm iv (init. vector) biến đổi khóa"
                        ,font=("Times New Roman", 13), width=700)
            self.mes.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def set_key(self, text):
        self.key_text.delete(0,tk.END)
        self.key_text.insert(tk.INSERT, text)
    def get_key(self):
        while True:
            try:
                if self.key_text.get() == '':
                    raise SyntaxError('Error')
                key = self.key_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return key
    def generate_key(self):
        if self.parent.get_func() == 0:
            self.set_key(Random.new().read(DES.block_size).hex())
        else:
            self.set_key(Random.new().read(AES.block_size).hex())
    def set_iv(self, text):
        self.iv_text.delete(0,tk.END)
        self.iv_text.insert(tk.INSERT, text)
    def get_iv(self):
        while True:
            try:
                if self.iv_text.get() == '':
                    raise SyntaxError('Error')
                iv = self.iv_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return iv
    def generate_iv(self):
        if self.parent.get_func() == 0:
            self.set_iv(Random.new().read(DES.block_size).hex())
        else:
            self.set_iv(Random.new().read(AES.block_size).hex())
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def set_plain(self, text):
        self.plain_text.delete(0,tk.END)
        self.plain_text.insert(tk.INSERT, text)
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise SyntaxError('Error')
                plaintext = self.plain_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return plaintext
    def set_cipher(self, text):
        self.cipher_text.delete(0,tk.END)
        self.cipher_text.insert(tk.INSERT, text)
    def get_cipher(self):
        while True:
            try:
                if self.cipher_text.get() == '':
                    raise SyntaxError('Error')
                cipher_text = self.cipher_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return cipher_text
    def decrypt_ECB_DES(self, ciphertext, key):
        while True:
            try:
                cipher = DES.new(key, DES.MODE_ECB)
                break
            except ValueError:
                ErrorMessage('09', 0)
                raise
        plaintext = cipher.decrypt(ciphertext)
        while True:
            try:
                final_plain = unpad(plaintext, DES.block_size)
                break
            except ValueError:
                ErrorMessage('07', 0)
                raise
        return final_plain
    def decrypt_CBC_DES(self, ciphertext, key, iv):
        while True:
            try:
                cipher = DES.new(key, DES.MODE_CBC, iv)
                break
            except ValueError:
                ErrorMessage('10', 0)
                raise
        plaintext = cipher.decrypt(ciphertext)
        while True:
            try:
                final_plain = unpad(plaintext, DES.block_size)
                break
            except ValueError:
                ErrorMessage('07', 0)
                raise
        return final_plain
    def decrypt_DES(self, key):
        while True:
            try:
                ciphertext = bytearray.fromhex(self.get_cipher())
                break
            except ValueError or IndexError:
                ErrorMessage('12', 0)
                raise
        if self.parent.get_mode() == 0:
            plaintext = self.decrypt_ECB_DES(ciphertext, key)
            self.set_plain(plaintext)
        else:
            while True:
                try:
                    iv = bytearray.fromhex(self.get_iv())
                    break
                except ValueError:
                    ErrorMessage('04', 0)
                    raise
            plaintext = self.decrypt_CBC_DES(ciphertext, key, iv)
            self.set_plain(plaintext)
    def decrypt_ECB_AES(self, ciphertext, key):
        while True:
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                break
            except ValueError:
                ErrorMessage('09', 0)
                raise
        plaintext = cipher.decrypt(ciphertext)
        while True:
            try:
                final_plain = unpad(plaintext, AES.block_size)
                break
            except ValueError:
                ErrorMessage('07', 0)
                raise
        return final_plain
    def decrypt_CBC_AES(self, ciphertext, key, iv):
        while True:
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                break
            except ValueError:
                ErrorMessage('10', 0)
                raise
        plaintext = cipher.decrypt(ciphertext)
        while True:
            try:
                final_plain = unpad(plaintext, AES.block_size)
                break
            except ValueError:
                ErrorMessage('07', 0)
                raise
        return final_plain
    def decrypt_AES(self, key):
        while True:
            try:
                ciphertext = bytearray.fromhex(self.get_cipher())
                break
            except ValueError or IndexError:
                ErrorMessage('08', 0)
                raise
        if self.parent.get_mode() == 0:
            plaintext = self.decrypt_ECB_AES(ciphertext, key)
            self.set_plain(plaintext)
        else:
            while True:
                try:
                    iv = bytearray.fromhex(self.get_iv())
                    break
                except ValueError:
                    ErrorMessage('04', 0)
                    raise
            plaintext = self.decrypt_CBC_AES(ciphertext, key, iv)
            self.set_plain(plaintext)
    def decrypt_file_ECB(self, file_name, key):
        while True:
            try:
                with open(file_name, 'rb') as fo:
                    ciphertext = fo.read()
                break
            except FileNotFoundError:
                ErrorMessage('06', 0)
                raise
        dec = self.decrypt_ECB_AES(ciphertext, key)
        save_file(dec, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("Text files", "*.txt"),
                   ("Png files", "*.png"),
                   ("Image files", "*.jpg")), ".txt")
    def decrypt_file_CBC(self, file_name, key):
        while True:
            try:
                iv = bytearray.fromhex(self.get_iv())
                break
            except ValueError:
                ErrorMessage('04', 0)
                raise
        while True:
            try:
                with open(file_name, 'rb') as fo:
                    ciphertext = fo.read()
                break
            except FileNotFoundError:
                ErrorMessage('06', 0)
                raise
        dec = self.decrypt_CBC_AES(ciphertext, key, iv)
        save_file(dec, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("Text files", "*.txt"),
                   ("Png files", "*.png"),
                   ("Image files", "*.jpg")), ".txt")
    def decrypt_file(self, file_name, key):
        if self.parent.get_mode() == 0:
            self.decrypt_file_ECB(file_name, key)
        else:
            self.decrypt_file_CBC(file_name, key)
    def decrypt(self):
        while True:
            try:
                key = bytearray.fromhex(self.get_key())
                break
            except ValueError:
                ErrorMessage('03', 0)
                raise
        if self.parent.get_func() == 0:
            self.decrypt_DES(key)
            SuccessMessage('Giải mã')
        else:
            if self.file_val.get() == 1:
                linktext = self.get_link()
                self.decrypt_file(linktext, key)
                head, tail = os.path.split(linktext)
                SuccessMessage('Giải mã tệp ' + tail)
            else:
                self.decrypt_AES(key)
                SuccessMessage('Giải mã')
    def browse(self):
        self.set_link(browse_file())
    def back(self):
        root.deiconify()
        self.destroy()
    def copy(self):
        if self.file_val.get() == 0:
            self.parent.clipboard.set_plain(self.get_plain())
            self.parent.clipboard.set_cipher(self.get_cipher())
        self.parent.clipboard.set_key(self.get_key())
        if self.parent.get_mode() == 1:
            self.parent.clipboard.set_iv(self.get_iv())
    def paste(self):
        if self.file_val.get() == 0:
            self.set_cipher(self.parent.clipboard.get_cipher())
        self.set_key(self.parent.clipboard.get_key())
        if self.parent.get_mode() == 1:
            self.set_iv(self.parent.clipboard.get_iv())
class Clipboard:
    def __init__(self):
        self.plain = ''
        self.cipher = ''
        self.key = None
        self.iv = None
    def set_plain(self, text):
        self.plain = text
    def set_cipher(self, text):
        self.cipher = text
    def set_key(self, text):
        self.key = text
    def set_iv(self, text):
        self.iv = text
    def get_plain(self):
        return self.plain
    def get_cipher(self):
        return self.cipher
    def get_key(self):
        return self.key
    def get_iv(self):
        return self.iv
class Symmetric(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.clipboard = Clipboard();
        self.group = tk.LabelFrame(self, text = "Mã hóa đối xứng"
                        ,font=("Times New Roman", 13))
        self.group.pack(side = tk.TOP, fill="both", expand="yes")
        self.explain = tk.Label(self.group, text="Ta dùng đồng thời cùng một key để mã hóa và giải mã"
                                ,font=("Times New Roman", 13))
        self.explain.pack()
        self.func_group = tk.LabelFrame(self.group
                            , text = "Chọn thuật toán",font=("Times New Roman", 13))
        self.func_group.pack(side = tk.LEFT, fill="both", expand="yes")
        self.func_val = tk.IntVar()                     #
        self.des_func = tk.Radiobutton(self.func_group, text = "DES"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 0)
        self.des_func.pack(anchor=tk.W)
        self.aes_func = tk.Radiobutton(self.func_group, text = "AES"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 1)
        self.aes_func.pack(anchor=tk.W)
        
        self.mode_group = tk.LabelFrame(self.group, text = "Chọn chế độ mã hóa"
                                ,font=("Times New Roman", 13))
        self.mode_group.pack(side = tk.LEFT, fill="both", expand="yes")
        self.mode_val = tk.IntVar()                         #
        self.ecb = tk.Radiobutton(self.mode_group, text = "ECB (chế độ sách mã điện tử)"
                        ,font=("Times New Roman", 11), variable = self.mode_val, value = 0)
        self.ecb.pack(anchor=tk.W)
        self.cbc = tk.Radiobutton(self.mode_group, text = "CBC (chế độ xích liên kết khối)"
                        ,font=("Times New Roman", 11), variable = self.mode_val, value = 1)
        self.cbc.pack(anchor=tk.W)
        self.encrypt_button = tk.Button(self.group, text="Mã hóa"
                                    ,font=("Times New Roman", 11), command=self.encrypt)
        self.decrypt_button = tk.Button(self.group, text="Giải mã"
                            ,font=("Times New Roman", 11), command=self.decrypt)
        self.decrypt_button.pack(side = tk.RIGHT)
        self.encrypt_button.pack(side = tk.RIGHT)
        self.group['background']=bgcolor
        self.explain['background']=bgcolor
        self.des_func['background']=bgcolor
        self.aes_func['background']=bgcolor
        self.cbc['background']=bgcolor
        self.ecb['background']=bgcolor
        self.mode_group['background']=bgcolor
        self.func_group['background']=bgcolor
    def get_func(self):
        return self.func_val.get()
    def get_mode(self):
        return self.mode_val.get()
    def encrypt(self):
        EncryptSYMWindow(self)
        root.withdraw()
    def decrypt(self):
        DecryptSYMWindow(self)
        root.withdraw()
class EncryptASYMWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title("Chương trình mã hóa bất đối xứng")
        self.geometry('600x360')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.plain_label = tk.Label(self.frame, text="Bản gốc: "
                    ,font=("Times New Roman", 13))
        self.plain_label.grid(column=0, row=0, sticky="W")
        self.plain_text = tk.Entry(self.frame,width=50)
        self.plain_text.grid(column=1, row=0)
        self.cipher_label = tk.Label(self.frame, text="Bản mã: "
                             ,font=("Times New Roman", 13))
        self.cipher_label.grid(column=0, row=1, sticky="W")
        self.cipher_text = tk.Entry(self.frame,width=50)
        self.cipher_text.grid(column=1, row=1)
        self.link_label = tk.Label(self.frame, text="Tệp tin chứa khóa: "
                                     , font=("Times New Roman", 13))
        self.link_label.grid(column=0, row=2, sticky="W")
        self.link_text = tk.Entry(self.frame, width=50)
        self.link_text.grid(column=1, row=2)
        self.link_button = tk.Button(self.frame, text="Chọn tệp", command=self.browse)
        self.link_button.grid(column=2, row=2)
        self.group = tk.Frame(self)
        self.group.pack()
        self.size_group = tk.LabelFrame(self.group
                                        , text="Chọn kích thước khóa", font=("Times New Roman", 13))
        self.size_group.pack(side=tk.LEFT, fill="x", expand="yes")
        self.size_val = tk.IntVar()  #
        self.size_1024 = tk.Radiobutton(self.size_group, text="1024"
                                       , font=("Times New Roman", 11), variable=self.size_val, value=0)
        self.size_1024.pack(anchor=tk.W)
        self.size_2048 = tk.Radiobutton(self.size_group, text="2048"
                                       , font=("Times New Roman", 11), variable=self.size_val, value=1)
        self.size_2048.pack(anchor=tk.W)
        self.generate_key_button = tk.Button(self, text="Sinh khóa", command=self.generate_key)
        self.generate_key_button.pack()
        self.encrypt_button = tk.Button(self, text="Mã hóa", command=self.encrypt)
        self.encrypt_button.pack()
        self.board_group = tk.LabelFrame(self)
        self.board_group.pack(side=tk.RIGHT)
        self.copy_button = tk.Button(self.board_group, text="Copy to clipboard", command=self.copy)
        self.copy_button.pack()
        self.paste_button = tk.Button(self.board_group, text="Paste", command=self.paste)
        self.paste_button.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def get_key(self):
        with open(self.get_link(), 'rb') as file:
            key = RSA.importKey(file.read())
        return key
    def get_size(self):
        if self.size_val.get() == 0:
            return 1024
        else:
            return 2048
    def get_mode(self):
        if self.mode_val.get() == 0:
            return 'DER'
        else:
            return 'PEM'
    def set_plain(self, text):
        self.plain_text.delete(0, tk.END)
        self.plain_text.insert(tk.INSERT, text)
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise SyntaxError('Error')
                plaintext = self.plain_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return plaintext
    def set_cipher(self, text):
        self.cipher_text.delete(0, tk.END)
        self.cipher_text.insert(tk.INSERT, text)
    def get_cipher(self):
        while True:
            try:
                if self.cipher_text.get() == '':
                    raise SyntaxError('Error')
                cipher_text = self.cipher_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return cipher_text
    def generate_key(self):
        key = RSA.generate(self.get_size())
        if save_file(key.exportKey(self.get_mode()), 'wb', 'Lưu khóa cá nhân',
                     (("All files", "*.*"),
                    ("DER files", "*.der"),
                    ("PEM files", "*.pem")), ".der")!= None:
            save_file(key.publickey().exportKey(self.get_mode()), 'wb'
                      , 'Lưu khóa công khai', (("All files", "*.*"),
                                                ("DER files", "*.der"),
                                                ("PEM files", "*.pem")), ".der")
        #with open('rsapri.' + self.get_mode(), 'wb') as file:
        #    file.write(key.exportKey(self.get_mode()))
        #with open('rsapub.' + self.get_mode(), 'wb') as file:
        #    file.write(key.publickey().exportKey(self.get_mode()))
    def encrypt(self):
        key = self.get_key()
        cipher = PKCS1_v1_5.new(key)
        plaintext = cipher.encrypt(self.get_plain().encode())
        self.set_cipher(plaintext.hex())
    def browse(self):
        self.set_link(browse_file())
    def copy(self):
        self.parent.clipboard.set_plain(self.get_plain())
        self.parent.clipboard.set_cipher(self.get_cipher())
    def paste(self):
        self.set_plain(self.parent.clipboard.get_plain())
    def back(self):
        root.deiconify()
        self.destroy()
class DecryptASYMWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title("Chương trình mã hóa bất đối xứng")
        self.geometry('600x360')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.cipher_label = tk.Label(self.frame, text="Bản mã: "
                             ,font=("Times New Roman", 13))
        self.cipher_label.grid(column=0, row=0, sticky="W")
        self.cipher_text = tk.Entry(self.frame,width=50)
        self.cipher_text.grid(column=1, row=0)
        self.plain_label = tk.Label(self.frame, text="Bản gốc: "
                    ,font=("Times New Roman", 13))
        self.plain_label.grid(column=0, row=1, sticky="W")
        self.plain_text = tk.Entry(self.frame,width=50)
        self.plain_text.grid(column=1, row=1)
        self.link_label = tk.Label(self.frame, text="Tệp tin chứa khóa: "
                                   , font=("Times New Roman", 13))
        self.link_label.grid(column=0, row=2, sticky="W")
        self.link_text = tk.Entry(self.frame, width=50)
        self.link_text.grid(column=1, row=2)
        self.link_button = tk.Button(self.frame, text="Chọn tệp", command=self.browse)
        self.link_button.grid(column=2, row=2)
        self.decrypt_button = tk.Button(self, text="Giải mã", command=self.decrypt)
        self.decrypt_button.pack()
        self.board_group = tk.LabelFrame(self)
        self.board_group.pack(side=tk.RIGHT)
        self.copy_button = tk.Button(self.board_group, text="Copy to clipboard", command=self.copy)
        self.copy_button.pack()
        self.paste_button = tk.Button(self.board_group, text="Paste", command=self.paste)
        self.paste_button.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def get_key(self):
        with open(self.get_link(), 'rb') as file:
            key = RSA.importKey(file.read())
        return key
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def set_plain(self, text):
        self.plain_text.delete(0, tk.END)
        self.plain_text.insert(tk.INSERT, text)
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise SyntaxError('Error')
                plaintext = self.plain_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return plaintext
    def set_cipher(self, text):
        self.cipher_text.delete(0, tk.END)
        self.cipher_text.insert(tk.INSERT, text)
    def get_cipher(self):
        while True:
            try:
                if self.cipher_text.get() == '':
                    raise SyntaxError('Error')
                cipher_text = self.cipher_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return cipher_text
    def decrypt(self):
        key = self.get_key()
        plaintext = PKCS1_v1_5.new(key)
        ciphertext = plaintext.decrypt(bytearray.fromhex(self.get_cipher()), 'sentinel')
        self.set_plain(ciphertext.decode())
    def browse(self):
        self.set_link(browse_file())
    def copy(self):
        self.parent.clipboard.set_plain(self.get_plain())
        self.parent.clipboard.set_cipher(self.get_cipher())
    def paste(self):
        self.set_cipher(self.parent.clipboard.get_cipher())
    def back(self):
        root.deiconify()
        self.destroy()
class Asymmetric(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.clipboard = Clipboard()
        self.group = tk.LabelFrame(self, text = "Mã hóa bất đối xứng"
                                ,font=("Times New Roman", 13))
        self.group.pack(side = tk.TOP, fill="both", expand="yes")
        self.explain = tk.Label(self.group, text="Ta dùng một key để mã hóa và một key khác để giải mã"
                                ,font=("Times New Roman", 13))
        self.explain.pack()
        self.func_group = tk.LabelFrame(self.group, borderwidth = 0, highlightthickness = 0, text = "Chọn thuật toán",font=("Times New Roman", 13))
        self.func_group.pack(side = tk.LEFT)
        self.func_val = tk.IntVar()
        self.rsa_func = tk.Radiobutton(self.func_group, text = "RSA"
                        ,font=("Times New Roman", 11), variable = self.func_val, value = 0)
        self.rsa_func.pack(anchor=tk.W)
        self.diffie_hellman_func = tk.Radiobutton(self.func_group, text = "Diffie–Hellman"
                        ,font=("Times New Roman", 11), variable = self.func_val, value = 1)
        self.diffie_hellman_func.pack(anchor=tk.W)
        self.encrypt_button = tk.Button(self.group, text="Mã hóa"
                        ,font=("Times New Roman", 11), command=self.encrypt)
        self.decrypt_button = tk.Button(self.group, text="Giải mã"
                        ,font=("Times New Roman", 11), command=self.decrypt)
        self.decrypt_button.pack(side = tk.RIGHT)
        self.encrypt_button.pack(side = tk.RIGHT)
        self.group['background']=bgcolor
        self.explain['background']=bgcolor
        self.diffie_hellman_func['background']=bgcolor
        self.rsa_func['background']=bgcolor
        self.func_group['background']=bgcolor
    def encrypt(self):
        if self.func_val.get() == 1:
            ErrorMessage('12', 1)
        else:
            EncryptASYMWindow(self)
            root.withdraw()
    def decrypt(self):
        if self.func_val.get() == 1:
            ErrorMessage('12', 1)
        else:
            DecryptASYMWindow(self)
            root.withdraw()
class HashWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title('Băm')
        self.geometry('600x200')
        self.label = tk.Label(self, text="Nhập một đoạn văn bản : "
                    ,font=("Times New Roman", 13))
        self.label.grid(column=0, row=0)
        self.plain_text = tk.Entry(self,width=50)   #
        self.plain_text.grid(column=1, row=0)
        self.cipher_label = tk.Label(self, text="Đoạn kí tự đã băm: "
                             ,font=("Times New Roman", 13))
        self.cipher_label.grid(column=0, row=1)
        self.cipher_text = tk.Entry(self,width=50)   #
        self.cipher_text.grid(column=1, row=1)
        self.file_label = tk.Label(self, text="File:",font=("Times New Roman", 13))
        self.file_label.grid(column=0, row=2)
        self.link_text = tk.Entry(self,width=30)   #
        self.link_text.grid(column=1, row=2)
        self.file_button = tk.Button(self, text="Chọn tệp", command=self.browse)
        self.file_button.grid(column=2, row=2)
        self.hash_button = tk.Button(self, text="Băm", command=self.check_file)
        self.hash_button.grid(column=1, row=3)
        self.file_val = tk.IntVar()
        self.file_check = tk.Checkbutton(self, text = "Băm từ tệp tin"
                                    ,variable = self.file_val ,onvalue = 1
                                    ,offvalue = 0, height=5,width = 20)
        self.file_check.grid(column=0, row=3)
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.grid(column=0, row=4)
    def back(self):
        root.deiconify()
        self.destroy()
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                error_message = ErrorMessage('xx',0)
                raise
        return linktext
    def set_cipher(self, text):
        self.cipher_text.delete(0,tk.END)
        self.cipher_text.insert(tk.INSERT, text)
    def get_plain(self):
        while True:
            try:
                if self.plain_text.get() == '':
                    raise ValueError('Value Error')
                plaintext = self.plain_text.get()
                break
            except ValueError:
                error_message = ErrorMessage('xx',0)
                raise
        return plaintext
    def check_file(self):
        if self.file_val.get() == 0:
            self.set_cipher(hashing(self.parent.get_func(), self.get_plain().encode()))
        else:
            while True:
                try:
                    with open(self.get_link(), 'rb') as fo:
                        content = fo.read()
                    break
                except FileNotFoundError:
                    error_message = ErrorMessage('xx', 0)
                    raise
            self.set_cipher(hashing(self.parent.get_func(), content))
    def browse(self):
        self.set_link(browse_file())
class Hashing(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.group = tk.LabelFrame(self, text = "Băm"
                            ,font=("Times New Roman", 13))
        self.group.pack(side = tk.TOP, expand = True, fill = tk.BOTH)
        self.explain = tk.Label(self.group, text="Ta băm một đoạn kí tự hoặc file ra một đoạn kí tự bất kì, không thể giải mã"
                                 ,font=("Times New Roman", 13))
        self.explain.pack()
        self.func_group = tk.LabelFrame(self.group, borderwidth = 0, highlightthickness = 0, text = "Chọn thuật toán"
                                ,font=("Times New Roman", 13))
        self.func_group.pack(side = tk.LEFT, fill="both", expand="yes")
        self.func_val = tk.IntVar()
        self.md5_func = tk.Radiobutton(self.func_group, text = "Hash MD5"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 0)
        self.md5_func.grid(row=0, column=0, sticky="W")
        self.sha1_func = tk.Radiobutton(self.func_group, text = "Hash SHA1"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 1)
        self.sha1_func.grid(row=0, column=1, sticky="W")
        self.sha256_func = tk.Radiobutton(self.func_group, text = "Hash SHA256"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 2)
        self.sha256_func.grid(row=1, column=0, sticky="W")
        self.sha224_func = tk.Radiobutton(self.func_group, text = "Hash SHA224"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 3)
        self.sha224_func.grid(row=1, column=1, sticky="W")
        self.sha384_func = tk.Radiobutton(self.func_group, text = "Hash SHA384"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 4)
        self.sha384_func.grid(row=2, column=0, sticky="W")
        self.sha512_func = tk.Radiobutton(self.func_group, text = "Hash SHA512"
                    ,font=("Times New Roman", 11), variable = self.func_val, value = 5)
        self.sha512_func.grid(row=2, column=1, sticky="W")
        self.open_window_button = tk.Button(self.group, text="Băm"
                     , font=("Times New Roman", 11), command=self.open_window)
        self.open_window_button.pack(side = tk.RIGHT, expand = True, fill = tk.BOTH)
        self.group['background']=bgcolor
        self.explain['background']=bgcolor
        self.md5_func['background']=bgcolor
        self.sha1_func['background']=bgcolor
        self.sha256_func['background']=bgcolor
        self.sha224_func['background']=bgcolor
        self.sha384_func['background']=bgcolor
        self.sha512_func['background']=bgcolor
        self.func_group['background']=bgcolor
    def open_window(self):
        HashWindow(self)
        root.withdraw()
    def get_func(self):
        return self.func_val.get()
class SigningWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title('Tạo chữ ký')
        self.geometry('600x500')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.link_label_file = tk.Label(self.frame, text="Đường dẫn tệp tin: "
                                   , font=("Times New Roman", 13))
        self.link_label_file.grid(column=0, row=0, sticky="W")
        self.link_text_file = tk.Entry(self.frame, width=50)
        self.link_text_file.grid(column=1, row=0)
        self.link_button_file = tk.Button(self.frame, text="Chọn tệp", command=self.browse_file)
        self.link_button_file.grid(column=2, row=0)
        self.link_label_key = tk.Label(self.frame, text="Đường dẫn khóa cá nhân: "
                                        , font=("Times New Roman", 13))
        self.link_label_key.grid(column=0, row=1, sticky="W")
        self.link_text_key = tk.Entry(self.frame, width=50)
        self.link_text_key.grid(column=1, row=1)
        self.link_button_key = tk.Button(self.frame, text="Chọn tệp", command=self.browse_key)
        self.link_button_key.grid(column=2, row=1)
        self.group = tk.LabelFrame(self)
        self.group.pack(side=tk.TOP, expand=True, fill=tk.BOTH)
        self.func_group = tk.LabelFrame(self.group, borderwidth=0, highlightthickness=0, text="Chọn thuật toán băm"
                                        , font=("Times New Roman", 13))
        self.func_group.pack(side=tk.LEFT, fill="both", expand="yes")
        self.func_val = tk.IntVar()
        self.sha1_func = tk.Radiobutton(self.func_group, text="Hash SHA1"
                                        , font=("Times New Roman", 11), variable=self.func_val, value=0)
        self.sha1_func.grid(row=0, column=0, sticky="W")
        self.md5_func = tk.Radiobutton(self.func_group, text="Hash MD5"
                                       , font=("Times New Roman", 11), variable=self.func_val, value=1)
        self.md5_func.grid(row=0, column=1, sticky="W")
        self.sha256_func = tk.Radiobutton(self.func_group, text="Hash SHA256"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=2)
        self.sha256_func.grid(row=1, column=0, sticky="W")
        self.sha224_func = tk.Radiobutton(self.func_group, text="Hash SHA224"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=3)
        self.sha224_func.grid(row=1, column=1, sticky="W")
        self.sha384_func = tk.Radiobutton(self.func_group, text="Hash SHA384"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=4)
        self.sha384_func.grid(row=2, column=0, sticky="W")
        self.sha512_func = tk.Radiobutton(self.func_group, text="Hash SHA512"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=5)
        self.sha512_func.grid(row=2, column=1, sticky="W")
        self.scheme_group = tk.LabelFrame(self.group, borderwidth=0, highlightthickness=0, text="Chọn sơ đồ chữ ký"
                                        , font=("Times New Roman", 13))
        self.scheme_group.pack(side=tk.LEFT, fill="both", expand="yes")
        self.scheme_val = tk.IntVar()  #
        self.v1_5 = tk.Radiobutton(self.scheme_group, text="PKCS1_v1_5"
                                  , font=("Times New Roman", 11), variable=self.scheme_val, value=0)
        self.v1_5.pack(anchor=tk.W)
        self.pss = tk.Radiobutton(self.scheme_group, text="PKCS1_PSS"
                                  , font=("Times New Roman", 11), variable=self.scheme_val, value=1)
        self.pss.pack(anchor=tk.W)
        self.sign_button = tk.Button(self, text="Tạo chữ ký số", command=self.generatesignature)
        self.sign_button.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def get_link_file(self):
        while True:
            try:
                if self.link_text_file.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text_file.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link_file(self, text):
        self.link_text_file.delete(0,tk.END)
        self.link_text_file.insert(tk.INSERT, text)
    def get_link_key(self):
        while True:
            try:
                if self.link_text_key.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text_key.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link_key(self, text):
        self.link_text_key.delete(0,tk.END)
        self.link_text_key.insert(tk.INSERT, text)
    def generatesignature(self):
        with open(self.get_link_key(), 'rb') as file:
            key = RSA.importKey(file.read())
        with open(self.get_link_file(), 'rb') as file:
            plaintext = file.read()
        if self.func_val.get() == 0:
            hashingtext = SHA1.new(plaintext)
        elif self.func_val.get() == 1:
            hashingtext = MD5.new(plaintext)
        elif self.func_val.get() == 2:
            hashingtext = SHA256.new(plaintext)
        elif self.func_val.get() == 3:
            hashingtext = SHA224.new(plaintext)
        elif self.func_val.get() == 4:
            hashingtext = SHA384.new(plaintext)
        else:
            hashingtext = SHA512.new(plaintext)
        if self.scheme_val.get() == 0:
            cipher = PKCS1_v1_5_2.new(key)
        else:
            cipher = PKCS1_PSS.new(key)
        signature = cipher.sign(hashingtext)
        save_file(signature, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("PEM files", "*.sig")), ".sig")
        SuccessMessage('Tạo chữ ký')
    def browse_file(self):
        self.set_link_file(browse_file())
    def browse_key(self):
        self.set_link_key(browse_file())
    def back(self):
        root.deiconify()
        self.destroy()
class Date:
    def __init__(self, day, month, year):
        self.day = day
        self.month = month
        self.year = year
    def set_day(self, day):
        self.day = day
    def set_month(self, month):
        self.month = month
    def set_year(self, year):
        self.year = year
    def get_day(self):
        return self.day
    def get_month(self):
        return self.month
    def get_year(self):
        return self.year
class DigitalCertification:
    def __init__(self):
        self.name = ''
        self.serial = 0
        self.period = Date(0, 0, 0)
        self.authority = ''
        self.publickey = None
    def set_name(self, name):
        self.name = name
    def set_serial(self, serial):
        self.serial = serial
    def set_period(self, period):
        self.period.set_day(period.get_day())
        self.period.set_month(period.get_month())
        self.period.set_year(period.get_year())
    def set_authority(self, authority):
        self.authority = authority
    def set_publickey(self, publickey):
        self.publickey = publickey
    def get_name(self):
        return self.name
    def get_serial(self):
        return self.serial
    def get_period(self):
        return self.period
    def get_authority(self):
        return self.authority
    def get_publickey(self):
        return self.publickey
class CertificationWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title('Tạo chứng thư số')
        self.geometry('600x500')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.name_label = tk.Label(self.frame, text="Tên: "
                                    , font=("Times New Roman", 13))
        self.name_label.grid(column=0, row=0, sticky="W")
        self.name_text = tk.Entry(self.frame, width=50)
        self.name_text.grid(column=1, row=0)
        self.link_label = tk.Label(self.frame, text="Đường dẫn khóa: "
                                        , font=("Times New Roman", 13))
        self.link_label.grid(column=0, row=1, sticky="W")
        self.link_text = tk.Entry(self.frame, width=50)
        self.link_text.grid(column=1, row=1)
        self.link_button = tk.Button(self.frame, text="Chọn tệp", command=self.browse_file)
        self.link_button.grid(column=2, row=1)
        self.sign_button = tk.Button(self, text="Tạo chứng thư", command=self.create)
        self.sign_button.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def get_name(self):
        while True:
            try:
                if self.name_text.get() == '':
                    raise SyntaxError('Error')
                name = self.name_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return name
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise SyntaxError('Error')
                link = self.link_text.get()
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
        return link
    def get_publickey(self):
        while True:
            try:
                with open(self.get_link(), 'rb') as fo:
                    key = fo.read()
                break
            except FileNotFoundError:
                ErrorMessage('06', 0)
                raise
        return key
    def get_serial(self):
        with open('certificationserial.txt', 'rb') as fo:
            currentserial = fo.read()
        print("sada" + currentserial.decode())
        currentserial = int(currentserial.decode(), 10) + 1
        currentserial = str(currentserial)
        with open('certificationserial.txt', 'wb') as fo:
            fo.write(currentserial.encode())
        return currentserial
    def get_period(self):
        dt = datetime.datetime.today()
        return Date(dt.day, dt.month, dt.year)
    def get_authority(self):
        return 'Viettel-CA'
    def create(self):
        certification = DigitalCertification()
        certification.set_name(self.get_name())
        certification.set_serial(self.get_serial())
        certification.set_period(self.get_period())
        certification.set_authority(self.get_authority())
        certification.set_publickey(self.get_publickey())
        save_object(certification, 'wb', 'Save as',
                  (("All files", "*.*"),
                   ("Digital Certification files", "*.dcq")), ".dcq")
        SuccessMessage('Tạo chứng thư')
    def browse_file(self):
        self.set_link(browse_file())
    def back(self):
        root.deiconify()
        self.destroy()
class VerifyingWindow(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title('Xác minh nguồn gốc tập tin')
        self.geometry('600x500')
        self.frame = tk.Frame(self)
        self.frame.pack()
        self.link_label_file = tk.Label(self.frame, text="Đường dẫn tệp tin: "
                                        , font=("Times New Roman", 13))
        self.link_label_file.grid(column=0, row=0, sticky="W")
        self.link_text_file = tk.Entry(self.frame, width=50)
        self.link_text_file.grid(column=1, row=0)
        self.link_button_file = tk.Button(self.frame, text="Chọn tệp", command=self.browse_file)
        self.link_button_file.grid(column=2, row=0)
        self.link_label_key = tk.Label(self.frame, text="Đường dẫn chứng thư: "
                                       , font=("Times New Roman", 13))
        self.link_label_key.grid(column=0, row=1, sticky="W")
        self.link_text_key = tk.Entry(self.frame, width=50)
        self.link_text_key.grid(column=1, row=1)
        self.link_button_key = tk.Button(self.frame, text="Chọn tệp", command=self.browse_key)
        self.link_button_key.grid(column=2, row=1)
        self.link_label_sig = tk.Label(self.frame, text="Đường dẫn chữ ký: "
                                       , font=("Times New Roman", 13))
        self.link_label_sig.grid(column=0, row=2, sticky="W")
        self.link_text_sig = tk.Entry(self.frame, width=50)
        self.link_text_sig.grid(column=1, row=2)
        self.link_button_sig = tk.Button(self.frame, text="Chọn tệp", command=self.browse_sig)
        self.link_button_sig.grid(column=2, row=2)
        self.group = tk.LabelFrame(self)
        self.group.pack(side=tk.TOP, expand=True, fill=tk.BOTH)
        self.func_group = tk.LabelFrame(self.group, borderwidth=0, highlightthickness=0, text="Chọn thuật toán băm"
                                        , font=("Times New Roman", 13))
        self.func_group.pack(side=tk.LEFT, fill="both", expand="yes")
        self.func_val = tk.IntVar()
        self.sha1_func = tk.Radiobutton(self.func_group, text="Hash SHA1"
                                        , font=("Times New Roman", 11), variable=self.func_val, value=0)
        self.sha1_func.grid(row=0, column=0, sticky="W")
        self.md5_func = tk.Radiobutton(self.func_group, text="Hash MD5"
                                       , font=("Times New Roman", 11), variable=self.func_val, value=1)
        self.md5_func.grid(row=0, column=1, sticky="W")
        self.sha256_func = tk.Radiobutton(self.func_group, text="Hash SHA256"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=2)
        self.sha256_func.grid(row=1, column=0, sticky="W")
        self.sha224_func = tk.Radiobutton(self.func_group, text="Hash SHA224"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=3)
        self.sha224_func.grid(row=1, column=1, sticky="W")
        self.sha384_func = tk.Radiobutton(self.func_group, text="Hash SHA384"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=4)
        self.sha384_func.grid(row=2, column=0, sticky="W")
        self.sha512_func = tk.Radiobutton(self.func_group, text="Hash SHA512"
                                          , font=("Times New Roman", 11), variable=self.func_val, value=5)
        self.sha512_func.grid(row=2, column=1, sticky="W")
        self.scheme_group = tk.LabelFrame(self.group, borderwidth=0, highlightthickness=0, text="Chọn sơ đồ chữ ký"
                                          , font=("Times New Roman", 13))
        self.scheme_group.pack(side=tk.LEFT, fill="both", expand="yes")
        self.scheme_val = tk.IntVar()  #
        self.v1_5 = tk.Radiobutton(self.scheme_group, text="PKCS1_v1_5"
                                   , font=("Times New Roman", 11), variable=self.scheme_val, value=0)
        self.v1_5.pack(anchor=tk.W)
        self.pss = tk.Radiobutton(self.scheme_group, text="PKCS1_PSS"
                                  , font=("Times New Roman", 11), variable=self.scheme_val, value=1)
        self.pss.pack(anchor=tk.W)
        self.sign_button = tk.Button(self, text="Xác minh tệp tin", command=self.verify_file)
        self.sign_button.pack()
        self.back = tk.Button(self, text="Trở lại trang chính <---", command=self.back)
        self.back.pack(anchor='w', side=tk.BOTTOM)
    def get_link_file(self):
        while True:
            try:
                if self.link_text_file.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text_file.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link_file(self, text):
        self.link_text_file.delete(0,tk.END)
        self.link_text_file.insert(tk.INSERT, text)
    def get_link_key(self):
        while True:
            try:
                if self.link_text_key.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text_key.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link_key(self, text):
        self.link_text_key.delete(0,tk.END)
        self.link_text_key.insert(tk.INSERT, text)
    def get_link_sig(self):
        while True:
            try:
                if self.link_text_sig.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text_sig.get()
                break
            except ValueError:
                ErrorMessage('05',0)
                raise
            except UnboundLocalError:
                ErrorMessage('11', 0)
                raise
        return linktext
    def set_link_sig(self, text):
        self.link_text_sig.delete(0,tk.END)
        self.link_text_sig.insert(tk.INSERT, text)
    def verify_file(self):
        signature = open(self.get_link_sig(), "rb").read()
        with open(self.get_link_key(), 'rb') as input:
            the_object = pickle.load(input)
        key = RSA.importKey(the_object.get_publickey())
        plaintext = open(self.get_link_file(), "rb").read()
        if self.scheme_val.get() == 0:
            verifier = PKCS1_v1_5_2.new(key)
        else:
            verifier = PKCS1_PSS.new(key)
        if self.func_val.get() == 0:
            hashingtext = SHA1.new(plaintext)
        elif self.func_val.get() == 1:
            hashingtext = MD5.new(plaintext)
        elif self.func_val.get() == 2:
            hashingtext = SHA256.new(plaintext)
        elif self.func_val.get() == 3:
            hashingtext = SHA224.new(plaintext)
        elif self.func_val.get() == 4:
            hashingtext = SHA384.new(plaintext)
        else:
            hashingtext = SHA512.new(plaintext)
        if verifier.verify(hashingtext, signature):
            AcceptMessage()
        else:
            RefuseMessage()
    def browse_file(self):
        self.set_link_file(browse_file())
    def browse_key(self):
        self.set_link_key(browse_file())
    def browse_sig(self):
        self.set_link_sig(browse_file())
    def back(self):
        root.deiconify()
        self.destroy()
class DigitalSignature(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.group = tk.LabelFrame(self)
        self.group.pack(side = tk.TOP, expand = True, fill = tk.BOTH)
        self.explain = tk.Label(self.group, text="Ký chữ ký số cho tệp tin và kiểm tra tính toàn vẹn của một tệp tin có chữ ký"
                         ,font=("Times New Roman", 13))
        self.explain.pack()
        self.digital_signature_button = tk.Button(self.group, text="Tạo chữ ký"
                        ,font=("Times New Roman", 11),command=self.create_ds)
        self.digital_signature_button.pack(side = tk.LEFT, expand = True, fill = tk.BOTH)
        self.digital_certificate_button = tk.Button(self.group, text="Tạo chứng thư"
                        ,font=("Times New Roman", 11),command=self.create_dc)
        self.digital_certificate_button.pack(side = tk.LEFT, expand = True, fill = tk.BOTH)
        self.verify_button = tk.Button(self.group, text="Xác minh nguồn gốc tệp tin"
                        ,font=("Times New Roman", 11),command=self.verify)
        self.verify_button.pack(side = tk.RIGHT, expand = True, fill = tk.BOTH)
        self.explain['background']=bgcolor
        self.group['background']=bgcolor
    def create_ds(self):
        SigningWindow(self)
        root.withdraw()
    def create_dc(self):
        CertificationWindow(self)
        root.withdraw()
    def verify(self):
        VerifyingWindow(self)
        root.withdraw()
class Center(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.symmetric  = Symmetric(self)
        self.asymmetric = Asymmetric(self)
        self.hashing = Hashing(self)
        self.digitalsignature = DigitalSignature(self)
        self.symmetric.pack(side = tk.TOP, fill="both", expand="yes")
        self.asymmetric.pack(side = tk.TOP, fill="both", expand="yes")
        self.hashing.pack(side = tk.TOP, fill="both", expand="yes")
        self.digitalsignature.pack(side = tk.TOP, fill="both", expand="yes")
class Menu(tk.Toplevel):
    def __init__(self, parent):
        self.parent = parent
        tk.Toplevel.__init__(self)
        self.title('Bảng tra cứu lỗi')
        self.geometry('500x400')
        self.canvas = tk.Canvas(self)
        self.scrolling_y = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.frame = tk.Frame(self.canvas)
        self.mes = tk.Message(self.frame, text=
            "Lỗi 01: Chưa nhập khóa\n\n"
            "Lỗi 02: Chưa nhập bản gốc\n\n"
            "Lỗi 03: Chưa nhập bản mã\n\n"
                              
            "Lỗi xx: Chưa nhập bảng mã\n\n"
            "Lỗi xx: Chưa nhập đường dẫn tệp tin\n\n"
            "Lỗi xx: Không tìm thấy tệp tin hay đường dẫn\n\n"
            "Lỗi xx: Bảng mã hoặc khóa không đúng\n\n"
            "Lỗi xx: Không giải mã được tệp tin này\n\n"
            "Lỗi xx: Yêu cầu kiểm tra lại độ dài bảng mã\n\n"                  
            "\n***\nCác lỗi khi dùng mã hóa affine:\n\n"
            "Lỗi 04: Không được bỏ trống ô khóa nào, mỗi ô khóa phải là số nguyên tố\n\n"                  
            "Lỗi 05: Bản gốc phải là kí tự ASCII in hoa\n\n"
            "Lỗi 06: Bản mã phải là kí tự ASCII in hoa\n\n"
                              
            "\n***\nCác lỗi khi dùng mã hóa đối xứng:\n\n"
            "Cảnh báo 01: Chương trình không sử dụng kiểu mã hóa DES để mã hóa và giải mã tệp do vấn đề bảo mật\n\n"
            "Lỗi xx: Yêu cầu kiểm tra lại độ dài khóa\n\n"
            "Lỗi xx: Chưa nhập iv, bạn bắt buộc nhập iv ở chế độ CBC\n\n"
            "Lỗi xx: Đang sử dụng mã khóa của kiểu mã hóa khác (thường gặp ở chế độ ECB)\n\n"
            "Lỗi xx: Đang sử dụng mã khóa hoặc iv của kiểu mã hóa khác (thường gặp ở chế độ CBC)\n\n"
            "\n***\nCác lỗi khi dùng mã hóa bất đối xứng:\n\n"

            "\n***\nCác lỗi khi băm:\n\n"

            "\n***\nCác lỗi khi tạo hoặc xác nhận chữ kí số:\n\n" 
                        ,font=("Times New Roman", 13), width=450)
        self.mes.pack(anchor="w")
        self.canvas.create_window(0, 0, anchor='nw', window=self.frame)
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox('all'), 
                         yscrollcommand=self.scrolling_y.set)
                         
        self.canvas.pack(fill='both', expand=True, side='left')
        self.scrolling_y.pack(fill='y', side='right')
class Welcome(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.welcome = tk.Label(self, text="Chào mừng bạn đến với chương trình mã hóa đơn giản ver 1.2020"
                      ,font=("Times New Roman", 12))
        self.welcome.pack(side = tk.LEFT)
        self.menu = tk.Button(self, text="! Tra cứu lỗi", fg='#f22a13'
                        ,font=("Times New Roman", 11),command=self.open)
        self.menu.pack(side = tk.RIGHT)
    def open(self):
        menu = Menu(self)
class MainWindow(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.affine = Affine(self)
        self.affine.pack(side = tk.TOP, fill="both", expand="yes")
        self.center = Center(self)
        self.center.pack()
        self.welcome = Welcome(self)
        self.welcome.pack(side = tk.BOTTOM, fill="both", expand="yes")
        self.affine['background']=bgcolor
        self.welcome['background']=bgcolor
def hashing(func, content):
    if func == 0:
        result = MD5.new(content)
        return result.hexdigest()
    if func == 1:
        result = SHA1.new(content)
        return result.hexdigest()
    if func == 2:
        return SHA256.new(content).hexdigest()
    if func == 3:
        result = SHA224.new(content)
        return result.hexdigest()
    if func == 4:
        result = SHA384.new(content)
        return result.hexdigest()
    if func == 5:
        result = SHA512.new(content)
        return result.hexdigest()
def browse_file():
    return tk.filedialog.askopenfilename(initialdir="D:/",
                    title="Open", filetypes=(("All files", "*.*"),
                                             ("Image files", "*.jpg"),
                                             ("Encoded files", "*.enc"),
                                             ("DER files", "*.der"),
                                             ("PEM files", "*.pem"),
                                             ("Digital signature files", "*.sig"),
                                             ("Text files", "*.txt")))
def save_file(content, _mode, _title, _filetypes, _defaultextension):
    f = tk.filedialog.asksaveasfile(mode=_mode, initialdir="D:/",
                    title=_title, filetypes = _filetypes, defaultextension = _defaultextension)
    if f is None:
        return
    f.write(content)
    f.close()
    return 0
def save_object(the_object, _mode, _title, _filetypes, _defaultextension):
    f = tk.filedialog.asksaveasfile(mode=_mode, initialdir="D:/",
                    title=_title, filetypes = _filetypes, defaultextension = _defaultextension)
    if f is None:
        return
    pickle.dump(the_object, f, pickle.HIGHEST_PROTOCOL)
    f.close()
    return 0
def set_windowcolor(color_in_hex):
    global bgcolor
    bgcolor = color_in_hex
def main():
    set_windowcolor('#cedbd2')
    global root
    root = tk.Tk()
    root.title("Chương trình mã hóa đơn giản")
    root.geometry('800x700')
    root['background']=bgcolor
    app = MainWindow(root)
    root.mainloop()
if __name__ == '__main__':
    main()
