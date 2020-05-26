import tkinter as tk
from tkinter import filedialog
import math
from Crypto.Hash import SHA256, MD5, SHA1, SHA224, SHA384, SHA512
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Cipher import AES
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
        self.error = tk.Message(self, text=padtext + self.signal
                        ,font=("Times New Roman Bold", 13), fg='#f22a13', width=700)
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
        self.key_text.insert(tk.INSERT, text.hex())
    def get_key(self):
        return self.key_text.get()
    def generate_key(self):
        if self.parent.get_func() == 0:
            self.set_key(Random.new().read(DES.block_size))
        else:
            self.set_key(Random.new().read(AES.block_size))
    def set_iv(self, text):
        self.iv_text.delete(0,tk.END)
        self.iv_text.insert(tk.INSERT, text.hex())
    def generate_iv(self):
        if self.parent.get_func() == 0:
            self.set_iv(Random.new().read(DES.block_size))
        else:
            self.set_iv(Random.new().read(AES.block_size))
    def get_link(self):
        while True:
            try:
                if self.link_text.get() == '':
                    raise ValueError('Value Error')
                linktext = self.link_text.get()
                break
            except ValueError:
                error_message('05',0)
                raise
        return linktext
    def set_link(self, text):
        self.link_text.delete(0,tk.END)
        self.link_text.insert(tk.INSERT, text)
    def encrypt(self):
        while True:
            try:
                if self.get_key() == '':
                    raise SyntaxError('Error')
                key = bytearray.fromhex(self.get_key())
                break
            except SyntaxError:
                ErrorMessage('01', 0)
                raise
            except ValueError:
                ErrorMessage('03', 0)
                raise
        if self.parent.get_func() == 0:
            if self.file_val.get() == 1:
                ErrorMessage('01', 1)
            else:
                encrypt_DES(key)
                SuccessMessage('Mã hóa')
        else:
            if self.file_val.get() == 1:
                while True:
                    try:
                        if self.get_link() == '':
                            raise ValueError('Value Error')
                        linktext = self.get_link()
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
    def browse(self):
        pass
    def back(self):
        root.deiconify()
        self.destroy()
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
        self.encrypt_button = tk.Button(self, text="Giải hóa", command=self.encrypt)
        self.encrypt_button.pack()
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
    def encrypt(self):
        pass
    def browse(self):
        pass
    def back(self):
        root.deiconify()
        self.destroy()
class Symmetric(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
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
        encrypt_button = tk.Button(self.group, text="Mã hóa"
                                    ,font=("Times New Roman", 11), command=self.encrypt)
        decrypt_button = tk.Button(self.group, text="Giải mã"
                            ,font=("Times New Roman", 11), command=self.decrypt)
        decrypt_button.pack(side = tk.RIGHT)
        encrypt_button.pack(side = tk.RIGHT)
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
class Asymmetric(tk.Frame):
    def __init__(self, parent):
        self.parent = parent
        tk.Frame.__init__(self)
        self.group = tk.LabelFrame(self, text = "Mã hóa bất đối xứng"
                                ,font=("Times New Roman", 13))
        self.group.pack(side = tk.TOP, fill="both", expand="yes")
        self.explain = tk.Label(self.group, text="Ta dùng một key để mã hóa và một key khác để giải mã"
                                ,font=("Times New Roman", 13))
        self.explain.pack()
        self.func_group = tk.LabelFrame(self.group, borderwidth = 0, highlightthickness = 0, text = "Chọn thuật toán",font=("Times New Roman", 13))
        self.func_group.pack(side = tk.LEFT)
        self.func_val = tk.IntVar()                     #
        self.diffie_hellman_func = tk.Radiobutton(self.func_group, text = "Diffie–Hellman"
                        ,font=("Times New Roman", 11), variable = self.func_val, value = 0)
        self.diffie_hellman_func.pack(anchor=tk.W)
        self.rsa_func = tk.Radiobutton(self.func_group, text = "RSA"
                        ,font=("Times New Roman", 11), variable = self.func_val, value = 1)
        self.rsa_func.pack(anchor=tk.W)
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
        asym_encrypt_toplevel = tk.Toplevel()
        asym_encrypt_toplevel.title('Mã hóa')
        asym_encrypt_toplevel.geometry('600x500')
    def decrypt(self):
        asym_decrypt_toplevel = tk.Toplevel()
        asym_decrypt_toplevel.title('Giải mã')
        asym_decrypt_toplevel.geometry('600x500')
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
            self.set_cipher(hashing(self.parent.get_func_val(), self.get_plain().encode()))
        else:
            while True:
                try:
                    with open(self.get_link(), 'rb') as fo:
                        content = fo.read()
                    break
                except FileNotFoundError:
                    error_message = ErrorMessage('xx', 0)
                    raise
            self.set_cipher(hashing(self.parent.get_func_val(), content))
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
    def get_func_val(self):
        return self.func_val.get()
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
    def create_ds():
        create_digital_signature_toplevel = tk.Toplevel()
        create_digital_signature_toplevel.title('Tạo chữ ký')
        create_digital_signature_toplevel.geometry('600x500')
    def create_dc():
        create_digital_signature_toplevel = tk.Toplevel()
        create_digital_signature_toplevel.title('Tạo chữ ký')
        create_digital_signature_toplevel.geometry('600x500')
    def verify():
        verify_digital_signature_toplevel = tk.Toplevel()
        verify_digital_signature_toplevel.title('Xác minh nguồn gốc tệp tin')
        verify_digital_signature_toplevel.geometry('600x500')
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
                    title="Open", filetypes=(("Text files", "*.txt"),
                                             ("Image files", "*.jpg"),
                                             ("Encoded files", "*.enc"),
                                             ("All files", "*.*")))
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
