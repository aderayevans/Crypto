# -*- coding: utf8 -*-
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image
import tkinter.ttk

def open():
    file = filedialog.askopenfilename(initialdir="D:/",
                    title="Open", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    file_Link.insert(INSERT, file)
    #my_image = ImageTk.PhotoImage(Image.open(root.file))
    #my_image_label = Label(image=my_image)
    #my_image_label.grid(column=1, row=2)
def a():
    mb = Menubutton(window, text="Type", relief=RAISED)
    mb.grid(column=2, row=0)
    mb.menu = Menu(mb, tearoff = 0)
    mb["menu"] = mb.menu
    mayoVar = IntVar()
    ketchVar = IntVar()
    mb.menu.add_checkbutton(label="Text", variable=mayoVar)
    mb.menu.add_checkbutton(label="File", variable=ketchVar)
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
def encryptAF():
    a,b,m = int(affine_key01.get()),int(affine_key02.get()),26
    en_txt = ""
    for c in plain_Txt.get():
    	e = (a*Char2Num(c)+b )%m	#e = [a*(char - 65) + b] mod 26
    	en_txt = en_txt+Num2Char(e)			#r = r + e + 65
    cipher_Txt.delete(0,END)
    cipher_Txt.insert(INSERT,en_txt)
def decryptAF():
    a,b,m = int(affine_key01.get()),int(affine_key02.get()),26
    de_txt = ""
    a1 = xgcd(a,m)
    for c in cipher_Txt.get():
        e = (a1*(Char2Num(c)-b ))%m
        de_txt = de_txt+Num2Char(e)
    plain_Txt.delete(0,END)
    plain_Txt.insert(INSERT,de_txt)
root = Tk()
root.title("Cryptography application")
root.geometry('800x600')

top_frame = Frame(root, width=450, height=50, pady=3)
center = Frame(root, width=50, height=40, padx=3, pady=3)
btm_frame = Frame(root, width=450, height=45, pady=3)
btm_frame2 = Frame(root, bg='grey', width=450, height=60, pady=3)

root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)
top_frame.grid(row=0, sticky="ew")
center.grid(row=1, sticky="nsew")
btm_frame.grid(row=3, sticky="ew")
btm_frame2.grid(row=4, sticky="ew")

plain_Label = Label(top_frame, text="Input text (plain): ",font=("Arial", 14))
plain_Label.grid(column=0, row=0)
plain_Txt = Entry(top_frame,width=80)   #
plain_Txt.grid(column=1, row=0)
cipher_Label = Label(top_frame, text="Input text (cipher): ",font=("Arial", 14))
cipher_Label.grid(column=0, row=1)
cipher_Txt = Entry(top_frame,width=80)   #
cipher_Txt.grid(column=1, row=1)
file_Label = Label(top_frame, text="File: ",font=("Arial", 14))
file_Label.grid(column=0, row=2)
file_Link = Entry(top_frame,width=50)   #
file_Link.grid(column=1, row=2)
file_Button = Button(top_frame, text="Browse", command=open)
file_Button.grid(column=2, row=2)

affine_Label = Label(center, text="Affine: ",font=("Arial Bold", 14))
affine_Label.grid(column=0, row=0)
space_label1 = Label(center, text="              ",font=("Arial", 14))
space_label1.grid(column=0, row=1)
affine_key_Label1 = Label(center, text="A Coefficient  ",font=("Arial", 14))
affine_key_Label1.grid(column=1, row=1)
affine_key01 = Entry(center,width=4)    #
affine_key01.grid(column=2, row=1)
space_label2 = Label(center, text="              ",font=("Arial", 14))
space_label2.grid(column=0, row=2)
affine_key_Label1 = Label(center, text="B Coefficient  ",font=("Arial", 14))
affine_key_Label1.grid(column=1, row=2)
affine_key02 = Entry(center,width=4)    #
affine_key02.grid(column=2, row=2)

#DES_Label = Label(center, text="DES: ",font=("Arial Bold", 14))
#DES_Label.grid(column=0, row=3)
def check_Status():
    print(check_DES.get())
check_DES = IntVar()
DES_checkBut = Checkbutton(center, text = "DES", variable = check_DES, \
                 onvalue = 1, offvalue = 0, height=5, \
                 width = 20, command=check_Status)
DES_checkBut.grid(column=0, row=3)






space_labelen = Label(btm_frame,
                text="                                                          ",
                font=("Arial", 14))
space_labelen.grid(column=0, row=0)
encrypt_Button = Button(btm_frame, text="Encrypt", command=encryptAF)
encrypt_Button.grid(column=1, row=0)
space_labelde = Label(btm_frame, text="         ",font=("Arial", 14))
space_labelde.grid(column=2, row=0)
decrypt_Button = Button(btm_frame, text="Decrypt", command=decryptAF)
decrypt_Button.grid(column=3, row=0)

welcome_Label = Label(btm_frame2, text="Welcome to Cryptography Demo App Ver 1.2020",
                      font=("Arial", 10))
welcome_Label.grid(column=1, row=10)
root.mainloop()
