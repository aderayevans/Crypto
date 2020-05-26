import tkinter as tk


class MainGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        tk.Button(self, text="Open Toplevel", command=self.open_toplevel_window).pack()

    def open_toplevel_window(self):
        OtherGUI(self)
        self.withdraw()


class OtherGUI(tk.Toplevel):
    def __init__(self, master):
        super().__init__()
        tk.Button(self, text="Close top and deiconify main", command=self.main_window).pack()

    def main_window(self):
        self.master.deiconify()
        self.destroy()


MainGUI().mainloop()
