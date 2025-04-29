



import tkinter as tk
from gui_components import ask_master, build_main_window

if __name__ == '__main__':
    root = tk.Tk()
    key = ask_master(root)
    build_main_window(root, key)
    root.mainloop()