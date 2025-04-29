import tkinter as tk
from tkinter import messagebox, ttk
import json
import base64
import os
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"
DATA_FILE = "passwords.json"


def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key


def save_password(site, password):
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    encoded = base64.b64encode(encrypted).decode('utf-8')

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = {}

    data[site] = encoded
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    messagebox.showinfo("Успешно", f"Пароль для {site} сохранён!")
    site_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    update_services_list()


def show_password_window(site: str, password: str):
    """Открывает окно с показом пароля и кнопкой копирования."""
    win = tk.Toplevel(root)
    win.title(f"Пароль для {site}")
    win.resizable(False, False)
    win.geometry("300x120")

    tk.Label(win, text=f"{site}:", font=("Arial", 10, "bold")).pack(pady=(10, 0))
    pwd_entry = tk.Entry(win, width=30, justify="center")
    pwd_entry.insert(0, password)
    pwd_entry.configure(state="readonly")
    pwd_entry.pack(pady=5)

    def copy_to_clipboard():
        win.clipboard_clear()
        win.clipboard_append(password)
        #messagebox.showinfo("Скопировано", "Пароль скопирован в буфер обмена.")

    tk.Button(win, text="Копировать пароль", command=copy_to_clipboard).pack(pady=(0, 10))


def get_password(site):
    if not os.path.exists(DATA_FILE):
        messagebox.showwarning("Ошибка", "Файл с паролями не найден.")
        return
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if site not in data:
        messagebox.showwarning("Нет записи", f"Пароль для {site} не найден.")
        return

    # Дешифруем
    key = load_key()
    fernet = Fernet(key)
    encrypted = base64.b64decode(data[site])
    decrypted = fernet.decrypt(encrypted).decode()

    # Показываем в отдельном окне с кнопкой копирования
    show_password_window(site, decrypted)


def show_services():
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("Список сервисов", "Нет сохранённых паролей.")
        return
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not data:
        messagebox.showinfo("Список сервисов", "Пока ничего не сохранено.")
        return

    services = "\n".join(data.keys())
    top = tk.Toplevel(root)
    top.title("Сохранённые сервисы")
    tk.Label(top, text="Сервисы:", font=("Arial", 12, "bold")).pack(padx=10, pady=(10, 0))
    text = tk.Text(top, width=40, height=10, wrap="word", state="normal")
    text.insert("1.0", services)
    text.configure(state="disabled")
    text.pack(padx=10, pady=10)


def update_services_list():
    if not os.path.exists(DATA_FILE):
        service_combobox['values'] = []
        return
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    service_combobox['values'] = list(data.keys())


# --- GUI ---
root = tk.Tk()
root.title("Менеджер Паролей")
root.resizable(False, False)

# Ввод сайта/сервиса
tk.Label(root, text="Сайт/Сервис:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
site_entry = tk.Entry(root, width=30)
site_entry.grid(row=0, column=1, padx=5, pady=5)

# Ввод пароля
tk.Label(root, text="Пароль:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
password_entry = tk.Entry(root, width=30, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

# Кнопки сохранить/показать
tk.Button(root, text="Сохранить", width=15,
          command=lambda: save_password(site_entry.get(), password_entry.get())) \
    .grid(row=2, column=0, padx=5, pady=10)
tk.Button(root, text="Показать пароль", width=15,
          command=lambda: get_password(site_entry.get())) \
    .grid(row=2, column=1, padx=5, pady=10)

# Combobox для выбора сохранённых сервисов
tk.Label(root, text="Выбрать сервис:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
service_combobox = ttk.Combobox(root, width=28, state="readonly")
service_combobox.grid(row=3, column=1, padx=5, pady=5)

tk.Button(root, text="Показать пароль выбранного", width=32,
          command=lambda: get_password(service_combobox.get())) \
    .grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Кнопка показа всех сервисов
tk.Button(root, text="Показать все сервисы", width=32,
          command=show_services) \
    .grid(row=5, column=0, columnspan=2, padx=5, pady=10)

# Инициализация списка сервисов
update_services_list()

root.mainloop()
