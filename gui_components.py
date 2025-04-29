import json
from typing import Dict
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from crypto_utils import derive_key, load_salt
from storage import load_store, save_store, init_verify
from cryptography.fernet import Fernet
import base64
from config import VERIFY_KEY, DATA_FILE


def ask_master(root: tk.Tk) -> bytes:
    # Скрываем окно до ввода
    root.withdraw()
    salt = load_salt()
    while True:
        # Определяем, создаём ли пароль или вводим
        store = load_store()
        is_first = VERIFY_KEY not in store
        if is_first:
            pwd1 = simpledialog.askstring("Создание мастер-пароля", "Введите новый мастер-пароль:", show='*')
            if pwd1 is None:
                messagebox.showinfo("Выход", "Мастер-пароль не введен. Выход.")
                exit()
            pwd2 = simpledialog.askstring("Подтверждение", "Повторите мастер-пароль:", show='*')
            if pwd1 != pwd2:
                messagebox.showwarning("Несоответствие", "Пароли не совпадают.")
                continue
            master_pwd = pwd1
        else:
            master_pwd = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль:", show='*')
            if master_pwd is None:
                messagebox.showinfo("Выход", "Мастер-пароль не введен. Выход.")
                exit()
        # Попытка получить ключ и проверить
        try:
            key = derive_key(master_pwd, salt)
            init_verify(store, key)
            break
        except Exception:
            messagebox.showerror("Ошибка", "Неверный мастер-пароль. Попробуйте снова.")
    root.deiconify()
    return key


def build_main_window(root: tk.Tk, key: bytes):
    root.deiconify()
    root.title("Менеджер Паролей")
    root.resizable(False, False)

    # Основные функции сохранения и получения

    def save_password(site: str, password: str) -> None:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(password.encode())
        encoded = base64.b64encode(encrypted).decode('utf-8')
        with open(DATA_FILE, 'r+', encoding='utf-8') as f:
            data: Dict[str, str] = json.load(f)
            data[site] = encoded
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
        messagebox.showinfo("Успешно", f"Пароль для {site} сохранён!")
        site_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        update_services_list()

    def show_password_window(site: str, password: str) -> None:
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
            messagebox.showinfo("Скопировано", "Пароль скопирован в буфер обмена.")

        tk.Button(win, text="Копировать пароль", command=copy_to_clipboard).pack(pady=(0, 10))

    def get_password(site: str) -> None:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data: Dict[str, str] = json.load(f)
        if site not in data or site == VERIFY_KEY:
            messagebox.showwarning("Нет записи", f"Пароль для {site} не найден.")
            return
        fernet = Fernet(key)
        encrypted = base64.b64decode(data[site])
        decrypted = fernet.decrypt(encrypted).decode()
        show_password_window(site, decrypted)

    def show_services() -> None:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data: Dict[str, str] = json.load(f)
        services = [s for s in data.keys() if s != VERIFY_KEY]
        if not services:
            messagebox.showinfo("Список сервисов", "Пока ничего не сохранено.")
            return
        top = tk.Toplevel(root)
        top.title("Сохранённые сервисы")
        tk.Label(top, text="Сервисы:", font=("Arial", 12, "bold")).pack(padx=10, pady=(10, 0))
        text = tk.Text(top, width=40, height=10, wrap="word", state="normal")
        text.insert("1.0", "\n".join(services))
        text.configure(state="disabled")
        text.pack(padx=10, pady=10)

    def update_services_list() -> None:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data: Dict[str, str] = json.load(f)
        services = [s for s in data.keys() if s != VERIFY_KEY]
        service_combobox['values'] = services

    global site_entry, password_entry, service_combobox
    tk.Label(root, text="Сайт/Сервис:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    site_entry = tk.Entry(root, width=30)
    site_entry.grid(row=0, column=1, padx=5, pady=5)
    tk.Label(root, text="Пароль:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    password_entry = tk.Entry(root, width=30, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)
    tk.Button(root, text="Сохранить", width=15,
              command=lambda: save_password(site_entry.get(), password_entry.get())) \
        .grid(row=2, column=0, padx=5, pady=10)
    tk.Button(root, text="Показать пароль", width=15,
              command=lambda: get_password(site_entry.get())) \
        .grid(row=2, column=1, padx=5, pady=10)
    tk.Label(root, text="Выбрать сервис:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
    service_combobox = ttk.Combobox(root, width=28, state="readonly")
    service_combobox.grid(row=3, column=1, padx=5, pady=5)
    tk.Button(root, text="Показать пароль выбранного", width=32,
              command=lambda: get_password(service_combobox.get())) \
        .grid(row=4, column=0, columnspan=2, padx=5, pady=5)
    tk.Button(root, text="Показать все сервисы", width=32,
              command=show_services) \
        .grid(row=5, column=0, columnspan=2, padx=5, pady=10)