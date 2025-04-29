

import json
import base64
import random
import string
from typing import Dict
from cryptography.fernet import Fernet


# ---------- Шифрование ----------
def generate_key() -> bytes:
    return Fernet.generate_key()

def encrypt_password(password: str, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password).decode()


# ---------- Работа с паролями ----------
def generate_random_password(length: int = 12) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def save_passwords(passwords: Dict[str, str], filename: str = "passwords.json") -> None:
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(passwords, f, indent=2)

def load_passwords(filename: str = "passwords.json") -> Dict[str, str]:
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# ---------- Главное меню ----------
def main():
    key_file = "secret.key"

    # Загрузка ключа
    try:
        with open(key_file, 'rb') as f:
            key = f.read()
    except FileNotFoundError:
        key = generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        print("🔑 Сгенерирован и сохранён новый ключ шифрования.")

    passwords = load_passwords()

    while True:
        print("\nМеню:")
        print("1. Добавить новый пароль")
        print("2. Посмотреть сохранённый пароль")
        print("3. Сгенерировать случайный пароль")
        print("4. Выход")

        choice = input("Выберите действие: ")

        if choice == '1':
            site = input("Введите название сайта/сервиса: ")
            password = input("Введите пароль: ")

            encrypted = encrypt_password(password, key)
            encoded = base64.b64encode(encrypted).decode('utf-8')
            passwords[site] = encoded
            save_passwords(passwords)
            print("✅ Пароль успешно сохранён.")

        elif choice == '2':
            site = input("Введите название сайта/сервиса: ")
            if site in passwords:
                encoded = passwords[site]
                encrypted = base64.b64decode(encoded)
                decrypted = decrypt_password(encrypted, key)
                print(f"🔓 Пароль для {site}: {decrypted}")
            else:
                print("⚠️ Пароль не найден.")

        elif choice == '3':
            length = int(input("Введите желаемую длину пароля: "))
            generated = generate_random_password(length)
            print(f"🔐 Сгенерированный пароль: {generated}")

        elif choice == '4':
            print("👋 До свидания!")
            break

        else:
            print("⛔ Неверный выбор. Попробуйте снова.")



if __name__=="__main__":
    main()