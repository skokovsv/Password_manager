import os

# Папка для данных
APP_DIR    = os.path.join(os.path.expanduser("~"), ".password_manager")
# Создаем директорию при импорте
os.makedirs(APP_DIR, exist_ok=True)

# Пути к файлам
SALT_FILE  = os.path.join(APP_DIR, "salt.bin")
DATA_FILE  = os.path.join(APP_DIR, "passwords.json")
VERIFY_KEY = "__verify__"

# Параметры KDF
KDF_ITERATIONS = 200_000