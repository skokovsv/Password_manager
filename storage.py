

import os
import json
import base64
from typing import Dict
from cryptography.fernet import Fernet
from config import DATA_FILE, VERIFY_KEY


def load_store() -> Dict[str, str]:
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_store(store: Dict[str, str]) -> None:
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(store, f, indent=2)


def init_verify(store: Dict[str, str], key: bytes) -> None:
    # Проверка и создание записи VERIFY_KEY
    if VERIFY_KEY in store:
        token_b64 = store[VERIFY_KEY]
        token = base64.b64decode(token_b64)
        Fernet(key).decrypt(token)
    else:
        # создаем verify токен
        token = f"verify_{os.urandom(8).hex()}".encode()
        encrypted = Fernet(key).encrypt(token)
        store[VERIFY_KEY] = base64.b64encode(encrypted).decode('utf-8')
        save_store(store)