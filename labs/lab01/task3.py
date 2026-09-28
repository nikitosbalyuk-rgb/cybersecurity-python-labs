import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# Підтягуємо номер варіанту з нашого спільного файлу
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER


# Власна помилка для перевірки пароля
class ValidationError(Exception):
    pass


# Налаштовуємо шляхи для збереження файлів
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")

# Робимо сіль з 5 символів з нулями зліва (для 1 варіанту буде 00001)
SALT = str(VARIANT_NUMBER).zfill(5)
MIN_LENGTH = 12


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Порожні дані")
    if len(password) < MIN_LENGTH:
        raise ValidationError("Пароль надто короткий")

    # Змішуємо пароль із сіллю та хешуємо
    return hashlib.sha3_512((password + salt).encode("utf-8")).hexdigest()


# Декоратор, щоб автоматично записувати логи входу
def log_event(func):
    def wrapper(username, password):
        result = "failure"
        try:
            is_success = func(username, password)
            if is_success:
                result = "success"
            return is_success
        finally:
            # Формуємо словник для json-файлу
            log_entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Читаємо старі логи (якщо є) і дописуємо нові
            logs = []
            if os.path.exists(LOG_JSON):
                with open(LOG_JSON, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            logs.append(log_entry)

            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4)

    return wrapper


# Чіпляємо наш декоратор на тестову функцію входу
@log_event
def dummy_login(username, password):
    # Імітуємо, що успішно входить тільки admin
    return username == "admin"


def create_user(username, password):
    return username, generate_hash(password, SALT)


def run_db_tasks():
    print("--- Завдання 3 ---")
    users_to_register = (("admin", "SuperSecurePass123!"), ("bob", "Short"))

    # Створюємо папку data, якщо вона раптом видалена
    os.makedirs(DATA_DIR, exist_ok=True)

    print("1. Створення бази користувачів (users.csv)...")
    # Відкриваємо файл і записуємо користувачів
    with open(USERS_CSV, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["login", "password_hash"])

        for user, pwd in users_to_register:
            try:
                login, pwd_hash = create_user(user, pwd)
                writer.writerow([login, pwd_hash])
                print(f" [+] Юзер [{login:<5}] зареєстрований. Хеш: {pwd_hash[:20]}...")
            except ValidationError as e:
                print(f" [-] Відхилено [{user:<5}]: {e}")

    print("\n2. Перевірка системи логування (log.json)...")
    is_admin = dummy_login("admin", "SuperSecurePass123!")
    print(f" [*] Спроба входу [admin]  -> {'Дозволено' if is_admin else 'Відмовлено'}")

    is_hacker = dummy_login("hacker", "123456")
    print(f" [*] Спроба входу [hacker] -> {'Дозволено' if is_hacker else 'Відмовлено'}")

    print("\n3. Вміст файлу журналу (log.json):")
    if os.path.exists(LOG_JSON):
        with open(LOG_JSON, "r", encoding="utf-8") as f:
            print(f.read())
    else:
        print("Файл журналу порожній або не створений.")

    print("\nЗавдання 3 завершено. Бази даних оновлено!\n")


# Дозволяє запускати файл окремо
if __name__ == "__main__":
    run_db_tasks()