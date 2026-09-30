import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# Підтягуємо номер варіанту
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER


class ValidationError(Exception):
    pass


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")

# Сіль з 5 символів (для 1 варіанту буде 00001)
SALT = str(VARIANT_NUMBER).zfill(5)
MIN_LENGTH = 12


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Порожні дані")
    if len(password) < MIN_LENGTH:
        raise ValidationError("Пароль надто короткий")
    return hashlib.sha3_512((password + salt).encode("utf-8")).hexdigest()


# Декоратор для логування
def log_event(func):
    def wrapper(username, password):
        result = "failure"
        try:
            is_success = func(username, password)
            if is_success:
                result = "success"
            return is_success
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            logs = []
            if os.path.exists(LOG_JSON):
                with open(LOG_JSON, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            logs.append(log_entry)
            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4)

    return wrapper


def create_user(username, password):
    return username, generate_hash(password, SALT)


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_CSV, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["login", "password_hash"])
        for user, pwd in users_list:
            try:
                login_str, pwd_hash = create_user(user, pwd)
                writer.writerow([login_str, pwd_hash])
                print(
                    f" [+] Юзер [{login_str:<8}] зареєстрований. Хеш: {pwd_hash[:20]}..."
                )
            except ValidationError as e:
                print(f" [-] Відхилено [{user:<8}]: {e}")
            except ValueError as e:
                print(f" [-] Відхилено [{user:<8}]: {e}")


# Глобальний список для зберігання бази
users_db = []


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми")

    # Хешуємо введений пароль для порівняння
    try:
        expected_hash = generate_hash(password, SALT)
    except ValidationError:
        return False  # Якщо пароль надто короткий, він точно не співпаде

    # Перевіряємо, чи є юзер і чи збігається хеш
    for db_user, db_hash in users_db:
        if db_user == username and db_hash == expected_hash:
            return True
    return False


def run_db_tasks():
    print("--- Завдання 3 ---")

    # 10 користувачів, як вимагає завдання
    users_to_register = (
        ("admin", "SuperSecurePass123!"),
        ("bob", "Short"),
        ("alice", "AliceStrongPass!"),
        ("charlie", "Charlie1234567"),
        ("david", "DavidPass123!"),
        ("eve", "EveHackerKey!!"),
        ("frank", "FrankSecure12"),
        ("grace", "GracePassword!"),
        ("heidi", "HeidiSecret99"),
        ("ivan", "IvanPass2026!"),
    )

    print("1. Створення бази користувачів (users.csv)...")
    create_users(users_to_register)

    print("\n2. Читання бази даних у список users_db...")
    users_db.clear()
    if os.path.exists(USERS_CSV):
        with open(USERS_CSV, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)  # Пропускаємо заголовок
            for row in reader:
                if row:
                    users_db.append((row[0], row[1]))

    # Вивід у вигляді структурованої таблиці
    print(f"{'Логін':<10} | {'Хеш (перші 30 символів)':<30}")
    print("-" * 45)
    for user, pwd_hash in users_db:
        print(f"{user:<10} | {pwd_hash[:30]}...")

    print("\n3. Перевірка реальної авторизації (login)...")
    print(
        f" [*] Вхід [admin] (правильний пароль) -> {'Успіх' if login('admin', 'SuperSecurePass123!') else 'Відмовлено'}"
    )
    print(
        f" [*] Вхід [alice] (неправильний пароль)-> {'Успіх' if login('alice', 'WrongPass!') else 'Відмовлено'}"
    )
    print(
        f" [*] Вхід [hacker] (немає в базі)     -> {'Успіх' if login('hacker', '123456789012') else 'Відмовлено'}"
    )

    print(" [*] Спроба входу з порожнім паролем...")
    try:
        login("admin", "")
    except ValueError as e:
        print(f" [-] Перехоплено виняток ValueError: {e}")

    print("\n4. Вміст файлу журналу (log.json):")
    if os.path.exists(LOG_JSON):
        with open(LOG_JSON, "r", encoding="utf-8") as f:
            print(f.read())

    print("\nЗавдання 3 завершено!\n")


if __name__ == "__main__":
    run_db_tasks()
