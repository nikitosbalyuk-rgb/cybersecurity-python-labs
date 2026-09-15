import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER


class ValidationError(Exception):
    pass


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")
SALT = str(VARIANT_NUMBER).zfill(5)
MIN_LENGTH = 12


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Порожні дані")
    if len(password) < MIN_LENGTH:
        raise ValidationError("Пароль надто короткий")
    return hashlib.sha3_512((password + salt).encode("utf-8")).hexdigest()


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


def run_db_tasks():
    print("--- Завдання 3 ---")
    users_to_register = (("admin", "SuperSecurePass123!"), ("bob", "Short"))

    with open(USERS_CSV, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["login", "password_hash"])
        for user, pwd in users_to_register:
            try:
                writer.writerow(create_user(user, pwd))
            except ValidationError as e:
                print(f"Помилка {user}: {e}")
    print("Базу створено. Готово!")
