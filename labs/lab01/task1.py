import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER

passwords = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"password", "123456", "admin", "test", "welcome", "qwerty"}


def analyze_passwords():
    print("--- Завдання 1 ---")
    print(f"Варіант: {VARIANT_NUMBER}")
    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords.append(passwords[idx])

    for pwd in passwords:
        length = len(pwd)
        is_forbidden = (
            pwd.lower() in forbidden_passwords or length < criteria["min_length"]
        )
        has_digit = any(char.isdigit() for char in pwd)
        has_upper = any(char.isupper() for char in pwd)
        has_lower = any(char.islower() for char in pwd)
        has_special = any(not char.isalnum() for char in pwd)

        meets_all = has_digit and has_upper and has_lower and has_special
        meets_some = has_digit or has_upper or has_lower or has_special

        if is_forbidden:
            status = "Заборонений"
        elif (
            meets_all
            and length >= criteria["min_length"] + 4
            and passwords.count(pwd) == 1
        ):
            status = "Дуже сильний"
        elif meets_all and length >= criteria["min_length"]:
            status = "Сильний"
        elif length >= criteria["min_length"] and meets_some:
            status = "Середній"
        else:
            status = "Слабкий"

        print(f"{pwd:<20} | {status:<15}")
    print("\n")
