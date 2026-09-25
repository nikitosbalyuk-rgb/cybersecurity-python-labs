# База користувачів з їхніми ролями та рівнями доступу
users = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

# Ресурси системи та їх необхідний рівень доступу
resources = [("database_backup", 4), ("user_logs", 2), ("public_docs", 1)]
security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user"}  # Множина для швидкого пошуку


def check_access():
    print("--- Завдання 2 ---")

    # Список юзерів для тестування доступу
    test_users = ["admin001", "user123", "contractor99", "unknown_user"]

    for username in test_users:
        for res_name, res_level in resources:
            # Отримуємо рівень доступу користувача (якщо юзера немає, пишемо "N/A")
            user_clearance = users[username].get("clearance", 0) if username in users else "N/A"
            # Основна логіка: перевіряємо всі умови відмови і дозволу
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username].get("active"):
                status = "DENY (Account inactive)"
            elif users[username].get("clearance", 0) >= res_level:
                status = "ALLOW"  # Все добре, пускаємо
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user=[{username}] clearance=[{user_clearance}] resource=[{res_name} (req:{res_level})] -> {status}")
    print("\n")