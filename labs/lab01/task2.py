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
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

# Повний список з 10 ресурсів
resources = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

security_levels = ("Public", "Internal", "Confidential", "Secret")
# Повний чорний список
blocked_users = {"contractor99", "temp_user", "suspended_acc"}


def check_access():
    print("--- Завдання 2 ---")

    print("Список усіх ресурсів у системі:")
    for res_name, res_level in resources:
        # Витягуємо текстову назву рівня безпеки з кортежу
        level_name = security_levels[res_level - 1]
        print(f" [Ресурс] {res_name:<18} | Рівень безпеки: {level_name}")
    print("-" * 65)

    # Автоматично беремо всіх користувачів з бази і додаємо одного неіснуючого для перевірки
    test_users = list(users.keys()) + ["unknown_user"]

    for username in test_users:
        for res_name, res_level in resources:
            user_clearance = (
                users[username].get("clearance", 0) if username in users else 0
            )

            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username].get("active"):
                status = "DENY (Account inactive)"
            elif user_clearance >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            print(f"user=[{username:<12}] resource=[{res_name:<18}] -> {status}")
    print("\n")


if __name__ == "__main__":
    check_access()
