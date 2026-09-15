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
resources = [("database_backup", 4), ("user_logs", 2), ("public_docs", 1)]
security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user"}


def check_access():
    print("--- Завдання 2 ---")
    test_users = ["admin001", "user123", "contractor99", "unknown_user"]
    for username in test_users:
        for res_name, res_level in resources:
            if username not in users:
                status = "DENY (User not found)"
            elif username in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[username].get("active"):
                status = "DENY (Account inactive)"
            elif users[username].get("clearance", 0) >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"
            print(f"user=[{username}] resource=[{res_name}] -> {status}")
    print("\n")
