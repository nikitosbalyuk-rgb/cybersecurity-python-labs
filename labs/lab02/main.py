import argparse

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import analyze_access_log


def run_demo():
    print("--- Демонстрація Завдання 1 ---")

    # Створення користувача
    user1 = User("m.baliuk", "mykyta@polytech.lviv.ua")
    user1.set_password("SecureP@ssw0rd!")
    print(user1)

    # Перевірка валідації пошти
    try:
        user1.email = "bad-email.com"
    except ValueError as e:
        print(f"Помилка валідації: {e}")

    user1.email = "mykyta.new@lviv.ua"
    print(f"Новий email: {user1.email}")

    # Адміністратор і права
    admin = Admin("root_admin", "admin@corp.local")
    admin.grant_permission("READ_LOGS")
    admin.grant_permission("MANAGE_USERS")
    print(admin)

    # Робота з обліковим записом та сесіями
    account = UserAccount(user=user1)

    print("\nВхід з неправильним паролем:")
    account.login("m.baliuk", "12345", "192.168.1.55")
    print(f"Авторизований: {account.is_authenticated()}")

    print("Вхід з правильним паролем:")
    account.login("m.baliuk", "SecureP@ssw0rd!", "192.168.1.55")
    print(f"Авторизований: {account.is_authenticated()}")

    # Вихід
    account.logout()
    print(f"Авторизований після виходу: {account.is_authenticated()}")

    # Вивід записів аудиту
    audit = account["audit_log"]
    audit.show_all()


def main():
    parser = argparse.ArgumentParser(description="ЛР2 - Аналізатор логів")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Команда demo (для Завдання 1)
    subparsers.add_parser("demo")

    # Команда analyze (для Завдання 2)
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument(
        "--log-file", required=True, help="Шлях до файлу access.log"
    )
    analyze_parser.add_argument("--output", required=True, help="Шлях до файлу звіту")
    analyze_parser.add_argument(
        "--min-status", type=int, default=400, help="Мінімальний статус код помилки"
    )
    analyze_parser.add_argument(
        "--top", type=int, default=5, help="Кількість IP у топі"
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат звіту (json або csv)",
    )

    args = parser.parse_args()

    # Виклик відповідного завдання залежно від команди
    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_access_log(
            log_path=args.log_file,
            output_path=args.output,
            min_status=args.min_status,
            top_n=args.top,
            report_format=args.format,
        )


if __name__ == "__main__":
    main()
