# Імпортуємо код з усіх інших файлів
from task1 import analyze_passwords
from task2 import check_access
from task3 import run_db_tasks


# Головна функція, яка запускає всю лабораторну по черзі
def main():
    print("=== Лабораторна робота №1 ===")
    analyze_passwords()
    check_access()
    run_db_tasks()


# Стандартна точка входу для запуску
if __name__ == "__main__":
    main()