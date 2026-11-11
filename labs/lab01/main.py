# Імпортуємо код з усіх інших файлів
from task1 import analyze_passwords
from task2 import check_access
from task3 import main as task3_main


# Головна функція, яка запускає всю лабораторну по черзі
def main():
    print("=== Лабораторна робота №1 ===")
    analyze_passwords()
    check_access()
    task3_main()


# Стандартна точка входу для запуску
if __name__ == "__main__":
    main()
