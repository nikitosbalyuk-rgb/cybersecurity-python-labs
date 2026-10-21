import json
import sqlite3

from labs.lab03.database import BASE_DIR, get_connection

SEED_FILE = BASE_DIR / "data" / "seed.json"


def seed_database():
    if not SEED_FILE.exists():
        print(f"Файл {SEED_FILE} не знайдено!")
        return

    with open(SEED_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    connection = get_connection()

    try:
        # Перевіряємо, чи база вже не заповнена (щоб не дублювати)
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            print("База даних вже містить записи. Пропускаємо заповнення.")
            return

        # Контекстний менеджер with connection гарантує виконання транзакції
        with connection:
            # Спочатку додаємо категорії (бо на них посилаються зовнішні ключі)
            for cat in data["categories"]:
                connection.execute(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    (cat["id"], cat["name"])
                )

            # Потім додаємо записи про вразливості
            for rec in data["records"]:
                connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                    (rec["code"], rec["title"], rec["category_id"], rec["value"], rec["status"])
                )
        print("Базу даних успішно заповнено навчальними даними Варіанта 1!")

    except sqlite3.IntegrityError as e:
        print(f"Помилка цілісності даних. Транзакцію повністю скасовано: {e}")
    except Exception as e: # noqa: BLE001
        print(f"Неочікувана помилка: {e}")
    finally:
        connection.close()


if __name__ == "__main__":
    seed_database()