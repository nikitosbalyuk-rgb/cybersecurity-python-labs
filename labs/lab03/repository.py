import sqlite3
from typing import Any

from labs.lab03.database import get_connection


def dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    """Перетворює рядки SQLite на словники для зручної роботи."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# --- ОПЕРАЦІЇ З КАТЕГОРІЯМИ ---

def get_categories() -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return cursor.fetchall()
    finally:
        conn.close()


def create_category(name: str) -> dict[str, Any]:
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        with conn:
            cursor.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            new_id = cursor.lastrowid
        cursor.execute("SELECT id, name FROM categories WHERE id = ?", (new_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def delete_category(category_id: int) -> bool:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        with conn:
            cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


# --- ОПЕРАЦІЇ ІЗ ЗАПИСАМИ (ВРАЗЛИВОСТЯМИ) ---

def get_record(record_id: int) -> dict[str, Any] | None:
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, c.name as category_name 
            FROM records r 
            JOIN categories c ON r.category_id = c.id 
            WHERE r.id = ?
        """, (record_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def get_records(
        category_id: int | None = None,
        status: str | None = None,
        min_value: float | None = None,
        q: str | None = None,
        limit: int = 20,
        offset: int = 0
) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()

        # Динамічно збираємо SQL-запит залежно від переданих фільтрів
        query = """
            SELECT r.*, c.name as category_name 
            FROM records r 
            JOIN categories c ON r.category_id = c.id 
            WHERE 1=1
        """
        params = []

        if category_id is not None:
            query += " AND r.category_id = ?"
            params.append(category_id)
        if status is not None:
            query += " AND r.status = ?"
            params.append(status)
        if min_value is not None:
            query += " AND r.value >= ?"
            params.append(min_value)
        if q is not None:
            query += " AND instr(r.title, ?) > 0"
            params.append(q)

        query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        conn.close()


def create_record(record: dict[str, Any]) -> dict[str, Any]:
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        with conn:
            cursor.execute("""
                INSERT INTO records (code, title, category_id, value, status) 
                VALUES (?, ?, ?, ?, ?)
            """, (record["code"], record["title"], record["category_id"], record["value"], record["status"]))
            new_id = cursor.lastrowid

        return get_record(new_id)
    finally:
        conn.close()


def update_record(record_id: int, record: dict[str, Any]) -> dict[str, Any] | None:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        with conn:
            cursor.execute("""
                UPDATE records 
                SET code = ?, title = ?, category_id = ?, value = ?, status = ? 
                WHERE id = ?
            """, (record["code"], record["title"], record["category_id"], record["value"], record["status"], record_id))

            if cursor.rowcount == 0:
                return None

        return get_record(record_id)
    finally:
        conn.close()


def delete_record(record_id: int) -> bool:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        with conn:
            cursor.execute("DELETE FROM records WHERE id = ?", (record_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def create_records_bulk(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Пакетне додавання записів у межах однієї транзакції."""
    conn = get_connection()
    try:
        conn.row_factory = dict_factory
        cursor = conn.cursor()

        created_ids = []
        # with conn гарантує, що якщо хоч один запис викличе помилку, уся група не збережеться
        with conn:
            for record in records:
                cursor.execute("""
                    INSERT INTO records (code, title, category_id, value, status) 
                    VALUES (?, ?, ?, ?, ?)
                """, (record["code"], record["title"], record["category_id"], record["value"], record["status"]))
                created_ids.append(cursor.lastrowid)

        # Дістаємо всі щойно створені записи для повернення клієнту
        placeholders = ",".join("?" * len(created_ids))
        cursor.execute(f"""
            SELECT r.*, c.name as category_name 
            FROM records r 
            JOIN categories c ON r.category_id = c.id 
            WHERE r.id IN ({placeholders})
            ORDER BY r.id ASC
        """, tuple(created_ids))
        return cursor.fetchall()
    finally:
        conn.close()