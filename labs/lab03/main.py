from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared import student


# Lifespan: код, який автоматично виконується під час запуску та зупинки сервера
@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Під час запуску створюємо відсутні таблиці, але не перезаписуємо дані[cite: 13]
    initialize_database()
    yield

app = FastAPI(
    title="Реєстр вразливостей вебзастосунку",
    description="API для обліку знахідок перевірки вебзастосунку. Одиниця вимірювання: оцінка небезпеки (від 0 до 10).",
    version="1.0.0",
    lifespan=lifespan
)

# Підключаємо маршрути
app.include_router(categories.router)
app.include_router(records.router)

@app.get("/ping")
def ping():
    """Перевірка доступності API."""
    return {"status": "ok"}

@app.get("/student")
def get_student():
    """Дані про студента."""
    return {
        "student_name": student.STUDENT_NAME,
        "group_name": student.GROUP_NAME,
        "variant_number": student.VARIANT_NUMBER
    }