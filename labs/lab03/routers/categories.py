import sqlite3

from fastapi import APIRouter, HTTPException, status

from labs.lab03 import repository, schemas

router = APIRouter(prefix="/categories", tags=["Categories"])

@router.get("", response_model=list[schemas.CategoryRead])
def read_categories():
    """Отримати список усіх категорій."""
    return repository.get_categories()

@router.post("", response_model=schemas.CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: schemas.CategoryCreate):
    """Створити нову категорію."""
    try:
        return repository.create_category(category.name)
    except sqlite3.IntegrityError:
        # Якщо така категорія вже є (порушення UNIQUE) — повертаємо 409 Conflict
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія з такою назвою вже існує"
        )

@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    """Видалити порожню категорію."""
    try:
        success = repository.delete_category(category_id)
        if not success:
            # Якщо категорії з таким ID немає — повертаємо 404 Not Found
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Категорію не знайдено"
            )
    except sqlite3.IntegrityError:
        # Якщо в категорії є записи (спрацював ON DELETE RESTRICT) — повертаємо 409 Conflict
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Неможливо видалити категорію: вона містить записи"
        )