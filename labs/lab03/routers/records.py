import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from labs.lab03 import repository, schemas

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[schemas.RecordRead])
def get_records(
        category_id: Annotated[int | None, Query(gt=0)] = None,
        status_param: Annotated[str | None, Query(alias="status")] = None,
        min_value: float | None = None,
        q: Annotated[str | None, Query(max_length=120)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0
):
    """Отримати список записів із фільтрами."""
    return repository.get_records(
        category_id=category_id,
        status=status_param,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset
    )


@router.get("/{record_id}", response_model=schemas.RecordRead)
def get_record(record_id: int):
    """Отримати один запис за ID."""
    record = repository.get_record(record_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено")
    return record


@router.post("", response_model=schemas.RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: schemas.RecordCreate):
    """Створити новий запис."""
    try:
        return repository.create_record(record.model_dump())
    except sqlite3.IntegrityError as e:
        error_msg = str(e).lower()
        if "foreign key" in error_msg:
            # Якщо посилаємося на неіснуючу категорію
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Категорію не знайдено")
        elif "unique" in error_msg:
            # Якщо такий code вже є в базі[cite: 13]
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Запис із таким code вже існує")
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Помилка цілісності даних")


@router.put("/{record_id}", response_model=schemas.RecordRead)
def update_record(record_id: int, record: schemas.RecordReplace):
    """Повна заміна змінюваних полів запису."""
    try:
        updated_record = repository.update_record(record_id, record.model_dump())
        if not updated_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено")
        return updated_record
    except sqlite3.IntegrityError as e:
        error_msg = str(e).lower()
        if "foreign key" in error_msg:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Категорію не знайдено")
        elif "unique" in error_msg:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Запис із таким code вже існує")
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Помилка цілісності даних")


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    """Видалити запис."""
    success = repository.delete_record(record_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено")


@router.post("/bulk", response_model=list[schemas.RecordRead], status_code=status.HTTP_201_CREATED)
def create_records_bulk(records: list[schemas.RecordCreate]):
    """Пакетне створення записів з атомарним збереженням."""
    if not (1 <= len(records) <= 100):
        # Перевірка кількості елементів пакета: від 1 до 100[cite: 13]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Пакет має містити від 1 до 100 записів")

    records_data = [r.model_dump() for r in records]
    try:
        return repository.create_records_bulk(records_data)
    except sqlite3.IntegrityError as e:
        error_msg = str(e).lower()
        if "foreign key" in error_msg:
            # Неіснуюча категорія в пакеті
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Одна з категорій не знайдена")
        elif "unique" in error_msg:
            # Дублікат у базі або всередині самого пакета[cite: 14]
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="Дублікат code в базі або всередині пакета")
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Помилка цілісності даних у пакеті")