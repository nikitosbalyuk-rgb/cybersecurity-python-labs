from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# --- МОДЕЛІ ДЛЯ КАТЕГОРІЙ ---

class CategoryCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,  # Автоматично обрізає пробіли по краях
        extra="forbid",  # Забороняє передавати невідомі поля (наприклад, "hacker_data")
    )
    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    id: int = Field(gt=0)


# --- МОДЕЛІ ДЛЯ ЗАПИСІВ (ВРАЗЛИВОСТЕЙ) ---

class RecordCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)

    # Для Варіанта 1: оцінка від 0 до 10, нескінченність (NaN) заборонена
    value: float = Field(ge=0, le=10, allow_inf_nan=False)

    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    # Усі змінювані поля в PUT обов'язкові, тому просто успадковуємо RecordCreate
    pass


class RecordRead(RecordCreate):
    id: int = Field(gt=0)
    category_name: str