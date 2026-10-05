import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Константа кількості ітерацій для хешування пароля (чим більше, тим безпечніше)
HASH_ITERATIONS = 100_000
# Час життя сесії у секундах (15 хвилин)
SESSION_TIMEOUT_SEC = 900


class User:
    """Клас для моделювання базового користувача системи."""

    def __init__(self, username: str, email: str, role: str = "user"):
        self.username = username
        # Присвоюємо email через property-сеттер для миттєвої валідації
        self.email = email
        self.role = role
        self.active = True

        # Приватні атрибути для зберігання пароля, приховані від прямого доступу
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        # Валідація: локальна частина (3-64 символи, починається з літери), @, та домен з крапкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email адреси: {value}")
        self._email = value

    def set_password(self, password: str):
        """Хешує пароль з унікальною сіллю та зберігає в приватні атрибути."""
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode('utf-8'),
            self.__password_salt,
            HASH_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє правильність введеного пароля."""
        if not self.__password_hash or not self.__password_salt:
            return False

        test_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode('utf-8'),
            self.__password_salt,
            HASH_ITERATIONS
        )
        # Використовуємо безпечне порівняння для запобігання атакам за часом
        return hmac.compare_digest(self.__password_hash, test_hash)

    def deactivate(self):
        """Деактивує користувача (блокує обліковий запис)."""
        self.active = False

    def __str__(self) -> str:
        status = "Активний" if self.active else "Заблокований"
        return f"Користувач {self.username} ({self.email}) - Роль: {self.role} [{status}]"


class Admin(User):
    """Клас адміністратора, що наслідує базового користувача."""

    # Не використовуємо змінювану колекцію (set()) як типовий аргумент, щоб уникнути багів
    def __init__(self, username: str, email: str, permissions: set[str] | None = None):
        super().__init__(username, email, role="admin")
        self.permissions = permissions if permissions is not None else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_info = super().__str__()
        perms = ", ".join(self.permissions) if self.permissions else "немає прав"
        return f"{base_info} | Дозволи: {perms}"


class Session:
    """Модель сеансу користувача."""

    def __init__(self, ip: str):
        self.ip = ip
        # Фіксуємо час створення сесії в UTC
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        """Оновлює час останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не сплив час сесії."""
        if timeout_sec <= 0:
            return False

        time_diff = datetime.now(timezone.utc) - self.last_activity
        return time_diff < timedelta(seconds=timeout_sec)


@dataclass
class LogEntry:
    """Клас даних для представлення одного запису аудиту."""
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту для фіксації подій."""

    def __init__(self):
        self.logs: list[LogEntry] = []

    def add_log(self, username: str, action: str):
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action
        )
        self.logs.append(entry)

    def show_all(self):
        print("\n--- Журнал аудиту системи ---")
        for log in self.logs:
            time_fmt = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{time_fmt}] {log.username}: {log.action}")
        print("-----------------------------\n")


class UserAccount:
    """
    Комплексний обліковий запис.
    Реалізує композицію класів User, Session та AuditLog.
    """

    def __init__(self, user: User, session: Session | None = None, audit_log: AuditLog | None = None):
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Спроба входу в систему."""
        # Перевіряємо чи збігається логін з прив'язаним користувачем
        if self.user.username != username:
            self.audit_log.add_log(username, "login_failure (wrong username)")
            return False

        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure (account blocked)")
            return False

        if self.user.check_password(password):
            # Створюємо сесію лише у разі успіху
            self.session = Session(ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure (wrong password)")
            return False

    def is_authenticated(self) -> bool:
        """Перевіряє, чи користувач авторизований (чи жива сесія)."""
        if self.session and self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session.touch()  # Подовжуємо час сесії
            return True
        return False

    def logout(self):
        """Завершує сеанс користувача."""
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str):
        """Дозволяє отримувати компоненти через квадратні дужки, наприклад account['user']."""
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        elif key in ("__password_hash", "__password_salt", "password"):
            raise KeyError("Доступ до хешів та паролів заборонено з міркувань безпеки!")

        raise KeyError(f"Невідомий атрибут: {key}")

    def __setitem__(self, key: str, value):
        """Дозволяє змінювати компоненти, якщо тип відповідає очікуваному."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути об'єктом класу User")
            self.user = value
        else:
            raise KeyError(f"Зміна атрибута '{key}' через словник заборонена")