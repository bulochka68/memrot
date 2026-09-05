"""Долгоживущие API-ключи для headless-доступа к агенту (автотестирование).

Общий модуль для Streamlit UI (генерация/отзыв) и app/api_server.py (валидация
входящих запросов) — единый формат ключа и способ его хеширования.
"""

import hashlib
import secrets

from app.memory.models import ApiKey

_PREFIX = "sk-genai-"


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_key(user_id: str, label: str = "") -> tuple[str, ApiKey]:
    """Вернуть (сырой_ключ, запись_для_хранения). Сырой ключ нигде не сохраняется —
    вызывающий код обязан показать его пользователю один раз и забыть.
    """
    raw_key = _PREFIX + secrets.token_urlsafe(32)
    record = ApiKey(
        key_hash=hash_key(raw_key),
        key_prefix=raw_key[: len(_PREFIX) + 6],
        user_id=user_id,
        label=label,
    )
    return raw_key, record
