"""Pydantic-схемы для уровней памяти."""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MessageTurn(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str
    ts: datetime = Field(default_factory=utc_now)


class WorkingMemory(BaseModel):
    messages: list[MessageTurn] = Field(default_factory=list)
    summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DialogSession(BaseModel):
    user_id: str
    session_id: str
    messages: list[MessageTurn] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None
    source: str = "user_interaction"


class EpisodicMemory(BaseModel):
    episode_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    session_id: str
    summary: str
    source_session: str
    created_at: datetime = Field(default_factory=utc_now)
    source: str = "orchestrator"


class SemanticMemory(BaseModel):
    fact_id: str = Field(default_factory=lambda: str(uuid4()))
    fact: str
    scope: Literal["user", "global"] = "user"
    user_id: str | None = None
    confidence: float = 0.8
    source_episode_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    source: str = "orchestrator"


class ApiKey(BaseModel):
    """Долгоживущий API-ключ для headless-доступа к агенту (автотестирование — promptfoo
    и подобные тулы). В отличие от SSO-токена Keycloak (5 минут), не истекает сам по себе,
    только по явному отзыву. Хранится только hash — сырой ключ показывается в UI один раз.
    """

    key_id: str = Field(default_factory=lambda: str(uuid4()))
    key_hash: str
    key_prefix: str
    user_id: str
    label: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    revoked: bool = False


class AgentPolicyMemory(BaseModel):
    """Уровень памяти, не привязанный к пользователю — общая "политика"/дообучение агента.

    Структурно не содержит user_id: любой пользователь, чья сессия сформировала такой
    факт, влияет на поведение агента для ВСЕХ клиентов. source_session_id — только для
    аудита (кто именно это записал), не используется для scoping/фильтрации при чтении.
    """

    policy_id: str = Field(default_factory=lambda: str(uuid4()))
    statement: str
    confidence: float = 0.8
    source_session_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    source: str = "orchestrator"
