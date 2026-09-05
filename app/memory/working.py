"""Рабочая память (Redis)."""

import json
import redis

from app.config import get_settings
from app.memory.models import MessageTurn, WorkingMemory


class WorkingMemoryStore:
    def __init__(self, client: redis.Redis | None = None):
        settings = get_settings()
        self._client = client or redis.from_url(settings.redis_url, decode_responses=True)
        self._ttl = settings.working_memory_ttl

    def _key(self, user_id: str, session_id: str) -> str:
        return f"working:{user_id}:{session_id}"

    def get(self, user_id: str, session_id: str) -> WorkingMemory:
        raw = self._client.get(self._key(user_id, session_id))
        if not raw:
            return WorkingMemory()
        data = json.loads(raw)
        messages = [MessageTurn.model_validate(m) for m in data.get("messages", [])]
        return WorkingMemory(
            messages=messages,
            summary=data.get("summary", ""),
            metadata=data.get("metadata", {}),
        )

    def save(self, user_id: str, session_id: str, memory: WorkingMemory) -> None:
        payload = {
            "messages": [m.model_dump(mode="json") for m in memory.messages],
            "summary": memory.summary,
            "metadata": memory.metadata,
        }
        self._client.setex(
            self._key(user_id, session_id),
            self._ttl,
            json.dumps(payload, default=str),
        )

    def append_message(
        self, user_id: str, session_id: str, role: str, content: str
    ) -> WorkingMemory:
        mem = self.get(user_id, session_id)
        mem.messages.append(MessageTurn(role=role, content=content))  # type: ignore[arg-type]
        self.save(user_id, session_id, mem)
        return mem

    def clear(self, user_id: str, session_id: str) -> None:
        self._client.delete(self._key(user_id, session_id))

    def list_sessions(self, user_id: str) -> list[tuple[str, WorkingMemory]]:
        """Все ещё не истёкшие (TTL) сессии рабочей памяти пользователя — для страницы
        отладки памяти. SCAN, а не KEYS — не блокирует Redis, что дороже, чем оправдано
        для маленького тестового стенда, но не блокирующий вариант ничего не стоит."""
        prefix = self._key(user_id, "")
        out = []
        for key in self._client.scan_iter(match=prefix + "*"):
            session_id = key[len(prefix):]
            out.append((session_id, self.get(user_id, session_id)))
        return out
