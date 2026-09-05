"""Клиент стенда для проверки находок аудита вживую (red-team harness).

Переводит статические находки (control_outcome=FAIL) в наблюдаемый результат:
поднятый локальный стенд, реальный HTTP, каждый сценарий привязан к rule_id и
его expected_invariant. Ничего разрушительного: только штатные ручки
/v1/chat/completions и /v1/sessions/{id}/finalize.

Только против СВОЕГО локального стенда. Ключи и адрес — из окружения:
  STAND_URL      (default http://localhost:8600)
  ATTACKER_KEY   API-ключ атакующего (user A)
  VICTIM_KEY     API-ключ жертвы (user B) — другой пользователь
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

STAND_URL = os.environ.get("STAND_URL", "http://localhost:8600")
ATTACKER_KEY = os.environ.get("ATTACKER_KEY", "")
VICTIM_KEY = os.environ.get("VICTIM_KEY", "")


@dataclass
class StandClient:
    """Тонкая обёртка над OpenAI-совместимой ручкой стенда для одного принципала."""
    api_key: str
    base_url: str = STAND_URL
    auth_mode: str = "vulnerable"          # режим стенда: vulnerable | protected
    timeout: float = 60.0
    _http: httpx.Client = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._http = httpx.Client(base_url=self.base_url, timeout=self.timeout)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def chat(self, message: str, session_id: str) -> str:
        """Один ход диалога. Возвращает текст ответа агента."""
        body = {
            "model": "genai-invest-assistant",
            "messages": [{"role": "user", "content": message}],
            "auth_mode": self.auth_mode,
            "session_id": session_id,
            "stream": False,
        }
        r = self._http.post("/v1/chat/completions", headers=self._headers(), json=body)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def finalize(self, session_id: str) -> dict[str, Any]:
        """Прогнать оркестратор финализации: рабочая память → долговременная.
        Возвращает {'episodes': [...], 'facts': [{'fact','scope','confidence'}, ...]}."""
        r = self._http.post(f"/v1/sessions/{session_id}/finalize", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def new_session(self, prefix: str = "rt") -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def close(self) -> None:
        self._http.close()


def attacker() -> StandClient:
    if not ATTACKER_KEY:
        raise RuntimeError("ATTACKER_KEY не задан (экспортируйте API-ключ атакующего)")
    return StandClient(ATTACKER_KEY)


def victim() -> StandClient:
    if not VICTIM_KEY:
        raise RuntimeError("VICTIM_KEY не задан (экспортируйте API-ключ жертвы)")
    return StandClient(VICTIM_KEY)


def global_facts(finalize_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Факты, которые модель пометила scope=global — они уходят в общую политику."""
    return [f for f in (finalize_result.get("facts") or []) if f.get("scope") == "global"]
