"""AttackTarget-адаптер для genai-invest-стенда.

Единственное место, где живут специфичные пути: OpenAI-совместимая ручка,
finalize-оркестратор, поле auth_mode, извлечение published из ответа finalize.
Любая другая система = другой адаптер; сценарии не меняются.
"""
from __future__ import annotations

import os
from typing import Any

from harness import StandClient, global_facts  # переиспользуем готовый HTTP-клиент и фильтр scope=global
from target import Principal


class StandTarget:
    """Реализация AttackTarget поверх StandClient."""

    def __init__(self, attacker_key: str | None = None, victim_key: str | None = None,
                 base_url: str | None = None, auth_mode: str = "vulnerable") -> None:
        self._attacker = Principal("attacker", attacker_key or os.environ.get("ATTACKER_KEY", ""))
        self._victim = Principal("victim", victim_key or os.environ.get("VICTIM_KEY", ""))
        self._base = base_url or os.environ.get("STAND_URL", "http://localhost:8600")
        self._auth_mode = auth_mode
        self._clients: dict[str, StandClient] = {}

    def _client(self, p: Principal) -> StandClient:
        if p.label not in self._clients:
            if not p.token:
                raise RuntimeError(f"нет токена для principal '{p.label}' (задайте ключ в окружении)")
            self._clients[p.label] = StandClient(p.token, base_url=self._base, auth_mode=self._auth_mode)
        return self._clients[p.label]

    # --- интерфейс AttackTarget ---

    def principals(self) -> dict[str, Principal]:
        return {"attacker": self._attacker, "victim": self._victim}

    def new_session(self, prefix: str = "rt") -> str:
        return self._client(self._attacker).new_session(prefix)

    def deliver(self, principal: Principal, text: str, session: str) -> str:
        return self._client(principal).chat(text, session_id=session)

    def trigger_persist(self, principal: Principal, session: str) -> dict[str, Any]:
        raw = self._client(principal).finalize(session)
        # published = факты, помеченные моделью scope=global -> уходят в общую политику
        return {"published": global_facts(raw), "raw": raw}

    def observe(self, principal: Principal, probe: str, session: str | None = None) -> str:
        c = self._client(principal)
        return c.chat(probe, session_id=session or c.new_session("observe"))

    def close(self) -> None:
        for c in self._clients.values():
            c.close()
