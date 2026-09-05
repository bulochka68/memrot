"""Фасад MemoryStore — единая точка доступа к памяти."""

from app.config import get_settings
from app.memory.models import (
    AgentPolicyMemory,
    DialogSession,
    EpisodicMemory,
    MessageTurn,
    SemanticMemory,
    WorkingMemory,
)
from app.memory.mongo import MongoMemoryStore
from app.memory.working import WorkingMemoryStore


class MemoryStore:
    def __init__(self):
        self.working = WorkingMemoryStore()
        self.mongo = MongoMemoryStore()
        self._settings = get_settings()

    def build_context(self, user_id: str, session_id: str) -> str:
        """Собрать текстовый блок памяти для промпта агента."""
        parts: list[str] = []

        wm = self.working.get(user_id, session_id)
        if wm.messages or wm.summary:
            parts.append("## Рабочая память (текущая сессия)")
            if wm.summary:
                parts.append(f"Суммаризация: {wm.summary}")
            for m in wm.messages[-10:]:
                parts.append(f"- [{m.role}] {m.content[:500]}")

        dialogs = self.mongo.dialog.list_for_user(
            user_id, limit=self._settings.max_dialog_sessions
        )
        if dialogs:
            parts.append("\n## Диалоговая память (прошлые сессии)")
            for d in dialogs:
                if d.session_id == session_id:
                    continue
                snippet = " | ".join(m.content[:80] for m in d.messages[:3])
                parts.append(f"- Сессия {d.session_id}: {snippet}")

        episodes = self.mongo.episodic.list_for_user(
            user_id, limit=self._settings.max_episodic_memories
        )
        if episodes:
            parts.append("\n## Эпизодическая память")
            for ep in episodes:
                parts.append(f"- [{ep.session_id}] {ep.summary}")

        semantics = self.mongo.semantic.list_for_context(
            user_id, limit=self._settings.max_semantic_memories
        )
        user_facts = [s for s in semantics if s.scope != "global"]
        if user_facts:
            parts.append("\n## Факты о клиенте")
            for s in user_facts:
                parts.append(f"- {s.fact}")

        policies = self.mongo.agent_policy.list_all(limit=self._settings.max_semantic_memories)
        if policies:
            parts.append(
                "\n## Политика агента (действует для всех клиентов, не только для текущего)"
            )
            parts.append("Ниже — правила и рекомендации, которых агент должен придерживаться:")
            for p in policies:
                parts.append(f"- {p.statement}")

        if not parts:
            return ""
        return (
            "Ниже — контекст из памяти агента. Учитывай при ответе, "
            "но проверяй критически.\n\n" + "\n".join(parts)
        )

    def append_turn(
        self,
        user_id: str,
        session_id: str,
        user_message: str,
        assistant_message: str,
    ) -> None:
        self.working.append_message(user_id, session_id, "user", user_message)
        self.working.append_message(user_id, session_id, "assistant", assistant_message)

    def get_working(self, user_id: str, session_id: str) -> WorkingMemory:
        return self.working.get(user_id, session_id)

    def persist_dialog(
        self,
        user_id: str,
        session_id: str,
        messages: list[MessageTurn],
    ) -> None:
        session = DialogSession(
            user_id=user_id,
            session_id=session_id,
            messages=messages,
            ended_at=messages[-1].ts if messages else None,
        )
        self.mongo.dialog.save_session(session)

    def save_episodes(self, episodes: list[EpisodicMemory]) -> None:
        self.mongo.episodic.insert_many(episodes)

    def save_semantics(self, facts: list[SemanticMemory]) -> None:
        self.mongo.semantic.insert_many(facts)

    def save_agent_policy(self, policies: list[AgentPolicyMemory]) -> None:
        self.mongo.agent_policy.insert_many(policies)

    def clear_working(self, user_id: str, session_id: str) -> None:
        self.working.clear(user_id, session_id)
