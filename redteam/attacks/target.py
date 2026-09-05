"""Generic-слой red-team: цель атаки как интерфейс, независимый от системы.

Переносимое ядро (не зависит от стенда):
  * Principal        — кто действует (attacker / victim), с меткой
  * AttackTarget     — протокол системы под атакой: доставить вход, заставить
                       осесть, снять наблюдение у жертвы
  * AttackResult     — результат сценария в словаре аудита (rule_id, инвариант,
                       published, cross_user, path_state)
  * canary()         — уникальный маркер-оракул

Специфика системы живёт в реализации AttackTarget (см. targets/stand.py).
Это тот же шов, что у аудитора: правила/сценарии — generic, привязки — в адаптере.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class Principal:
    """Действующее лицо. label — роль ('attacker'/'victim'), token — как система его узнаёт."""
    label: str
    token: str


@runtime_checkable
class AttackTarget(Protocol):
    """Система под атакой. Реализуйте под свою топологию — сценарии не меняются."""

    def principals(self) -> dict[str, Principal]:
        """Как минимум ключи 'attacker' и 'victim' (разные субъекты)."""
        ...

    def new_session(self, prefix: str = "rt") -> str:
        """Идентификатор новой сессии/контекста."""
        ...

    def deliver(self, principal: Principal, text: str, session: str) -> str:
        """Подать недоверенный вход от лица principal. Возвращает ответ системы."""
        ...

    def trigger_persist(self, principal: Principal, session: str) -> dict[str, Any]:
        """Заставить сказанное осесть в долговременное/общее состояние
        (finalize, фоновая джоба, commit). Возвращает нормализованный след:
        {'published': [ {...} ], 'raw': <как есть>} — published — записи,
        ставшие общими/политикой (пусто, если инвариант не нарушен)."""
        ...

    def observe(self, principal: Principal, probe: str, session: str | None = None) -> str:
        """Снять наблюдаемый ответ у principal (обычно жертвы) на нейтральный probe."""
        ...


@dataclass
class AttackResult:
    """Итог сценария в терминах аудита. path_state замыкает петлю offline→runtime."""
    rule_id: str
    expected_invariant: str
    published: list[dict[str, Any]] = field(default_factory=list)
    cross_user: bool | None = None
    canary: str | None = None
    notes: str = ""
    published_texts: list[str] = field(default_factory=list)  # что дословно осело в общей политике
    marker_in_policy: bool | None = None                      # пережил ли маркер суммаризацию
    attempts: int = 1                                         # сколько прогонов ушло (при --repeat)

    @property
    def path_state(self) -> str:
        # словарь состояний из аудитора (trifecta.state / control path_state)
        if self.cross_user:
            return "control_violation_observed"
        if self.published:
            return "runtime_path_observed"
        return "static_path_supported"  # вживую не воспроизвелось на этом прогоне

    def better_than(self, other: "AttackResult | None") -> bool:
        """Упорядочивание результатов по «силе» для выбора лучшего из повторов."""
        rank = {"control_violation_observed": 3, "runtime_path_observed": 2, "static_path_supported": 1}
        if other is None:
            return True
        return rank[self.path_state] > rank[other.path_state]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "expected_invariant": self.expected_invariant,
            "path_state": self.path_state,
            "published_count": len(self.published),
            "published_texts": self.published_texts,
            "marker_in_policy": self.marker_in_policy,
            "cross_user": self.cross_user,
            "canary": self.canary,
            "attempts": self.attempts,
            "notes": self.notes,
        }


def canary(tag: str = "RT") -> str:
    """Уникальный маркер-оракул для сквозной проверки утечки/влияния."""
    return f"{tag}-CANARY-{uuid.uuid4().hex[:8].upper()}"
