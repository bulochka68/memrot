"""Audit-domain attack categories: the single home for the coarse grouping of
an ``mcp_audit`` rule catalogue into attack-relevant domains
(``memory-poisoning``, ``tool-poisoning``, ``idor-bac``, ...).

``redteam/``'s ranking CLIs (``rank_targets.py`` / ``select_attacks.py``) group
findings by these domain slugs.  They used to keep their own private copy of
this table (``redteam/attack_taxonomy.py``); it now lives here so there is one
definition and the two cannot drift as independent lists -- ``redteam`` imports
it (``mcp_attack`` is the library, ``redteam`` the consumer).

This is a second, coarser *projection* of the same rule ids that
``taxonomy.py`` maps to the published OWASP Agent Memory Guard categories.
The two vocabularies are orthogonal (a domain like ``idor-bac`` has no OWASP
AMG memory/tool-poisoning equivalent, and ``taxonomy.py``'s per-rule bridge in
``audit_plan.py`` is deliberately finer-grained than these domains), so
neither is derived from the other; instead they are linked by an explicit
domain -> OWASP-AMG correspondence table (``DOMAIN_TO_OWASP_AMG``) so a reader
can cross-reference the two without either silently redefining the other.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Set, Tuple

from .taxonomy import OWASP_AMG_CATEGORY_SLUGS


@dataclass(frozen=True)
class AuditDomainCategory:
    slug: str
    title: str
    rule_ids: FrozenSet[str]
    owasp_amg_category: str = ""   # cross-reference to taxonomy.py; "" = no OWASP AMG equivalent


AUDIT_DOMAIN_CATEGORIES: Dict[str, AuditDomainCategory] = {
    "memory-poisoning": AuditDomainCategory(
        "memory-poisoning", "Отравление памяти (впрыск в общую политику без авторитета)",
        frozenset({"MEM-02", "MEM-03", "MEM-04", "MEM-06"}), "memory_prompt_injection"),
    "tool-poisoning": AuditDomainCategory(
        "tool-poisoning", "Отравление инструментов (инъекция в описании/результате инструмента)",
        frozenset({"TOOL-04", "TOOL-05"}), "tool_output_instruction_injection"),
    "idor-bac": AuditDomainCategory(
        "idor-bac", "IDOR / нарушение авторизации ресурса",
        frozenset({"AUTH-02", "AUTH-03"})),
    "token-validation": AuditDomainCategory(
        "token-validation", "Слабая валидация токена",
        frozenset({"AUTH-04"})),
    "delegation": AuditDomainCategory(
        "delegation", "Обход ограничений пользователя через делегирование",
        frozenset({"AUTH-05"})),
    "exfiltration": AuditDomainCategory(
        "exfiltration", "Неконтролируемый вывод данных наружу",
        frozenset({"EGRESS-01"}), "sensitive_data_leakage"),
    "memory-hygiene": AuditDomainCategory(
        "memory-hygiene", "Гигиена памяти (происхождение, retention, консистентность)",
        frozenset({"MEM-05", "MEM-09", "MEM-10", "MEM-08"}), "memory_integrity_violation"),
    "infrastructure": AuditDomainCategory(
        "infrastructure", "Инфраструктурная поверхность",
        frozenset({"INFRA-01", "INFRA-02"})),
    "inventory": AuditDomainCategory(
        "inventory", "Расхождения инвентаря / контрактов",
        frozenset({"INV-01", "INV-02", "TOOL-01", "TOOL-02"})),
}

# Explicit correspondence between the two projections: domain slug -> OWASP AMG
# slug (taxonomy.py). Only domains with a real memory/tool-poisoning analogue
# appear; the rest (auth/infra/inventory) have no OWASP AMG equivalent.
DOMAIN_TO_OWASP_AMG: Dict[str, str] = {
    slug: c.owasp_amg_category for slug, c in AUDIT_DOMAIN_CATEGORIES.items() if c.owasp_amg_category
}

# Guard against a typo in the correspondence table drifting away from the real
# OWASP AMG vocabulary (mirrors audit_plan.py's bridge-table safety check).
assert set(DOMAIN_TO_OWASP_AMG.values()) <= set(OWASP_AMG_CATEGORY_SLUGS), (
    "DOMAIN_TO_OWASP_AMG maps to an unknown taxonomy slug"
)


# Backward-compatible ``{slug: (title, rule_id set)}`` view: the shape
# ``redteam``'s CLIs consumed before this table moved into the library.
CATEGORIES: Dict[str, Tuple[str, Set[str]]] = {
    slug: (c.title, set(c.rule_ids)) for slug, c in AUDIT_DOMAIN_CATEGORIES.items()
}


def categories_for(rule_id: str) -> List[str]:
    """Domain slugs a given ``mcp_audit`` rule id belongs to (may be several, or none)."""
    return [slug for slug, c in AUDIT_DOMAIN_CATEGORIES.items() if rule_id in c.rule_ids]


def title(slug: str) -> str:
    c = AUDIT_DOMAIN_CATEGORIES.get(slug)
    return c.title if c else slug


def known_slugs() -> List[str]:
    return list(AUDIT_DOMAIN_CATEGORIES)
