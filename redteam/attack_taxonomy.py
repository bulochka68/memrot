"""Тонкий шим: общая таксономия доменов атак живёт в mcp_attack.

Раньше здесь лежал собственный словарь категорий (rule_id -> домен). Теперь он
переехал в `mcp_attack.audit_domains` — единый источник, чтобы rank_targets.py и
select_attacks.py не расходились с библиотекой. `mcp_attack` — базовый пакет,
`redteam` — его потребитель, поэтому определение живёт в библиотеке, а здесь
остаются только реэкспорты для обратной совместимости импортов
(`from attack_taxonomy import CATEGORIES, categories_for, title, known_slugs`).
"""
from __future__ import annotations

import os
import sys

# redteam-скрипты запускаются как `python3 redteam/rank_targets.py` (sys.path[0]
# = redteam/), поэтому корень репозитория нужно добавить вручную, чтобы был
# виден пакет mcp_attack.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mcp_attack.audit_domains import (  # noqa: E402,F401  (реэкспорт после bootstrap sys.path)
    AUDIT_DOMAIN_CATEGORIES,
    CATEGORIES,
    DOMAIN_TO_OWASP_AMG,
    categories_for,
    known_slugs,
    title,
)

__all__ = [
    "AUDIT_DOMAIN_CATEGORIES",
    "CATEGORIES",
    "DOMAIN_TO_OWASP_AMG",
    "categories_for",
    "known_slugs",
    "title",
]
