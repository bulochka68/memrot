"""Общая таксономия атак для скриптов ранжирования и выбора.

Категория атаки = осмысленный подкласс правил аудита, а не весь домен.
Держится в одном месте, чтобы rank_targets.py и select_attacks.py не расходились.
Ключ — стабильный slug категории; значение — правила и человекочитаемое имя.
"""
from __future__ import annotations

# slug -> (заголовок, множество rule_id)
CATEGORIES = {
    "memory-poisoning": ("Отравление памяти (впрыск в общую политику без авторитета)",
                          {"MEM-02", "MEM-03", "MEM-04", "MEM-06"}),
    "tool-poisoning":   ("Отравление инструментов (инъекция в описании/результате инструмента)",
                          {"TOOL-04", "TOOL-05"}),
    "idor-bac":         ("IDOR / нарушение авторизации ресурса",
                          {"AUTH-02", "AUTH-03"}),
    "token-validation": ("Слабая валидация токена",
                          {"AUTH-04"}),
    "delegation":       ("Обход ограничений пользователя через делегирование",
                          {"AUTH-05"}),
    "exfiltration":     ("Неконтролируемый вывод данных наружу",
                          {"EGRESS-01"}),
    "memory-hygiene":   ("Гигиена памяти (происхождение, retention, консистентность)",
                          {"MEM-05", "MEM-09", "MEM-10", "MEM-08"}),
    "infrastructure":   ("Инфраструктурная поверхность",
                          {"INFRA-01", "INFRA-02"}),
    "inventory":        ("Расхождения инвентаря / контрактов",
                          {"INV-01", "INV-02", "TOOL-01", "TOOL-02"}),
}

# обратная карта rule_id -> [slug, ...]
def categories_for(rule_id: str) -> list[str]:
    return [slug for slug, (_t, ids) in CATEGORIES.items() if rule_id in ids]

def title(slug: str) -> str:
    return CATEGORIES.get(slug, (slug, set()))[0]

def known_slugs() -> list[str]:
    return list(CATEGORIES.keys())
