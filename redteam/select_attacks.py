#!/usr/bin/env python3
"""Отбор конкретных атак по категориям из ранжированного списка целей.

Вход — либо машинный вывод rank_targets.py (--json), либо сырой отчёт аудита
(с флагом --from-audit; внутри вызывается тот же extract+rank).

  select_attacks.py targets.json --category tool-poisoning,memory-poisoning
  rank_targets.py report.json --json | select_attacks.py - --category memory-poisoning
  select_attacks.py report.json --from-audit -c tool-poisoning

По умолчанию печатает только атакуемое (control_outcome=FAIL); --include-unresolved
добавляет NOT_EVALUATED/INCONCLUSIVE отдельным блоком «сначала перевести в проверяемый режим».
--list-categories печатает известные категории и выходит.
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    from attack_taxonomy import CATEGORIES, title, known_slugs
    from rank_targets import extract, rank
except ImportError:
    from redteam.attack_taxonomy import CATEGORIES, title, known_slugs
    from redteam.rank_targets import extract, rank

ATTACKABLE = {"FAIL"}
UNRESOLVED = {"NOT_EVALUATED", "INCONCLUSIVE", None}


def _load(path: str, from_audit: bool) -> list[dict]:
    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    data = json.loads(text)
    if from_audit or (isinstance(data, dict) and "findings" in data):
        return rank(extract(data))
    return data  # уже список целей от rank_targets.py --json


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Отбор атак по категориям")
    ap.add_argument("source", nargs="?", help="targets.json (от rank_targets --json), '-' для stdin, или отчёт аудита")
    ap.add_argument("-c", "--category", default="tool-poisoning,memory-poisoning",
                    help="категории через запятую (по умолчанию: tool-poisoning,memory-poisoning)")
    ap.add_argument("--from-audit", action="store_true", help="источник — сырой отчёт аудита, а не список целей")
    ap.add_argument("--include-unresolved", action="store_true", help="показать и NOT_EVALUATED/INCONCLUSIVE")
    ap.add_argument("--json", action="store_true", help="машинный вывод отобранных целей")
    ap.add_argument("--list-categories", action="store_true", help="показать известные категории")
    a = ap.parse_args(argv)

    if a.list_categories:
        for slug in known_slugs():
            t, ids = CATEGORIES[slug]
            print(f"{slug:18} {sorted(ids)}  — {t}")
        return 0
    if not a.source:
        ap.error("нужен источник (targets.json, '-' или отчёт аудита)")

    wanted = [c.strip() for c in a.category.split(",") if c.strip()]
    unknown = [c for c in wanted if c not in CATEGORIES]
    if unknown:
        ap.error(f"неизвестные категории: {unknown}; доступны: {known_slugs()}")

    targets = _load(a.source, a.from_audit)
    sel = [t for t in targets if set(t.get("categories") or []) & set(wanted)]
    ready = [t for t in sel if t.get("control_outcome") in ATTACKABLE]
    unres = [t for t in sel if t.get("control_outcome") in UNRESOLVED]

    if a.json:
        json.dump({"ready": ready, "unresolved": unres}, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    for slug in wanted:
        print(f"### {slug} — {title(slug)}")
        block = [t for t in ready if slug in (t.get("categories") or [])]
        if not block:
            print("   (нет подтверждённых целей FAIL)")
        for t in block:
            tri = " [trifecta]" if t["in_trifecta"] else ""
            print(f"  [{t['severity'] or '?':8}] {t['rule_id']:9} {t['title']}{tri}")
            print(f"     цель:  {(t['expected_invariant'] or '')[:96]}")
            print(f"     где:   flow={t['flow'] or '-'} | код={t['code']}")
            if t["preconditions"]:
                print(f"     условия: {t['preconditions']}")
        print()

    if a.include_unresolved and unres:
        print("### сначала перевести в проверяемый режим (нельзя атаковать по отчёту)")
        for t in unres:
            print(f"  {t['rule_id']:9} {t.get('control_outcome'):14} {t['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
