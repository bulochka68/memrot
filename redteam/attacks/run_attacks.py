#!/usr/bin/env python3
"""Раннер: отчёт аудита → цели → generic-сценарии → результат в словаре аудита.

Замыкает конвейер: rank_targets/select_attacks выбирают rule_id целей, раннер
берёт сценарий по категории (scenarios/poisoning.py) и исполняет его против
AttackTarget (targets/stand.py по умолчанию). Успех переводит находку из
static_path_supported в runtime_path_observed / control_violation_observed.

  STAND_URL=... ATTACKER_KEY=... VICTIM_KEY=... \
    python3 run_attacks.py .audit/stand.json -c tool-poisoning,memory-poisoning

  --dry-run   не бить по системе — только показать, что бы запустилось
  --json      машинный вывод результатов
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # redteam/ для rank/select

from rank_targets import extract, rank              # type: ignore
from scenarios.poisoning import CATEGORY_SCENARIOS
from target import AttackResult


def _select(report_path: str, categories: list[str]) -> list[dict]:
    with open(report_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    targets = rank(extract(doc))
    want = set(categories)
    out = []
    seen = set()
    for t in targets:
        if t.get("control_outcome") != "FAIL":
            continue
        if not (set(t.get("categories") or []) & want):
            continue
        key = (t["rule_id"], t.get("categories", [None])[0])
        if t["rule_id"] in seen:      # один сценарий на rule_id достаточно
            continue
        seen.add(t["rule_id"])
        out.append(t)
    return out


def _make_target():
    from targets.stand import StandTarget
    return StandTarget()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Прогон generic-сценариев атак по целям из отчёта аудита")
    ap.add_argument("report", help="JSON-отчёт agent-security-audit v2.0")
    ap.add_argument("-c", "--category", default="tool-poisoning,memory-poisoning")
    ap.add_argument("--dry-run", action="store_true", help="не бить по системе, только план")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    a = ap.parse_args(argv)

    cats = [c.strip() for c in a.category.split(",") if c.strip()]
    unknown = [c for c in cats if c not in CATEGORY_SCENARIOS]
    if unknown:
        ap.error(f"нет сценария для категорий: {unknown}; есть: {list(CATEGORY_SCENARIOS)}")

    targets = _select(a.report, cats)
    if not targets:
        print("нет FAIL-целей под выбранные категории", file=sys.stderr)
        return 0

    if a.dry_run:
        for t in targets:
            cat = next(c for c in t["categories"] if c in cats)
            print(f"[plan] {t['rule_id']:9} {cat:16} -> {CATEGORY_SCENARIOS[cat].__name__}  ({t['title']})")
        return 0

    target = _make_target()
    results: list[AttackResult] = []
    try:
        for t in targets:
            cat = next(c for c in t["categories"] if c in cats)
            scenario = CATEGORY_SCENARIOS[cat]
            res = scenario(target, t["rule_id"], t.get("expected_invariant") or "")
            results.append(res)
            if not a.json:
                print(f"{res.rule_id:9} {res.path_state:26} "
                      f"published={len(res.published)} cross_user={res.cross_user} "
                      f"{('· '+res.notes) if res.notes else ''}")
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            close()

    if a.json:
        json.dump([r.to_dict() for r in results], sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
