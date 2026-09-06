#!/usr/bin/env python3
"""Ранжированный список целей атак из отчёта agent-security-audit v2.0.

Читает JSON-отчёт (`mcp_audit audit ... --json report.json`), извлекает
атакуемые цели и печатает их по убыванию severity и участия в trifecta.

Цель = находка. Для каждой берём:
  rule_id, severity, verification_status, control_outcome (из control_results),
  plane, категории (attack_taxonomy), expected_invariant (что ломать),
  flow + component_refs + локатор кода (где), preconditions (условия срабатывания),
  in_trifecta (складывается ли в сквозную цепочку).

По умолчанию оставляем только атакуемое: control_outcome == FAIL.
  --all             не фильтровать по outcome
  --min-severity S  порог severity (CRITICAL|HIGH|MEDIUM|LOW)
  --json            машинный вывод (список объектов) — вход для select_attacks.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# redteam-скрипты запускаются как `python3 redteam/rank_targets.py` — добавляем
# корень репозитория в sys.path, чтобы был виден пакет mcp_attack.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Единый источник правды о ранжировании по severity — в библиотеке mcp_attack,
# а не в собственной копии здесь (rank_targets/audit_plan больше не расходятся).
from mcp_attack.audit_plan import SEV_RANK, effective_severity as _sev  # noqa: E402

try:
    from attack_taxonomy import categories_for
except ImportError:  # запуск не из каталога redteam/
    from redteam.attack_taxonomy import categories_for


def _locator(f: dict, ev: dict) -> str:
    for r in f.get("evidence_refs") or []:
        e = ev.get(r)
        loc = (e or {}).get("locator") or {}
        if loc.get("path"):
            lines = loc.get("lines") or [""]
            return f"{loc['path']}:{lines[0]}"
        if loc.get("tool"):
            return f"tool:{loc['tool']}"
    return "-"


def extract(doc: dict) -> list[dict]:
    cr = {r["rule_id"]: r for r in doc.get("control_results", [])}
    ev = {e.get("evidence_id") or e.get("id"): e for e in doc.get("evidence", [])}
    chain_nodes: set[str] = set()
    for c in (doc.get("trifecta") or {}).get("chains", []):
        chain_nodes |= set(c.get("nodes", []))
    targets = []
    for f in doc.get("findings", []):
        rid = f["rule_id"]
        r = cr.get(rid, {})
        targets.append({
            "rule_id": rid,
            "severity": _sev(f),
            "verification_status": f.get("verification_status"),
            "control_outcome": r.get("control_outcome"),
            "applicability": r.get("applicability"),
            "plane": f.get("plane"),
            "categories": categories_for(rid),
            "title": f.get("title"),
            "expected_invariant": f.get("expected_invariant"),
            "flow": (f.get("scope") or {}).get("flow"),
            "components": f.get("component_refs") or [],
            "code": _locator(f, ev),
            "preconditions": f.get("preconditions") or [],
            "in_trifecta": bool(set(f.get("component_refs") or []) & chain_nodes),
            "evidence_refs": f.get("evidence_refs") or [],
        })
    return targets


def rank(targets: list[dict]) -> list[dict]:
    # severity ↑, участие в trifecta первым, затем rule_id
    return sorted(targets, key=lambda t: (SEV_RANK.get(t["severity"], 9),
                                          0 if t["in_trifecta"] else 1,
                                          t["rule_id"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ранжированный список целей атак из отчёта аудита")
    ap.add_argument("report", help="JSON-отчёт agent-security-audit v2.0")
    ap.add_argument("--all", action="store_true", help="не фильтровать по control_outcome=FAIL")
    ap.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="порог severity")
    ap.add_argument("--json", action="store_true", help="машинный вывод (для select_attacks.py)")
    a = ap.parse_args(argv)

    with open(a.report, encoding="utf-8") as fh:
        doc = json.load(fh)
    targets = extract(doc)
    if not a.all:
        targets = [t for t in targets if t["control_outcome"] == "FAIL"]
    if a.min_severity:
        cap = SEV_RANK[a.min_severity]
        targets = [t for t in targets if SEV_RANK.get(t["severity"], 9) <= cap]
    targets = rank(targets)

    if a.json:
        json.dump(targets, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    if not targets:
        print("нет целей под фильтром", file=sys.stderr)
        return 0
    for i, t in enumerate(targets, 1):
        tri = "trifecta" if t["in_trifecta"] else "-"
        cats = ",".join(t["categories"]) or "-"
        print(f"{i:2}. [{t['severity'] or '?':8}] {t['rule_id']:9} {t['control_outcome'] or '?':4} "
              f"{t['verification_status'] or '':18} [{cats}] {tri}")
        print(f"     что:   {t['title']}")
        print(f"     цель:  {(t['expected_invariant'] or '')[:96]}")
        print(f"     где:   flow={t['flow'] or '-'} | комп={','.join(t['components']) or '-'} | код={t['code']}")
        if t["preconditions"]:
            print(f"     условия: {t['preconditions']}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
