"""Loose, read-only coupling to an ``mcp_audit`` report: pure JSON parsing,
no import of ``mcp_audit`` at all. Lets a run prioritize or restrict itself
to the attack variants relevant to what an audit actually flagged on this
target, via the shared ``rule_id`` string-tag vocabulary.

Attackable rule ids follow ``redteam/rank_targets.py``: prefer
``control_results`` with ``control_outcome=FAIL``, unioned with P2
``TM-<rule_id>`` fail rows. If the report has no FAIL rows, fall back to
every finding's ``rule_id`` so incomplete snapshots still run.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set, Tuple

from .audit_plan import p2_fail_rule_ids
from .models import AttackVariant


def load_audit_rule_ids(audit_path: str) -> Dict[str, Any]:
    with open(audit_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    finding_rule_ids: Set[str] = {f.get("rule_id") for f in (doc.get("findings") or []) if f.get("rule_id")}
    fail_rule_ids: Set[str] = {
        r.get("rule_id") for r in (doc.get("control_results") or [])
        if r.get("rule_id") and r.get("control_outcome") == "FAIL"
    }
    fail_rule_ids |= p2_fail_rule_ids(doc)
    p2_matrix = (doc.get("downstream") or {}).get("P2_matrix") or []
    p2_matrix_ids: Set[str] = {row.get("id") for row in p2_matrix if row.get("id")}
    attackable = set(fail_rule_ids) if fail_rule_ids else set(finding_rule_ids)
    return {
        "finding_rule_ids": finding_rule_ids,
        "fail_rule_ids": fail_rule_ids,
        "attackable_rule_ids": attackable,
        "p2_matrix_ids": p2_matrix_ids,
        "p2_matrix": p2_matrix,
    }


def filter_variants_by_audit(variants: List[AttackVariant], audit_path: str,
                             mode: str = "filter") -> Tuple[List[AttackVariant], List[str]]:
    """mode='filter': keep only variants whose rule_ids intersect the audit's
    attackable (FAIL) rule_ids. mode='prioritize': keep all variants, reorder
    matched ones first. Falls back to the full, unfiltered catalog (with a
    limitation note) when the audit has no findings to filter by."""
    limitations: List[str] = []
    info = load_audit_rule_ids(audit_path)
    rule_ids = info["attackable_rule_ids"]
    if not rule_ids:
        limitations.append(f"{audit_path}: no findings with a rule_id -- running the full, unfiltered catalog")
        return variants, limitations

    matched = [v for v in variants if set(v.rule_ids) & rule_ids]
    unmatched = [v for v in variants if not (set(v.rule_ids) & rule_ids)]
    if mode == "prioritize":
        return matched + unmatched, limitations
    if mode != "filter":
        raise ValueError(f"unknown audit_mode {mode!r}; expected 'filter' or 'prioritize'")
    if not matched:
        limitations.append(f"{audit_path}: no catalog variant's rule_ids intersect the audit's findings "
                           f"({sorted(rule_ids)}) -- running the full, unfiltered catalog instead")
        return variants, limitations
    if unmatched:
        limitations.append(f"{len(unmatched)} catalog variant(s) excluded: rule_ids not present in "
                           f"{audit_path}'s FAIL control_results")
    return matched, limitations
