"""Severity-aware audit -> attack selection.

``audit_bridge.py``'s ``filter``/``prioritize`` modes do plain ``rule_id``
set-intersection with no notion of severity -- a CRITICAL and a LOW finding
tagged with the same rule_id are indistinguishable to it. The older
``redteam/`` harness already solved this properly for its own, narrower
scenario set (``redteam/rank_targets.py``'s ``SEV_RANK``/``extract``/``rank``);
this module ports that same ranking logic (not an import -- ``redteam/``
stays a separate, uncoupled harness) into a new, additive ``ranked`` mode for
``mcp_attack``, and adds the piece ``redteam/`` never needed: a bridge table
from ``mcp_audit``'s rule_id vocabulary to ``mcp_attack``'s own, target-
agnostic OWASP Agent Memory Guard taxonomy (``taxonomy.py``) -- two
independently-evolved vocabularies with no prior relationship.

``audit_bridge.py`` itself is untouched: existing ``--audit-mode
filter/prioritize`` behavior, config fields and tests keep working exactly
as before. This is a third, new mode alongside them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .models import AttackVariant

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 9, "": 9}   # ported verbatim from redteam/rank_targets.py

# mcp_audit rule_id -> mcp_attack owasp_amg_category slug (taxonomy.py).
# Deliberately partial: AUTH-*, INFRA-*, INV-*, TOOL-01/02 don't fit any of
# the 6 memory/tool-poisoning-focused categories -- left unmapped rather than
# forced. Those classes are ranked via RULE_ID_TO_TECHNIQUE_CATEGORY instead.
RULE_ID_TO_OWASP_AMG_CATEGORY: Dict[str, str] = {
    "MEM-02": "memory_prompt_injection",
    "MEM-04": "memory_prompt_injection",
    "MEM-06": "memory_prompt_injection",
    "MEM-05": "memory_integrity_violation",
    "MEM-08": "memory_integrity_violation",
    "MEM-09": "memory_integrity_violation",
    "MEM-10": "memory_integrity_violation",
    "MEM-01": "sensitive_data_leakage",
    "MEM-03": "sensitive_data_leakage",
    "MEM-07": "sensitive_data_leakage",
    "EGRESS-01": "sensitive_data_leakage",
    "TOOL-04": "tool_output_instruction_injection",
    "TOOL-05": "tool_output_instruction_injection",
}

# mcp_audit rule_id -> mcp_attack technique_category slug (delivery/obfuscation).
RULE_ID_TO_TECHNIQUE_CATEGORY: Dict[str, str] = {
    "AUTH-02": "direct_instruction_override",
    "AUTH-03": "direct_instruction_override",
    "TOOL-04": "tool_result_injection",
    "TOOL-05": "tool_result_injection",
}


def _sev(finding: dict) -> Optional[str]:
    """Ported verbatim from redteam/rank_targets.py's ``_sev``: a finding's
    severity can be null (hypothesis-only, not yet verified), in which case
    ``effective_severity`` (set once verified/reassessed) is authoritative."""
    return finding.get("effective_severity") or finding.get("severity")


@dataclass
class RankedFinding:
    rule_id: str
    severity: Optional[str]
    control_outcome: Optional[str]
    owasp_amg_category: str   # "" when RULE_ID_TO_OWASP_AMG_CATEGORY has no entry
    technique_category: str = ""  # "" when RULE_ID_TO_TECHNIQUE_CATEGORY has no entry


def extract_ranked_findings(audit_doc: dict, *, only_failed: bool = True,
                            min_severity: Optional[str] = None) -> List[RankedFinding]:
    """Mirrors redteam/rank_targets.py's extract()+rank(), scoped to just the
    fields this module needs (rule_id, severity, control_outcome) plus the
    new owasp_amg_category bridge."""
    control_results = {r["rule_id"]: r for r in audit_doc.get("control_results", [])}
    out: List[RankedFinding] = []
    for f in audit_doc.get("findings", []):
        rule_id = f["rule_id"]
        outcome = control_results.get(rule_id, {}).get("control_outcome")
        if only_failed and outcome != "FAIL":
            continue
        sev = _sev(f)
        if min_severity is not None and SEV_RANK.get(sev, 9) > SEV_RANK.get(min_severity, 9):
            continue
        out.append(RankedFinding(rule_id=rule_id, severity=sev, control_outcome=outcome,
                                 owasp_amg_category=RULE_ID_TO_OWASP_AMG_CATEGORY.get(rule_id, ""),
                                 technique_category=RULE_ID_TO_TECHNIQUE_CATEGORY.get(rule_id, "")))
    return sorted(out, key=lambda rf: (SEV_RANK.get(rf.severity, 9), rf.rule_id))


def _campaign_boost(audit_doc: dict) -> Dict[str, int]:
    """Negative rank offset for categories the audit grouped into a P3 campaign."""
    boost: Dict[str, int] = {}
    corpus = (audit_doc.get("downstream") or {}).get("P3_corpus") or []
    for item in corpus:
        campaign = str(item.get("campaign") or "")
        keys: List[str] = []
        if campaign.startswith("C2"):
            keys = ["memory_prompt_injection", "memory_integrity_violation", "sensitive_data_leakage",
                    "protected_key_tampering", "bulk_injection_anomaly"]
        elif "IDOR" in campaign:
            keys = ["direct_instruction_override"]
        elif campaign.startswith("C4"):
            keys = ["tool_output_instruction_injection", "tool_result_injection"]
        for key in keys:
            boost[key] = min(boost.get(key, 0), -1)
    return boost


def select_variants_by_audit(variants: List[AttackVariant], audit_path: str, *,
                             mode: str = "ranked", min_severity: Optional[str] = None,
                             top_n: Optional[int] = None
                             ) -> Tuple[List[AttackVariant], List[str]]:
    """Never filters -- like audit_bridge.filter_variants_by_audit's
    "prioritize" mode, not its "filter" mode -- it orders ALL variants by the
    best (lowest-rank) severity among findings whose bridged
    owasp_amg_category (or technique_category) matches the variant, falling
    back to direct ``rule_id`` matching for variants/findings the bridge
    tables don't cover, so nothing silently drops out of consideration.
    ``top_n`` optionally truncates to the N highest-priority variants.
    ``mode`` is accepted for symmetry with ``audit_bridge``'s signature and
    for future modes; only "ranked" is implemented here.
    """
    if mode != "ranked":
        raise ValueError(f"audit_plan.select_variants_by_audit only implements mode='ranked', got {mode!r}")

    with open(audit_path, "r", encoding="utf-8") as fh:
        audit_doc = json.load(fh)
    ranked = extract_ranked_findings(audit_doc, only_failed=True, min_severity=min_severity)
    if not ranked:
        return list(variants), [f"audit {audit_path!r} has no FAIL findings matching the given filters; "
                                "variant order is unchanged"]

    campaign_boost = _campaign_boost(audit_doc)
    best_rank_by_category: Dict[str, int] = {}
    best_rank_by_technique: Dict[str, int] = {}
    best_rank_by_rule_id: Dict[str, int] = {}
    for rf in ranked:
        rank = SEV_RANK.get(rf.severity, 9)
        if rf.owasp_amg_category:
            best_rank_by_category[rf.owasp_amg_category] = min(rank, best_rank_by_category.get(rf.owasp_amg_category, 9))
        if rf.technique_category:
            best_rank_by_technique[rf.technique_category] = min(rank, best_rank_by_technique.get(rf.technique_category, 9))
        best_rank_by_rule_id[rf.rule_id] = min(rank, best_rank_by_rule_id.get(rf.rule_id, 9))

    def variant_rank(v: AttackVariant) -> int:
        candidates = [9]
        if v.owasp_amg_category in best_rank_by_category:
            candidates.append(best_rank_by_category[v.owasp_amg_category])
        if v.technique_category in best_rank_by_technique:
            candidates.append(best_rank_by_technique[v.technique_category])
        for rule_id in v.rule_ids:
            if rule_id in best_rank_by_rule_id:
                candidates.append(best_rank_by_rule_id[rule_id])
        rank = min(candidates)
        if v.owasp_amg_category in campaign_boost:
            rank += campaign_boost[v.owasp_amg_category]
        if v.technique_category in campaign_boost:
            rank += campaign_boost[v.technique_category]
        return rank

    ordered = sorted(variants, key=lambda v: (variant_rank(v), v.id))
    limitations: List[str] = []
    unmapped = sorted({rf.rule_id for rf in ranked if not rf.owasp_amg_category})
    if unmapped:
        limitations.append(f"no owasp_amg_category bridge for rule_id(s) {unmapped}; "
                           "ranking for these falls back to technique_category and direct rule_id matching only")
    if top_n is not None:
        ordered = ordered[: max(0, int(top_n))]
    return ordered, limitations
