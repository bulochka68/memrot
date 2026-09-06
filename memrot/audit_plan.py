"""Severity-aware audit -> attack selection.

``audit_bridge.py``'s ``filter``/``prioritize`` modes do plain ``rule_id``
set-intersection with no notion of severity -- a CRITICAL and a LOW finding
tagged with the same rule_id are indistinguishable to it. The older
``redteam/`` harness already solved this properly for its own, narrower
scenario set (``redteam/rank_targets.py``'s ``SEV_RANK``/``extract``/``rank``);
this module ports that same ranking logic (not an import -- ``redteam/``
stays a separate, uncoupled harness) into a new, additive ``ranked`` mode for
``memrot``, and adds the piece ``redteam/`` never needed: a bridge table
from ``mcp_audit``'s rule_id vocabulary to ``memrot``'s own, target-
agnostic OWASP Agent Memory Guard taxonomy (``taxonomy.py``) -- two
independently-evolved vocabularies with no prior relationship.

Signals consumed from an ``mcp_audit`` v2 JSON report (read-only, no import):

* ``findings`` + ``control_results`` (FAIL-only by default, same as
  ``redteam/rank_targets.py``)
* ``effective_severity`` / ``severity``
* ``trifecta.chains[].nodes`` ∩ ``findings[].component_refs``
* ``downstream.P3_corpus`` campaign boost (C2 memory, C4 tool, C4-IDOR)
* ``downstream.P2_matrix`` rows ``TM-<rule_id>`` with ``state=fail`` as extra
  FAIL rule ids when control_results are incomplete

``audit_bridge.py`` itself is untouched in signature: existing ``--audit-mode
filter/prioritize`` behavior, config fields and tests keep working. This is a
third, new mode alongside them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .models import AttackVariant

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 9, "": 9}   # ported verbatim from redteam/rank_targets.py

# Port of redteam/attack_taxonomy.py CATEGORIES. Kept as a local copy so
# memrot never imports redteam/; if a slug or rule set changes there,
# update this table to match.
REDTEAM_CATEGORIES: Dict[str, Tuple[str, frozenset]] = {
    "memory-poisoning": ("memory poisoning", frozenset({"MEM-02", "MEM-03", "MEM-04", "MEM-06"})),
    "tool-poisoning": ("tool poisoning", frozenset({"TOOL-04", "TOOL-05"})),
    "idor-bac": ("IDOR / BAC", frozenset({"AUTH-02", "AUTH-03"})),
    "token-validation": ("weak token validation", frozenset({"AUTH-04"})),
    "delegation": ("delegation bypass", frozenset({"AUTH-05"})),
    "exfiltration": ("uncontrolled egress", frozenset({"EGRESS-01"})),
    "memory-hygiene": ("memory hygiene", frozenset({"MEM-05", "MEM-08", "MEM-09", "MEM-10"})),
    "infrastructure": ("infrastructure surface", frozenset({"INFRA-01", "INFRA-02"})),
    "inventory": ("inventory / contract drift", frozenset({"INV-01", "INV-02", "TOOL-01", "TOOL-02"})),
}


def redteam_categories_for(rule_id: str) -> List[str]:
    return [slug for slug, (_title, ids) in REDTEAM_CATEGORIES.items() if rule_id in ids]


# mcp_audit rule_id -> memrot owasp_amg_category slug (taxonomy.py).
# AUTH-04/05, INFRA-*, INV-*, TOOL-01/02 have no AMG analogue -- left blank
# rather than forced; they still rank via redteam category + direct rule_id.
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
    "AUTH-02": "protected_key_tampering",
    "AUTH-03": "protected_key_tampering",
}

# mcp_audit rule_id -> memrot technique_category slug (delivery/obfuscation).
RULE_ID_TO_TECHNIQUE_CATEGORY: Dict[str, str] = {
    "AUTH-02": "direct_instruction_override",
    "AUTH-03": "direct_instruction_override",
    "AUTH-05": "authority_impersonation",
    "TOOL-04": "tool_result_injection",
    "TOOL-05": "tool_result_injection",
}


def _sev(finding: dict) -> Optional[str]:
    """Ported verbatim from redteam/rank_targets.py's ``_sev``: a finding's
    severity can be null (hypothesis-only, not yet verified), in which case
    ``effective_severity`` (set once verified/reassessed) is authoritative."""
    return finding.get("effective_severity") or finding.get("severity")


def _trifecta_nodes(audit_doc: dict) -> set:
    nodes: set = set()
    for chain in (audit_doc.get("trifecta") or {}).get("chains") or []:
        nodes |= set(chain.get("nodes") or [])
    return nodes


def p2_fail_rule_ids(audit_doc: dict) -> set:
    """``downstream.P2_matrix`` rows ``TM-<rule_id>`` with ``state=fail``."""
    out = set()
    for row in (audit_doc.get("downstream") or {}).get("P2_matrix") or []:
        if (row.get("state") or "").lower() != "fail":
            continue
        row_id = str(row.get("id") or "")
        if row_id.startswith("TM-") and "-" in row_id[3:]:
            out.add(row_id[3:])  # TM-AUTH-02 -> AUTH-02
        elif row_id.startswith("TM-"):
            rest = row_id[3:]
            if rest and rest[:4] in ("MEM-", "AUTH", "TOOL", "EGRE", "INFR", "INV-"):
                out.add(rest)
    return out


@dataclass
class RankedFinding:
    rule_id: str
    severity: Optional[str]
    control_outcome: Optional[str]
    owasp_amg_category: str   # "" when RULE_ID_TO_OWASP_AMG_CATEGORY has no entry
    technique_category: str = ""  # "" when RULE_ID_TO_TECHNIQUE_CATEGORY has no entry
    redteam_categories: List[str] = field(default_factory=list)
    in_trifecta: bool = False
    verification_status: Optional[str] = None
    plane: Optional[str] = None


def extract_ranked_findings(audit_doc: dict, *, only_failed: bool = True,
                            min_severity: Optional[str] = None) -> List[RankedFinding]:
    """Mirrors redteam/rank_targets.py's extract()+rank(), plus AMG/technique
    bridges and P2-fail rule ids when control_results omit a FAIL row."""
    control_results = {r["rule_id"]: r for r in audit_doc.get("control_results", []) if r.get("rule_id")}
    p2_fails = p2_fail_rule_ids(audit_doc)
    chain_nodes = _trifecta_nodes(audit_doc)
    out: List[RankedFinding] = []
    for f in audit_doc.get("findings", []):
        rule_id = f["rule_id"]
        outcome = control_results.get(rule_id, {}).get("control_outcome")
        if only_failed and outcome != "FAIL" and rule_id not in p2_fails:
            continue
        sev = _sev(f)
        if min_severity is not None and SEV_RANK.get(sev, 9) > SEV_RANK.get(min_severity, 9):
            continue
        comps = set(f.get("component_refs") or [])
        out.append(RankedFinding(
            rule_id=rule_id, severity=sev, control_outcome=outcome,
            owasp_amg_category=RULE_ID_TO_OWASP_AMG_CATEGORY.get(rule_id, ""),
            technique_category=RULE_ID_TO_TECHNIQUE_CATEGORY.get(rule_id, ""),
            redteam_categories=redteam_categories_for(rule_id),
            in_trifecta=bool(comps & chain_nodes),
            verification_status=f.get("verification_status"),
            plane=f.get("plane"),
        ))
    return sorted(out, key=lambda rf: (SEV_RANK.get(rf.severity, 9),
                                       0 if rf.in_trifecta else 1,
                                       rf.rule_id))


def _campaign_boost(audit_doc: dict) -> Dict[str, int]:
    """Negative rank offset for categories the audit grouped into a P3 campaign.

    Keys are AMG slugs, technique slugs, *and* redteam category slugs so a
    boost actually lands on the fields variants carry.
    """
    boost: Dict[str, int] = {}
    corpus = (audit_doc.get("downstream") or {}).get("P3_corpus") or []
    for item in corpus:
        campaign = str(item.get("campaign") or "")
        keys: List[str] = []
        if campaign.startswith("C2"):
            keys = [
                "memory_prompt_injection", "memory_integrity_violation", "sensitive_data_leakage",
                "protected_key_tampering", "bulk_injection_anomaly",
                "memory-poisoning", "memory-hygiene",
            ]
        elif "IDOR" in campaign:
            keys = ["direct_instruction_override", "protected_key_tampering", "idor-bac"]
        elif campaign.startswith("C4"):
            keys = [
                "tool_output_instruction_injection", "tool_result_injection",
                "tool-poisoning",
            ]
        for key in keys:
            boost[key] = min(boost.get(key, 0), -1)
    return boost


def _variant_redteam_slugs(variant: AttackVariant) -> List[str]:
    slugs: List[str] = []
    seen = set()
    for rule_id in variant.rule_ids:
        for slug in redteam_categories_for(rule_id):
            if slug not in seen:
                seen.add(slug)
                slugs.append(slug)
    return slugs


def select_variants_by_audit(variants: List[AttackVariant], audit_path: str, *,
                             mode: str = "ranked", min_severity: Optional[str] = None,
                             top_n: Optional[int] = None
                             ) -> Tuple[List[AttackVariant], List[str]]:
    """Never filters -- like audit_bridge.filter_variants_by_audit's
    "prioritize" mode, not its "filter" mode -- it orders ALL variants by the
    best (lowest-rank) severity among findings whose bridged
    owasp_amg_category (or technique_category / redteam category) matches the
    variant, falling back to direct ``rule_id`` matching for variants/findings
    the bridge tables don't cover, so nothing silently drops out of
    consideration. ``top_n`` optionally truncates to the N highest-priority
    variants. ``mode`` is accepted for symmetry with ``audit_bridge``'s
    signature and for future modes; only "ranked" is implemented here.
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
    best_rank_by_redteam: Dict[str, int] = {}
    best_rank_by_rule_id: Dict[str, int] = {}
    trifecta_rules: set = set()
    trifecta_categories: set = set()
    trifecta_techniques: set = set()
    trifecta_redteam: set = set()
    for rf in ranked:
        rank = SEV_RANK.get(rf.severity, 9)
        if rf.owasp_amg_category:
            best_rank_by_category[rf.owasp_amg_category] = min(
                rank, best_rank_by_category.get(rf.owasp_amg_category, 9))
        if rf.technique_category:
            best_rank_by_technique[rf.technique_category] = min(
                rank, best_rank_by_technique.get(rf.technique_category, 9))
        for slug in rf.redteam_categories:
            best_rank_by_redteam[slug] = min(rank, best_rank_by_redteam.get(slug, 9))
        best_rank_by_rule_id[rf.rule_id] = min(rank, best_rank_by_rule_id.get(rf.rule_id, 9))
        if rf.in_trifecta:
            trifecta_rules.add(rf.rule_id)
            if rf.owasp_amg_category:
                trifecta_categories.add(rf.owasp_amg_category)
            if rf.technique_category:
                trifecta_techniques.add(rf.technique_category)
            trifecta_redteam.update(rf.redteam_categories)

    def _boost_keys(v: AttackVariant) -> Iterable[str]:
        keys = [v.owasp_amg_category, v.technique_category, *_variant_redteam_slugs(v)]
        return [k for k in keys if k]

    def variant_rank(v: AttackVariant) -> int:
        candidates = [9]
        if v.owasp_amg_category in best_rank_by_category:
            candidates.append(best_rank_by_category[v.owasp_amg_category])
        if v.technique_category in best_rank_by_technique:
            candidates.append(best_rank_by_technique[v.technique_category])
        for slug in _variant_redteam_slugs(v):
            if slug in best_rank_by_redteam:
                candidates.append(best_rank_by_redteam[slug])
        for rule_id in v.rule_ids:
            if rule_id in best_rank_by_rule_id:
                candidates.append(best_rank_by_rule_id[rule_id])
        rank = min(candidates)
        applied = [campaign_boost[k] for k in _boost_keys(v) if k in campaign_boost]
        if applied:
            rank += min(applied)
        return rank

    def in_trifecta(v: AttackVariant) -> bool:
        if v.owasp_amg_category in trifecta_categories:
            return True
        if v.technique_category in trifecta_techniques:
            return True
        if any(slug in trifecta_redteam for slug in _variant_redteam_slugs(v)):
            return True
        return any(rid in trifecta_rules for rid in v.rule_ids)

    ordered = sorted(variants, key=lambda v: (variant_rank(v), 0 if in_trifecta(v) else 1, v.id))
    limitations: List[str] = []
    unmapped = sorted({
        rf.rule_id for rf in ranked
        if not rf.owasp_amg_category and not rf.redteam_categories
    })
    if unmapped:
        limitations.append(f"no owasp_amg_category or redteam-category bridge for rule_id(s) {unmapped}; "
                           "ranking for these falls back to technique_category and direct rule_id matching only")
    amg_blank = sorted({rf.rule_id for rf in ranked if not rf.owasp_amg_category and rf.redteam_categories})
    if amg_blank:
        limitations.append(
            f"no owasp_amg_category bridge for rule_id(s) {amg_blank}; "
            "ranked via redteam category / technique_category / rule_id only"
        )
    if top_n is not None:
        ordered = ordered[: max(0, int(top_n))]
    return ordered, limitations
