"""Versioned rule catalogue and evaluation driver."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .. import RULESET_VERSION
from ..models import (Applicability, AuditDocument, ControlOutcome, ControlResult, ExecutionStatus, Method)
from .base import Rule, RuleContext, RuleEvaluation
from . import memory_rules, auth_rules, infra_rules, tool_rules, inventory_rules

ALL_RULES: List[Rule] = (memory_rules.RULES + auth_rules.RULES + infra_rules.RULES + tool_rules.RULES + inventory_rules.RULES)
RULES_BY_ID: Dict[str, Rule] = {r.rule_id: r for r in ALL_RULES}

# MVP scope (TZ §20 stages A-C); stage-D rules are evaluated when sources allow and otherwise stay NOT_EVALUATED with a roadmap note
MVP_RULES = [r.rule_id for r in ALL_RULES if r.stage != "D"]


def get_rule(rule_id: str) -> Rule:
    return RULES_BY_ID[rule_id]


def catalog_dict() -> Dict[str, Any]:
    return {"ruleset_version": RULESET_VERSION, "rules": [r.to_dict() for r in ALL_RULES]}


def plan(available: Iterable[str], required: Optional[Iterable[str]] = None, mode: str = "offline") -> Dict[str, Any]:
    """Applicability plan: which rules can be evaluated with the bound adapters (TZ §5, §19)."""
    avail = set(available)
    if mode == "baseline_comparison":
        avail.add("baseline")
    wanted = list(required) if required else [r.rule_id for r in ALL_RULES]
    entries = []
    for rid in wanted:
        r = RULES_BY_ID.get(rid)
        if r is None:
            entries.append({"rule_id": rid, "status": "unknown_rule"})
            continue
        missing = r.missing_sources(avail)
        entries.append({"rule_id": rid, "version": r.version, "stage": r.stage, "domain": r.domain,
                        "status": "planned" if not missing else "not_evaluated", "missing_sources": missing,
                        "required_sources": r.required_sources})
    return {"ruleset_version": RULESET_VERSION, "available_sources": sorted(avail), "required_controls": wanted,
            "entries": entries, "planned": sum(1 for e in entries if e["status"] == "planned"),
            "not_evaluated": sum(1 for e in entries if e["status"] == "not_evaluated")}


def evaluate_all(doc: AuditDocument, store, available: Iterable[str], required: Optional[Iterable[str]] = None,
                 correlation: Optional[Dict[str, Any]] = None) -> List[ControlResult]:
    ctx = RuleContext(doc=doc, store=store, available=set(available), correlation=correlation or {})
    if doc.mode.value == "baseline_comparison" or doc.drift:
        ctx.available.add("baseline")
    wanted = list(required) if required else [r.rule_id for r in ALL_RULES]
    results: List[ControlResult] = []
    for rid in wanted:
        r = RULES_BY_ID.get(rid)
        if r is None:
            continue
        ctx.rule = r
        missing = r.missing_sources(ctx.available)
        applicability, reason = (r.applicability(ctx) if r.applicability else (Applicability.APPLICABLE, ""))
        if applicability == Applicability.NOT_APPLICABLE:
            res = ControlResult(rule_id=rid, rule_version=r.version, applicability=applicability,
                                execution_status=ExecutionStatus.SKIPPED, control_outcome=ControlOutcome.NOT_APPLICABLE,
                                expected_invariant=r.expected_invariant, interpretation=reason, limitations=[reason] if reason else [])
            results.append(res)
            continue
        if missing:
            res = ControlResult(rule_id=rid, rule_version=r.version, applicability=applicability,
                                execution_status=ExecutionStatus.SKIPPED, control_outcome=ControlOutcome.NOT_EVALUATED,
                                expected_invariant=r.expected_invariant, missing_sources=missing,
                                interpretation=f"required source(s) not bound: {missing}" + (f" ({reason})" if reason else ""),
                                limitations=[f"missing source: {m}" for m in missing] + ([reason] if reason else []))
            results.append(res)
            continue
        try:
            ev: RuleEvaluation = r.evaluate(ctx)
        except Exception as exc:   # a rule error must be visible, never a green result
            ev = RuleEvaluation(outcome=ControlOutcome.INCONCLUSIVE, execution_status=ExecutionStatus.ERROR,
                                interpretation=f"rule evaluation error: {type(exc).__name__}: {exc}",
                                limitations=[f"evaluation error: {exc}"])
        if ev.outcome == ControlOutcome.NOT_APPLICABLE:
            applicability = Applicability.NOT_APPLICABLE
        elif applicability == Applicability.UNKNOWN and ev.outcome in (ControlOutcome.PASS, ControlOutcome.FAIL, ControlOutcome.INCONCLUSIVE):
            applicability = Applicability.APPLICABLE      # the rule found something to evaluate
        elif applicability == Applicability.UNKNOWN and ev.outcome == ControlOutcome.NOT_EVALUATED:
            ev.limitations.append(f"applicability unknown: {reason}")
        res = ControlResult(
            rule_id=rid, rule_version=r.version, applicability=applicability, execution_status=ev.execution_status,
            control_outcome=ev.outcome, expected_invariant=r.expected_invariant, observed_effect=ev.observed_effect,
            interpretation=ev.interpretation, evaluated_boundary_refs=sorted(set(ev.boundary_refs)),
            component_refs=sorted({c for c in ev.component_refs if c}), claim_refs=ev.claim_refs,
            evidence_refs=sorted({e for e in ev.evidence_refs if e}), finding_refs=ev.finding_refs,
            limitations=ev.limitations + ([f"stage {r.stage} control: roadmap item, evaluated as far as sources allow"] if r.stage == "D" else []),
            missing_sources=[], method=ev.method, case_refs=ev.case_refs, conditions=ev.conditions,
        )
        results.append(res)
    doc.control_results = results
    return results
