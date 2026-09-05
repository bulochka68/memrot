"""INV-01 / INV-02: inventory consistency and discovery freshness (TZ §6).

Sources may legitimately diverge (feature flags, roles, other build, lazy
attachment, collector unavailable): a mismatch needs a reason and is never
automatically a hidden tool.
"""
from __future__ import annotations

from typing import List

from ..models import Applicability, ClaimStatus, Confidence, ControlOutcome, Method, RemediationPriority, Severity, SourceType
from .base import Rule, RuleContext, RuleEvaluation, not_evaluated, worst


def _inv01(ctx: RuleContext) -> RuleEvaluation:
    rec = ctx.doc.inventory_reconciliation
    comparisons = [r for r in rec if r.get("kind") in ("inventory_mismatch", "inventory_match")]
    if not comparisons:
        return not_evaluated("only one inventory source available; nothing to reconcile", ["second inventory source (source_snapshot / live / policy)"])
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.STATIC_ANALYSIS)
    explained = {d.get("tool"): d for d in ctx.profile.get("inventory_differences") or []}
    outcomes: List[ControlOutcome] = []
    for m in comparisons:
        if m.get("kind") == "inventory_match":
            outcomes.append(ControlOutcome.PASS)
            continue
        refs = [r for r in m.get("evidence_refs") or [] if ctx.store.has(r)]
        c = ctx.claim(f"CL-INV-01-{m.get('server')}-{m.get('pair')}", m.get("detail", ""), ClaimStatus.STATIC_SUPPORTED if refs else ClaimStatus.HYPOTHESIS,
                      evidence_refs=refs, confidence=Confidence.HIGH if refs else Confidence.MEDIUM,
                      source_type=SourceType.DEFINITION, method=Method.STATIC_ANALYSIS,
                      limitations=["the number of tools on the running server was not checked"])
        ev.claim_refs.append(c.claim_id)
        unexplained = [t for t in (m.get("only_in_a") or []) + (m.get("only_in_b") or []) if t not in explained]
        if not unexplained:
            outcomes.append(ControlOutcome.PASS)
            ev.limitations.append(f"{m.get('server')}: differences explained by profile ({m.get('pair')})")
            continue
        outcomes.append(ControlOutcome.INCONCLUSIVE)
        fnd = ctx.finding("INVENTORY_MISMATCH", f"Inventory mismatch for {m.get('server')} ({m.get('pair')})",
                          m.get("detail", "") + f"; unexplained: {unexplained}.", status=ClaimStatus.HYPOTHESIS,
                          potential_severity=Severity.MEDIUM, claim_refs=[c.claim_id], evidence_refs=refs, server=m.get("server"),
                          priority=RemediationPriority.P1,
                          potential_effect="tools outside the reviewed catalogue are unaudited; a stale catalogue misleads downstream checks",
                          remediation="explain each difference (flag, role, build) or align the catalogues; audit the missing declarations",
                          closure_criterion="all inventory sources agree for the same server identity, build, role and time, or differences are explained",
                          limitations=["a mismatch is not automatically a hidden tool; reasons may be legitimate"],
                          evidence={"only_in_a": m.get("only_in_a"), "only_in_b": m.get("only_in_b"), "sources": m.get("sources")})
        ev.finding_refs.append(fnd.finding_id)
    ev.outcome = worst(outcomes)
    return ev


def _inv02(ctx: RuleContext) -> RuleEvaluation:
    ev = RuleEvaluation(outcome=ControlOutcome.PASS, method=Method.OBSERVATION)
    outcomes: List[ControlOutcome] = []
    for s in ctx.doc.servers:
        hs = s.handshake
        if not hs.performed and hs.source in ("config", "none"):
            outcomes.append(ControlOutcome.NOT_EVALUATED)
            ev.limitations.append(f"{s.name}: no discovery performed (configured catalogue only)")
            continue
        if hs.source == "snapshot":
            outcomes.append(ControlOutcome.INCONCLUSIVE if hs.completeness in ("stale", "unknown") else ControlOutcome.PASS)
            if hs.completeness in ("stale", "unknown"):
                ev.limitations.append(f"{s.name}: snapshot {hs.completeness}")
            continue
        if hs.ok and hs.completeness == "complete":
            outcomes.append(ControlOutcome.PASS)
        else:
            outcomes.append(ControlOutcome.INCONCLUSIVE)
            fnd = ctx.finding("DISCOVERY_INCOMPLETE", f"Discovery for {s.name} is {hs.completeness}",
                              hs.error or "; ".join(hs.notes) or "partial listing", status=ClaimStatus.STATIC_SUPPORTED,
                              severity=Severity.LOW, server=s.name, priority=RemediationPriority.P2,
                              evidence_refs=[(s.inventory_sources.get("live_advertised") or {}).get("evidence_ref")],
                              remediation="repeat discovery; investigate transport/pagination errors",
                              closure_criterion="handshake complete for the identity and time of the snapshot")
            ev.finding_refs.append(fnd.finding_id)
    if not outcomes or all(o == ControlOutcome.NOT_EVALUATED for o in outcomes):
        return not_evaluated("discovery not performed in this mode (configured catalogue only)")
    ev.outcome = worst(o for o in outcomes if o != ControlOutcome.NOT_EVALUATED)
    return ev


RULES: List[Rule] = [
    Rule("INV-01", "2.0.0", "Согласованность инвентаря",
         "configured / source_defined / live_advertised / runtime_observed / policy_authorized сопоставлены по ID сервера, сборке, роли и времени; расхождения объяснены.",
         "Расхождение инвентаря имеет причину и не трактуется автоматически как скрытый инструмент",
         "inventory", [["mcp_inventory", "source_snapshot"], ["mcp_inventory", "policy_snapshot"], ["mcp_inventory", "trace"], ["source_snapshot", "policy_snapshot"]],
         [Method.STATIC_ANALYSIS], "inventory sources agree or differences are explained", _inv01,
         lambda ctx: (Applicability.APPLICABLE, "") if ctx.doc.servers else (Applicability.UNKNOWN, "no servers"),
         known_false_positives=["feature flags, roles, another build, lazy attachment"],
         remediation_criterion="sources agree for the same identity/build/role/time or differences are explained"),
    Rule("INV-02", "2.0.0", "Полнота и свежесть discovery",
         "Отказ discovery виден как unavailable / partial / stale; config не подменяет успешный handshake.",
         "Отказ discovery виден; config не подменяет успешный handshake", "inventory", [["mcp_inventory"]],
         [Method.OBSERVATION], "discovery is complete and fresh for the identity used", _inv02,
         lambda ctx: (Applicability.APPLICABLE, "") if ctx.doc.servers else (Applicability.UNKNOWN, "no servers"),
         remediation_criterion="handshake complete for the identity and time of the snapshot", default_priority=RemediationPriority.P2),
]
