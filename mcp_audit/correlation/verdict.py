"""Verdict builder, summary and capability indicators (TZ §13).

The verdict has two independent axes:
  * ``assessment_state``    - complete_for_scope | partial | not_assessed
  * ``security_conclusion`` - findings_present | no_violations_observed | undetermined
Its ``basis`` is a machine-checkable list of claim ids; confidence is
qualitative with an explanation; no fixed number is emitted.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (AssessmentState, AuditDocument, ClaimStatus, Confidence, ControlOutcome, Finding,
                      Operation, PathState, SecurityConclusion, Severity)


def capability_indicators(doc: AuditDocument, store) -> Dict[str, Any]:
    """Capability facts (not findings): arbitrary execution, destructive operations, write access,
    full-project access.  Each is a claim with its status; a WRITE alone never implies full access."""
    tools = doc.all_tools()
    out: Dict[str, Any] = {}

    def ind(key: str, present: bool, statement: str, tool_list: List[str], potential: Severity, note: str = "") -> None:
        refs = []
        for t in tools:
            if not present or t.qualified_name in tool_list:
                for cr in t.claim_refs:
                    c = store.get_claim(cr)
                    if c:
                        refs += c.evidence_refs
        status = ClaimStatus.STATIC_SUPPORTED if refs else ClaimStatus.HYPOTHESIS
        claim = store.claim(f"CL-CAP-{key}", statement, status, evidence_refs=sorted(set(refs)),
            confidence=Confidence.MEDIUM,
            explanation="classification from definitions/config (assumed); not an observed exercise of the capability",
            limitations=["capability presence, not a violation; enforcement and scope unverified",
                         "absence refers to the inspected catalogues only"])
        out[key] = {"present": present, "tools": tool_list, "claim_ref": claim.claim_id, "potential_severity": potential.value,
                    "status": claim.claim_status.value, "note": note}

    exec_tools = [t.qualified_name for t in tools if t.classification == Operation.EXEC]
    ind("arbitrary_code_execution", bool(exec_tools),
        f"{len(exec_tools)} tool(s) classified as arbitrary execution: {exec_tools}" if exec_tools else "no tool classified as arbitrary execution",
        exec_tools, Severity.CRITICAL)
    destructive = [t.qualified_name for t in tools if t.destructive]
    ind("destructive_operations", bool(destructive), f"destructive tools: {destructive}" if destructive else "no destructive tool", destructive, Severity.CRITICAL)
    writers = [t.qualified_name for t in tools if t.classification in (Operation.WRITE, Operation.DELETE)]
    ind("write_access", bool(writers), f"{len(writers)} tool(s) can modify data: {writers}" if writers else "no write tool", writers, Severity.HIGH,
        note="modification of objects within the tool's scope; not a statement about the whole project")
    fs_full = []
    for s in doc.servers:
        if s.kind in ("filesystem", "git"):
            inf = s.effective_access.get("inferred") or {}
            allowed = (s.effective_access.get("policy_expected") or {}).get("paths_allowed") or inf.get("paths_allowed") or []
            if inf.get("unbounded") is True or any(p in ("/**", "/") for p in allowed):
                fs_full.append(s.name)
    ind("full_project_access", bool(fs_full),
        f"filesystem/git server(s) with an unbounded or root-wide scope: {fs_full}" if fs_full else
        "no server with an unbounded filesystem scope; a single allowed write does not prove full project access",
        [t.qualified_name for t in tools if t.server in fs_full], Severity.HIGH,
        note="derived from inferred scope (assumed); a successful write of one object is not full access")
    return out


def build_summary(doc: AuditDocument) -> Dict[str, Any]:
    tools = doc.all_tools()
    counts = {r.value: 0 for r in Severity}
    for t in tools:
        counts[t.capability_risk.value] += 1
    confirmed = [f for f in doc.findings if f.is_confirmed and f.plane not in ("definition", "context")]
    hyps = [f for f in doc.findings if not f.is_confirmed]
    by_outcome: Dict[str, int] = {}
    for r in doc.control_results:
        by_outcome[r.control_outcome.value] = by_outcome.get(r.control_outcome.value, 0) + 1
    return {
        "server_count": len(doc.servers),
        "tool_count": len(tools),
        "capability_risk_by_level": counts,
        "max_capability_risk": (max((t.capability_risk for t in tools), key=lambda r: r.rank).value if tools else None),
        "findings_confirmed": len(confirmed),
        "findings_hypotheses": len(hyps),
        "findings_by_severity": {s.value: sum(1 for f in confirmed if f.effective_severity == s) for s in Severity},
        "definition_signals": len(doc.definition_findings),
        "control_results": by_outcome,
        "runtime_validation_performed": doc.runtime_validation_performed,
        "trifecta": doc.trifecta,
        "note": "capability risk is potential damage per tool; finding severity is separate; no single security percentage is emitted",
    }


def build_verdict(doc: AuditDocument, required: List[str]) -> Dict[str, Any]:
    results = {r.rule_id: r for r in doc.control_results}
    req = [r for r in required if r in results]
    unresolved = [rid for rid in req if results[rid].control_outcome in (ControlOutcome.NOT_EVALUATED, ControlOutcome.INCONCLUSIVE)
                  or results[rid].applicability.value == "unknown"]
    adapters_missing = [a.adapter_id for a in doc.adapters if a.status in ("unavailable",)]
    confirmed = [f for f in doc.findings if f.is_confirmed and f.plane not in ("definition", "context")]
    hyps = [f for f in doc.findings if not f.is_confirmed]
    if doc.status == "failed" or not results:
        state = AssessmentState.NOT_ASSESSED
    elif unresolved or adapters_missing or any(a.status in ("partial", "stale") for a in doc.adapters):
        state = AssessmentState.PARTIAL
    else:
        state = AssessmentState.COMPLETE_FOR_SCOPE
    if confirmed:
        conclusion = SecurityConclusion.FINDINGS_PRESENT
    elif state == AssessmentState.COMPLETE_FOR_SCOPE and all(results[r].control_outcome in (ControlOutcome.PASS, ControlOutcome.NOT_APPLICABLE) for r in req):
        conclusion = SecurityConclusion.NO_VIOLATIONS_OBSERVED
    else:
        conclusion = SecurityConclusion.UNDETERMINED
    basis = sorted({c for f in confirmed for c in f.claim_refs} | {c for r in doc.control_results for c in r.claim_refs
                                                                   if r.control_outcome in (ControlOutcome.PASS, ControlOutcome.FAIL)})
    limitations = list(doc.limitations)
    limitations += [f"{rid}: {results[rid].control_outcome.value} ({results[rid].interpretation})" for rid in unresolved][:40]
    if not doc.runtime_validation_performed:
        limitations.append("no runtime validation was performed: all supported claims are static (config, definitions, source, policy)")
    conf = _confidence(doc, confirmed, state)
    return {
        "assessment_state": state.value,
        "security_conclusion": conclusion.value,
        "basis": basis,
        "confirmed_finding_refs": [f.finding_id for f in confirmed],
        "hypothesis_finding_refs": [f.finding_id for f in hyps],
        "required_controls": {rid: results[rid].control_outcome.value for rid in req},
        "unresolved_controls": unresolved,
        "missing_adapters": adapters_missing,
        "confidence": conf,
        "indicators": doc.summary.get("capability_indicators", {}),
        "trifecta_state": (doc.trifecta or {}).get("state", PathState.UNKNOWN.value),
        "cross_server": _cross_server(doc),
        "declared_divergences": _declared_divergences(doc),
        "limitations": limitations,
        "release_decision": "delegated to ObSec release policy; an unknown mandatory control never becomes an allow",
    }


def _confidence(doc: AuditDocument, confirmed: List[Finding], state: AssessmentState) -> Dict[str, str]:
    runtime = doc.runtime_validation_performed
    if not confirmed:
        level = Confidence.LOW if state != AssessmentState.COMPLETE_FOR_SCOPE else (Confidence.MEDIUM if not runtime else Confidence.HIGH)
        expl = "absence of findings is only as strong as the coverage; " + ("no runtime observation" if not runtime else "runtime cases executed")
    else:
        rt = [f for f in confirmed if f.verification_status == ClaimStatus.RUNTIME_SUPPORTED]
        level = Confidence.HIGH if rt else Confidence.MEDIUM
        expl = (f"{len(rt)} finding(s) runtime-supported, {len(confirmed) - len(rt)} static-supported; static support shows a code/config "
                "defect, not an observed effect on the running model")
    return {"level": level.value, "explanation": expl, "note": "qualitative; not a calibrated probability of exploitation"}


def _cross_server(doc: AuditDocument) -> Dict[str, Any]:
    signals = [f for f in doc.findings if f.code in ("TOOL_NAME_COLLISION", "CROSS_SERVER_REFERENCE", "TOOL_NAME_NEAR_COLLISION")]
    return {"server_count": len(doc.servers), "collision_signals": [f.finding_id for f in signals],
            "router_namespace": (doc.profile.get("tool_routing") or {}).get("namespace", "unknown"),
            "note": "shadowing needs a collision and a router that does not disambiguate (TOOL-03)"}


def _declared_divergences(doc: AuditDocument) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in doc.servers:
        dc = s.declared_capabilities or {}
        if dc.get("tools") and not s.tools:
            out.append({"server": s.name, "declared": "tools", "observed": "no tools enumerated"})
        for t in s.tools:
            ann = t.definition.annotations or {}
            if ann.get("readOnlyHint") is True and t.classification in (Operation.WRITE, Operation.DELETE, Operation.EXEC):
                out.append({"server": s.name, "tool": t.name, "declared": "readOnlyHint=true",
                            "observed": f"classified {t.classification.value} (assumed from name)"})
    return out
