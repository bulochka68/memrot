"""Trifecta indicator (TZ §11).

``LETHAL_TRIFECTA`` stays as an indicator of a *combination of capabilities*
(sensitive data x untrusted content x external channel).  It is never
presented as proof of a leak: the correlator reports a path state
(``capability_combination`` / ``static_path_supported`` /
``runtime_path_observed`` / ``control_violation_observed`` / ``unknown``).
Capabilities of different principals, deployments or security profiles are
not chained.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import AuditDocument, PathState


def assess_trifecta(doc: AuditDocument, correlation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    sensitive: List[str] = []
    untrusted: List[str] = []
    egress: List[str] = []
    single: List[str] = []
    for t in doc.all_tools():
        qn = t.qualified_name
        if t.sensitive_source:
            sensitive.append(qn)
        if t.untrusted_input:
            untrusted.append(qn)
        if t.egress:
            egress.append(qn)
        if t.sensitive_source and t.untrusted_input and t.egress:
            single.append(qn)
    legs = {"sensitive_access": sorted(sensitive), "untrusted_input": sorted(untrusted), "external_channel": sorted(egress)}
    combination = bool(sensitive and untrusted and egress)
    state = PathState.CAPABILITY_COMBINATION if combination else PathState.UNKNOWN
    chain_refs: List[Dict[str, Any]] = []
    for ch in (correlation or {}).get("chains") or []:
        if "trifecta" in (ch.get("chain_id") or "") or "LETHAL_TRIFECTA" in (ch.get("rule_refs") or []):
            chain_refs.append(ch)
            cs = PathState(ch.get("state", "unknown"))
            if _rank(cs) > _rank(state) and combination:
                state = cs
    return {
        "indicator": "LETHAL_TRIFECTA",
        "state": state.value,
        "capability_combination": combination,
        "legs": legs,
        "legs_present": {k: bool(v) for k, v in legs.items()},
        "single_tool_trifecta": sorted(single),
        "chains": chain_refs,
        "explanation": _explain(state, legs, single),
        "limitations": ["legs are classified from definitions (assumed); the indicator shows a combination of capabilities, "
                        "not an observed leak; runtime confirmation of one edge is not transferred to others"],
    }


def _rank(s: PathState) -> int:
    return [PathState.UNKNOWN, PathState.CAPABILITY_COMBINATION, PathState.STATIC_PATH_SUPPORTED,
            PathState.RUNTIME_PATH_OBSERVED, PathState.CONTROL_VIOLATION_OBSERVED].index(s)


def _explain(state: PathState, legs: Dict[str, List[str]], single: List[str]) -> str:
    if state == PathState.UNKNOWN:
        missing = [k for k, v in legs.items() if not v]
        return f"Trifecta legs not all present; missing: {missing}" if missing else "Trifecta state unknown"
    base = {
        PathState.CAPABILITY_COMBINATION: "Capability combination present: sensitive access, untrusted input and an external channel exist in the inventory. No connected path is established.",
        PathState.STATIC_PATH_SUPPORTED: "Code/configuration connect the three legs under the listed conditions (static path).",
        PathState.RUNTIME_PATH_OBSERVED: "A trace shows the corresponding transitions (runtime path observed).",
        PathState.CONTROL_VIOLATION_OBSERVED: "A concrete effect violating an access/data rule was observed on this path.",
    }[state]
    if single:
        base += f" A single tool holds all three legs: {single}."
    return base
