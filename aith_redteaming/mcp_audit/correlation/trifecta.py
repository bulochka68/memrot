"""Trifecta assessor.

The lethal trifecta (Simon Willison): an agent is exposed when it combines
  1. access to sensitive data,
  2. exposure to untrusted / attacker-controllable content, and
  3. a channel to exfiltrate.
Any single tool that has all three, OR the union across all tools/servers,
means the trifecta is assembled for the agent as a whole.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import AuditDocument, Operation


def assess_trifecta(doc: AuditDocument) -> Dict[str, Any]:
    sensitive: List[str] = []
    untrusted: List[str] = []
    egress: List[str] = []
    single_tool_trifecta: List[str] = []

    for t in doc.all_tools():
        qn = t.qualified_name
        if t.sensitive_source:
            sensitive.append(qn)
        if t.untrusted_input:
            untrusted.append(qn)
        if t.egress:
            egress.append(qn)
        if t.sensitive_source and t.untrusted_input and t.egress:
            single_tool_trifecta.append(qn)

    legs = {
        "sensitive_access": sorted(sensitive),
        "untrusted_input": sorted(untrusted),
        "external_channel": sorted(egress),
    }
    assembled = bool(sensitive and untrusted and egress)
    return {
        "assembled": assembled,
        "legs": legs,
        "legs_present": {k: bool(v) for k, v in legs.items()},
        "single_tool_trifecta": sorted(single_tool_trifecta),
        "explanation": _explain(assembled, legs, single_tool_trifecta),
    }


def _explain(assembled: bool, legs: Dict[str, List[str]], single: List[str]) -> str:
    if not assembled:
        missing = [k for k, v in legs.items() if not v]
        return f"Trifecta not assembled; missing leg(s): {missing}"
    base = "Lethal trifecta assembled: sensitive access + untrusted input + external channel all present."
    if single:
        base += f" A single tool holds all three: {single}."
    return base
