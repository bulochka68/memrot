"""Cross-server collision detector.

Duplicate tool names across servers are the *precondition* for shadowing.
Whether they become a substitution depends on the real router (qualified
names or a flat namespace) - that judgement belongs to TOOL-03, which reads
the profile's ``tool_routing``.  Here the collisions are recorded as signals
with their qualified names.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from ..models import ClaimStatus, Finding, Severity, ServerRecord


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _signal(code: str, title: str, description: str, sev: Severity, evidence: Dict[str, Any], **kw: Any) -> Finding:
    return Finding(code=code, title=title, description=description, rule_id="TOOL-03", plane="definition",
                   verification_status=ClaimStatus.STATIC_SUPPORTED, severity=None, potential_severity=sev,
                   severity_rationale="potential severity if the router does not disambiguate",
                   requirement="TOOL-03: names resolve unambiguously in the real router",
                   expected_invariant="tool names resolve unambiguously", evidence=evidence,
                   limitations=["a name collision is a precondition; substitution is not declared without the router"],
                   remediation="qualify tool names per server in the router", closure_criterion="router resolves qualified names", **kw)


def detect_collisions(servers: List[ServerRecord]) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    by_exact: Dict[str, List[str]] = defaultdict(list)
    by_norm: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for s in servers:
        for t in s.tools:
            by_exact[t.name].append(s.name)
            by_norm[_norm(t.name)].append((s.name, t.name))

    collisions: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    for name, owners in sorted(by_exact.items()):
        if len(set(owners)) > 1:
            qualified = sorted(f"{o}/{name}" for o in set(owners))
            collisions.append({"tool": name, "servers": sorted(set(owners)), "qualified": qualified, "kind": "exact"})
            findings.append(_signal("TOOL_NAME_COLLISION", "Same tool name on multiple servers",
                                    f"tool {name!r} is exposed by {sorted(set(owners))} ({qualified}); shadowing precondition",
                                    Severity.HIGH, {"servers": sorted(set(owners)), "qualified": qualified, "where": name}, tool=name))
    for norm, pairs in sorted(by_norm.items()):
        names = {n for _, n in pairs}
        owners = {s for s, _ in pairs}
        if len(names) > 1 and len(owners) > 1:
            collisions.append({"tool": sorted(names), "servers": sorted(owners), "kind": "near"})
            findings.append(_signal("TOOL_NAME_NEAR_COLLISION", "Look-alike tool names across servers",
                                    f"tools {sorted(names)} differ only by case/separators across {sorted(owners)}",
                                    Severity.MEDIUM, {"names": sorted(names), "servers": sorted(owners), "where": norm}))
    all_tools = {(s.name, t.name) for s in servers for t in s.tools}
    for s in servers:
        others = {t for (srv, t) in all_tools if srv != s.name and len(t) >= 5}
        for t in s.tools:
            text = f"{t.definition.description} {t.definition.title or ''}"
            hits = sorted(o for o in others if re.search(rf"\b{re.escape(o)}\b", text))
            hits = [h for h in hits if h != t.name]
            if hits:
                f = _signal("CROSS_SERVER_REFERENCE", "Description references another server's tool",
                            f"{s.name}/{t.name} mentions {hits} which belong to other servers (shadowing indicator)",
                            Severity.HIGH, {"referenced_tools": hits, "where": "description"}, server=s.name, tool=t.name)
                f.rule_id = "TOOL-05"
                f.verification_status = ClaimStatus.HYPOTHESIS
                findings.append(f)
    return collisions, findings
