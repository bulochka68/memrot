"""Cross-server collision detector.

Duplicate tool names across servers are the precondition for tool shadowing:
the client's tool namespace is flat, so whichever definition the model
picks (or the one loaded last) wins.  Also flags near-collisions (case /
separator variants) and a server's description that names another server's
tool.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from ..models import Finding, Provenance, Risk, ServerRecord


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


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
            collisions.append({"tool": name, "servers": sorted(set(owners)), "kind": "exact"})
            findings.append(Finding(
                id="DEF-TOOL-NAME-COLLISION", type="TOOL_NAME_COLLISION", severity=Risk.HIGH,
                title="Same tool name on multiple servers",
                description=f"tool {name!r} is exposed by {sorted(set(owners))}; namespace shadowing possible",
                plane="definition", provenance=Provenance.EFFECTIVE, tool=name,
                evidence={"servers": sorted(set(owners))},
            ))
    for norm, pairs in sorted(by_norm.items()):
        names = {n for _, n in pairs}
        owners = {s for s, _ in pairs}
        if len(names) > 1 and len(owners) > 1:
            collisions.append({"tool": sorted(names), "servers": sorted(owners), "kind": "near"})
            findings.append(Finding(
                id="DEF-TOOL-NAME-NEAR-COLLISION", type="TOOL_NAME_NEAR_COLLISION", severity=Risk.MEDIUM,
                title="Look-alike tool names across servers",
                description=f"tools {sorted(names)} differ only by case/separators across {sorted(owners)}",
                plane="definition", provenance=Provenance.EFFECTIVE,
                evidence={"names": sorted(names), "servers": sorted(owners)},
            ))

    # A description that mentions another server's tool by name -> cross-server steering.
    all_tools = {(s.name, t.name) for s in servers for t in s.tools}
    for s in servers:
        others = {t for (srv, t) in all_tools if srv != s.name and len(t) >= 5}
        for t in s.tools:
            text = f"{t.definition.description} {t.definition.title or ''}"
            hits = sorted(o for o in others if re.search(rf"\b{re.escape(o)}\b", text))
            hits = [h for h in hits if h != t.name]
            if hits:
                findings.append(Finding(
                    id="DEF-CROSS-SERVER-REFERENCE", type="CROSS_SERVER_REFERENCE", severity=Risk.HIGH,
                    title="Description references another server's tool",
                    description=f"{s.name}/{t.name} mentions {hits} which belong to other servers (shadowing indicator)",
                    plane="definition", provenance=Provenance.EFFECTIVE, server=s.name, tool=t.name,
                    evidence={"referenced_tools": hits},
                ))
    return collisions, findings
