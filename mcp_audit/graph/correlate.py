"""Correlation by links and trust boundaries.

Replaces "three flags => leak" with path states.  Runtime confirmation of
one edge is never transferred to other edges; capabilities of different
principals / deployments / security profiles are never chained.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import AuditDocument, Edge, PathState
from .model import TrustGraph


def path_state_for_chain(chain: Optional[List[Edge]], *, legs_present: bool) -> PathState:
    if not chain:
        return PathState.CAPABILITY_COMBINATION if legs_present else PathState.UNKNOWN
    states = [e.state for e in chain]
    if all(s == PathState.CONTROL_VIOLATION_OBSERVED for s in states):
        return PathState.CONTROL_VIOLATION_OBSERVED
    if all(s in (PathState.RUNTIME_PATH_OBSERVED, PathState.CONTROL_VIOLATION_OBSERVED) for s in states):
        return PathState.RUNTIME_PATH_OBSERVED
    if all(s in (PathState.STATIC_PATH_SUPPORTED, PathState.RUNTIME_PATH_OBSERVED,
                 PathState.CONTROL_VIOLATION_OBSERVED) for s in states):
        return PathState.STATIC_PATH_SUPPORTED
    return PathState.CAPABILITY_COMBINATION if legs_present else PathState.UNKNOWN


def _same_scope(chain: List[Edge]) -> bool:
    """Edges of different principals / deployments / security profiles cannot be chained."""
    keys = ("principal", "deployment", "security_profile")
    for k in keys:
        vals = {e.scope.get(k) for e in chain if e.scope.get(k) is not None}
        if len(vals) > 1:
            return False
    return True


def correlate_paths(doc: AuditDocument, graph: TrustGraph) -> Dict[str, Any]:
    """Compute path states for the named chains declared in the profile
    (``chains``: e.g. untrusted source -> agent -> sensitive data -> external channel) plus
    the memory chain (conversation transformation -> policy publication)."""
    result: Dict[str, Any] = {"chains": [], "break_points": []}
    for spec in doc.profile.get("chains") or []:
        nodes: List[str] = spec.get("nodes") or []
        edges: List[Edge] = []
        ok = True
        for a, b in zip(nodes, nodes[1:]):
            seg = graph.reachable(a, b)
            if not seg:
                ok = False
                break
            edges += seg
        legs_present = bool(spec.get("legs_present", True))
        if ok and edges and not _same_scope(edges):
            state = PathState.UNKNOWN
            note = "edges belong to different principals/deployments/security profiles; not chained"
        else:
            state = path_state_for_chain(edges if ok else None, legs_present=legs_present)
            note = ""
        result["chains"].append({
            "chain_id": spec.get("id"), "title": spec.get("title", ""), "nodes": nodes,
            "state": state.value, "edge_refs": [e.edge_id for e in edges] if ok else [],
            "conditions": sorted({c for e in edges for c in e.conditions}) if ok else [],
            "basis": sorted({b for e in edges for b in e.basis}) if ok else [],
            "note": note, "rule_refs": spec.get("rule_refs") or [],
        })
    for bp in doc.source_facts.get("break_points") or []:
        result["break_points"].append({
            **bp,
            "durable_control": bool(bp.get("durable_control", False)),
            "note": bp.get("note") or ("length truncation limits the observed path in one run but is not a "
                                       "durable security control" if bp.get("kind") == "truncation" else ""),
        })
    return result
