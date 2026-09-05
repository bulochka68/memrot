"""Trust graph: components, data sources, stores, principals, publishers and
control points.  Every edge carries its basis (evidence ids), conditions, the
expected boundary, the scope and an observation state.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..models import (AuditDocument, Component, Edge, KnowledgeState, PathState, TrustBoundary,
                      stable_id)


class TrustGraph:
    def __init__(self) -> None:
        self.components: Dict[str, Component] = {}
        self.edges: Dict[str, Edge] = {}
        self.boundaries: Dict[str, TrustBoundary] = {}

    # -- building ----------------------------------------------------------- #
    def add_component(self, c: Component) -> Component:
        if c.component_id in self.components:
            existing = self.components[c.component_id]
            for src in c.inventory_sources:
                if src not in existing.inventory_sources:
                    existing.inventory_sources.append(src)
            for ref in c.source_refs:
                if ref not in existing.source_refs:
                    existing.source_refs.append(ref)
            existing.attributes.update({k: v for k, v in c.attributes.items() if k not in existing.attributes})
            if not existing.role and c.role:
                existing.role = c.role
            return existing
        self.components[c.component_id] = c
        return c

    def add_edge(self, from_ref: str, to_ref: str, kind: str, *, basis: Iterable[str] = (),
                 conditions: Iterable[str] = (), expected_boundary: Optional[str] = None,
                 scope: Optional[Dict[str, Any]] = None, state: PathState = PathState.UNKNOWN,
                 claim_refs: Iterable[str] = (), attributes: Optional[Dict[str, Any]] = None) -> Edge:
        eid = stable_id("EDGE", from_ref, to_ref, kind, scope or {})
        if eid in self.edges:
            e = self.edges[eid]
            for b in basis:
                if b not in e.basis:
                    e.basis.append(b)
            if state.value != PathState.UNKNOWN.value and _rank(state) > _rank(e.state):
                e.state = state
            return e
        e = Edge(edge_id=eid, from_ref=from_ref, to_ref=to_ref, kind=kind, basis=list(basis),
                 conditions=list(conditions), expected_boundary=expected_boundary, scope=dict(scope or {}),
                 state=state, claim_refs=list(claim_refs), attributes=dict(attributes or {}))
        self.edges[eid] = e
        return e

    def add_boundary(self, b: TrustBoundary) -> TrustBoundary:
        self.boundaries.setdefault(b.boundary_id, b)
        return self.boundaries[b.boundary_id]

    # -- queries ------------------------------------------------------------ #
    def out_edges(self, ref: str, kinds: Optional[Iterable[str]] = None) -> List[Edge]:
        ks = set(kinds) if kinds else None
        return [e for e in self.edges.values() if e.from_ref == ref and (ks is None or e.kind in ks)]

    def reachable(self, start: str, goal: str, *, kinds: Optional[Iterable[str]] = None,
                  max_depth: int = 8) -> Optional[List[Edge]]:
        """Return one edge chain from ``start`` to ``goal`` or None."""
        ks = set(kinds) if kinds else None
        frontier: List[List[Edge]] = [[e] for e in self.out_edges(start, ks)]
        seen = {start}
        while frontier:
            path = frontier.pop(0)
            last = path[-1].to_ref
            if last == goal:
                return path
            if len(path) >= max_depth or last in seen:
                continue
            seen.add(last)
            for e in self.out_edges(last, ks):
                frontier.append(path + [e])
        return None

    def to_document(self, doc: AuditDocument) -> None:
        doc.components = list(self.components.values())
        doc.edges = list(self.edges.values())
        doc.boundaries = list(self.boundaries.values())


def _rank(state: PathState) -> int:
    order = [PathState.UNKNOWN, PathState.CAPABILITY_COMBINATION, PathState.STATIC_PATH_SUPPORTED,
             PathState.RUNTIME_PATH_OBSERVED, PathState.CONTROL_VIOLATION_OBSERVED]
    return order.index(state)


def build_graph(doc: AuditDocument) -> TrustGraph:
    """Assemble the graph from the inventory, the profile, the policy and source facts.

    * MCP servers / native tool hosts -> components of type ``mcp_server`` / ``native_function``;
    * profile components (agent, orchestrator, background jobs, stores, providers) are declared
      structure (knowledge ``assumed`` until an evidence ref backs them);
    * source-fact flows become edges with their evidence as basis (``static_path_supported``);
    * trace-observed flows upgrade edges to ``runtime_path_observed``.
    """
    g = TrustGraph()
    for s in doc.servers:
        cid = s.component_id or f"server:{s.name}"
        s.component_id = cid
        g.add_component(Component(
            component_id=cid, type="mcp_server" if s.is_mcp else "native_function", name=s.name,
            inventory_sources=[k for k, v in s.inventory_sources.items() if v],
            attributes={"kind": s.kind, "transport": s.transport, "url": s.url},
            knowledge_state=KnowledgeState.KNOWN if s.inventory_sources else KnowledgeState.ASSUMED,
        ))
    for c in doc.profile.get("components") or []:
        g.add_component(Component(
            component_id=c["id"], type=c.get("type", "unknown"), name=c.get("name", c["id"]),
            role=c.get("role", ""), deployment_ref=c.get("deployment_ref"),
            inventory_sources=["profile"], attributes={k: v for k, v in c.items()
                                                       if k not in ("id", "type", "name", "role", "deployment_ref")},
            knowledge_state=KnowledgeState.ASSUMED,
        ))
    for c in doc.components:      # components added by adapters (source facts) before graph build
        g.add_component(c)
    for flow in doc.source_facts.get("flows") or []:
        state = PathState.STATIC_PATH_SUPPORTED if flow.get("evidence_refs") and flow.get("status") == "static_supported" \
            else PathState.UNKNOWN
        g.add_edge(flow["from"], flow["to"], flow.get("kind", "data_flow"), basis=flow.get("evidence_refs") or [],
                   conditions=flow.get("conditions") or [], expected_boundary=flow.get("boundary"),
                   scope=flow.get("scope") or {}, state=state, claim_refs=flow.get("claim_refs") or [],
                   attributes={k: v for k, v in flow.items()
                               if k not in ("from", "to", "kind", "evidence_refs", "conditions", "boundary", "scope", "claim_refs", "status")})
    for b in doc.policy.get("boundaries") or []:
        g.add_boundary(TrustBoundary(
            boundary_id=b["id"], from_ref=b.get("from", ""), to_ref=b.get("to", ""), rule=b.get("rule", ""),
            enforcement_point=b.get("enforcement_point"), delegation=b.get("delegation"),
            conditions=list(b.get("conditions") or []), expected_access=dict(b.get("expected_access") or {}),
            scope=dict(b.get("scope") or {}), knowledge_state=KnowledgeState.KNOWN,
        ))
    for b in doc.profile.get("boundaries") or []:
        if b["id"] not in g.boundaries:
            g.add_boundary(TrustBoundary(
                boundary_id=b["id"], from_ref=b.get("from", ""), to_ref=b.get("to", ""), rule=b.get("rule", ""),
                enforcement_point=b.get("enforcement_point"), conditions=list(b.get("conditions") or []),
                expected_access=dict(b.get("expected_access") or {}), knowledge_state=KnowledgeState.ASSUMED,
            ))
    for ev in doc.trace_events:
        flow = ev.get("flow")
        if flow and flow.get("from") and flow.get("to"):
            g.add_edge(flow["from"], flow["to"], flow.get("kind", "data_flow"),
                       basis=[ev["_evidence_id"]] if ev.get("_evidence_id") else [],
                       state=PathState.RUNTIME_PATH_OBSERVED, scope={"trace_id": ev.get("trace_id")})
    g.to_document(doc)
    return g
