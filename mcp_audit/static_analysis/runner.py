"""Runs the definition plane over an AuditDocument: text/schema signals, collisions,
hash baseline, optional mcp-scan, and evidence registration for every definition."""
from __future__ import annotations

from typing import List, Optional

from ..models import AuditDocument, ClaimStatus, Confidence, Finding, Method, Severity, SourceType, digest as _digest
from ..evidence import EvidenceStore
from .description_linter import lint_tool, lint_text
from .schema_analyzer import analyze_schema
from .collision_detector import detect_collisions
from .hasher import build_hash_baseline, CANONICALIZATION_VERSION
from .mcp_scan import run_mcp_scan
from .reconcile import reconcile_inventory


def run_static_analysis(doc: AuditDocument, store: Optional[EvidenceStore] = None, config_path: Optional[str] = None,
                        use_mcp_scan: bool = False) -> None:
    store = store or EvidenceStore(doc)
    findings: List[Finding] = []
    for s in doc.servers:
        if s.handshake.instructions:
            ev = store.add(SourceType.DEFINITION, Method.PARSING, {"server": s.name, "field": "instructions"},
                           digest=_digest(s.handshake.instructions), summary=f"server instructions of {s.name}",
                           fragment=s.handshake.instructions, limitations=["server-supplied text; untrusted"])
            for f in lint_text(s.handshake.instructions, where="server.instructions", server=s.name, tool=None):
                f.evidence_refs.append(ev.evidence_id)
                findings.append(f)
        for t in s.tools:
            ev = store.add(SourceType.DEFINITION, Method.PARSING,
                           {"server": s.name, "tool": t.name, "inventory": s.handshake.source},
                           digest=_digest(t.definition.raw or {"name": t.name}), summary=f"definition of {s.name}/{t.name}",
                           captured_at=s.handshake.captured_at, scope={"identity": s.handshake.identity},
                           limitations=["definition text is untrusted self-report"])
            t.claim_refs = list(dict.fromkeys(t.claim_refs + [f"CL-DEF-{s.name}-{t.name}"]))
            store.claim(f"CL-DEF-{s.name}-{t.name}", f"{s.name}/{t.name} is defined in the {s.handshake.source} catalogue",
                        ClaimStatus.STATIC_SUPPORTED, evidence_refs=[ev.evidence_id], confidence=Confidence.HIGH,
                        source_type=SourceType.DEFINITION, method=Method.PARSING, component_refs=[s.component_id],
                        limitations=["presence in this catalogue only; other roles/builds may differ"])
            for f in lint_tool(t) + analyze_schema(t, server_kind=s.kind):
                f.evidence_refs.append(ev.evidence_id)
                f.component_refs.append(s.component_id)
                findings.append(f)
        for r in s.resources:
            for key in ("description", "name", "title"):
                if r.get(key):
                    findings += lint_text(str(r[key]), where=f"resource.{key}", server=s.name, tool=None)
        for p in s.prompts:
            if p.get("description"):
                findings += lint_text(str(p["description"]), where="prompt.description", server=s.name, tool=None)

    for cf in doc.agent_context:
        cf.findings = lint_text(cf.text, where=cf.path, server=None, tool=None, plane="context")
        for f in cf.findings:
            if f.code in ("MODEL_ADDRESSED_IMPERATIVE", "URGENCY_OR_AUTHORITY"):
                f.potential_severity = Severity.LOW
                f.limitations.append("imperatives are normal in agent instruction files")
        findings += cf.findings

    collisions, coll_findings = detect_collisions(doc.servers)
    doc.collisions = collisions
    for f in coll_findings:
        for s in doc.servers:
            for t in s.tools:
                if f.tool == t.name or (f.evidence.get("names") and t.name in f.evidence["names"]):
                    ref = f"CL-DEF-{s.name}-{t.name}"
                    c = store.get_claim(ref)
                    if c:
                        f.claim_refs.append(ref)
                        f.evidence_refs += [e for e in c.evidence_refs if e not in f.evidence_refs]
        findings.append(f)

    doc.hash_baseline = build_hash_baseline(doc.servers)
    doc.meta["canonicalization_version"] = CANONICALIZATION_VERSION

    if use_mcp_scan and config_path:
        doc.mcp_scan, scan_findings = run_mcp_scan(config_path)
        findings += scan_findings
    else:
        doc.mcp_scan = {"available": None, "ran": False, "reason": "disabled"}

    for f in findings:
        doc.add_finding(f)
    reconcile_inventory(doc)
