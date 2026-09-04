"""Runs the whole definition plane over an AuditDocument."""
from __future__ import annotations

from typing import List, Optional

from ..models import AuditDocument, Finding, Provenance, Risk
from .description_linter import lint_tool, lint_text
from .schema_analyzer import analyze_schema
from .collision_detector import detect_collisions
from .hasher import build_hash_baseline
from .mcp_scan import run_mcp_scan


def run_static_analysis(doc: AuditDocument, config_path: Optional[str] = None, use_mcp_scan: bool = False) -> None:
    findings: List[Finding] = []
    for s in doc.servers:
        # Server-level "instructions" from initialize() are injected into the system prompt by clients.
        if s.handshake.instructions:
            findings += lint_text(s.handshake.instructions, where="server.instructions",
                                  server=s.name, tool=None, id_prefix="DEF-INSTR")
        for t in s.tools:
            findings += lint_tool(t)
            findings += analyze_schema(t, server_kind=s.kind)
        for r in s.resources:
            for key in ("description", "name", "title"):
                if r.get(key):
                    findings += lint_text(str(r[key]), where=f"resource.{key}", server=s.name,
                                          tool=None, id_prefix="DEF-RES")
        for p in s.prompts:
            if p.get("description"):
                findings += lint_text(str(p["description"]), where="prompt.description", server=s.name,
                                      tool=None, id_prefix="DEF-PROMPT")

    for cf in doc.agent_context:
        text = getattr(cf, "text", "")
        cf.findings = lint_text(text, where=cf.path, server=None, tool=None, plane="context", id_prefix="CTX")
        # Imperatives are *normal* in agent instructions; downgrade that one class only.
        for f in cf.findings:
            if f.type in ("MODEL_ADDRESSED_IMPERATIVE", "URGENCY_OR_AUTHORITY"):
                f.severity = Risk.LOW
        findings += cf.findings

    collisions, coll_findings = detect_collisions(doc.servers)
    doc.collisions = collisions
    findings += coll_findings

    doc.hash_baseline = build_hash_baseline(doc.servers)

    if use_mcp_scan and config_path:
        doc.mcp_scan, scan_findings = run_mcp_scan(config_path)
        findings += scan_findings
    else:
        doc.mcp_scan = {"available": None, "ran": False, "reason": "disabled"}

    doc.definition_findings = findings
