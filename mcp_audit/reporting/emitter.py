"""JSON emitter, downstream feeders, and a human-readable Markdown report."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import AuditDocument, Operation, Risk


def build_downstream(doc: AuditDocument) -> Dict[str, Any]:
    """Map findings -> P2 matrix rows, P3 corpus cases, P8 drift baseline keys."""
    tm_rows: List[Dict[str, Any]] = []
    corpus: List[Dict[str, Any]] = []

    def tm(row_id: str, title: str, reachable: bool, evidence: Any) -> None:
        tm_rows.append({"id": row_id, "title": title, "reachable": reachable, "evidence": evidence})

    tools = doc.all_tools()
    tm("TM-EXEC", "Arbitrary code execution", any(t.classification == Operation.EXEC for t in tools),
       [t.qualified_name for t in tools if t.classification == Operation.EXEC])
    tm("TM-WRITE", "Unauthorized data modification",
       any(t.classification in (Operation.WRITE, Operation.DELETE) for t in tools),
       [t.qualified_name for t in tools if t.classification in (Operation.WRITE, Operation.DELETE)])
    tm("TM-EXFIL", "Data exfiltration channel", any(t.egress for t in tools),
       [t.qualified_name for t in tools if t.egress])
    poison = [f for f in doc.definition_findings if f.plane == "definition" and f.severity in (Risk.CRITICAL, Risk.HIGH)]
    tm("TM-POISON", "Tool poisoning via definitions", bool(poison), [f.id for f in poison])
    tm("TM-TRIFECTA", "Lethal trifecta", bool(doc.summary.get("trifecta", {}).get("assembled")),
       doc.summary.get("trifecta", {}).get("legs_present"))
    tm("TM-SHADOW", "Cross-server shadowing", bool(doc.collisions), doc.collisions)

    if any(f.type in ("HIDDEN_UNICODE", "CROSS_TOOL_STEERING", "HIDDEN_INSTRUCTION_MARKER", "INSTRUCTION_OVERRIDE")
           for f in doc.definition_findings):
        corpus.append({"campaign": "C4-*", "name": "tool poisoning", "reason": "definition-plane injection signals"})
    if any(t.classification == Operation.EXEC for t in tools):
        corpus.append({"campaign": "C4-EXEC", "name": "command execution abuse", "reason": "EXEC tool present"})
    if doc.summary.get("trifecta", {}).get("assembled"):
        corpus.append({"campaign": "C2-*", "name": "memory / context exfil", "reason": "trifecta assembled"})

    return {
        "P2_matrix": tm_rows,
        "P3_corpus": corpus,
        "P8_baseline_keys": sorted(doc.hash_baseline.keys()),
    }


def emit_json(doc: AuditDocument, indent: int = 2) -> str:
    doc.downstream = build_downstream(doc)
    return json.dumps(doc.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


def emit_markdown(doc: AuditDocument) -> str:
    s = doc.summary
    v = doc.verdict
    lines: List[str] = []
    lines.append(f"# MCP audit report ({doc.mode.value} mode)")
    lines.append("")
    lines.append(f"- Overall risk: **{s.get('overall_risk')}**")
    lines.append(f"- Servers: {s.get('server_count')}  Tools: {s.get('tool_count')}")
    lines.append(f"- Arbitrary code execution: **{v.get('arbitrary_code_execution')}**")
    lines.append(f"- Lethal trifecta: **{v.get('lethal_trifecta')}**")
    lines.append(f"- Full project access: **{v.get('full_project_access')}**")
    lines.append(f"- Confidence: {v.get('confidence')} (basis: {v.get('basis')})")
    if v.get("reasons"):
        lines.append("- Reasons: " + "; ".join(v["reasons"]))
    lines.append("")
    lines.append("## Tools")
    lines.append("")
    lines.append("| Server | Tool | Class | Risk | Egress | Verified |")
    lines.append("|---|---|---|---|---|---|")
    for t in doc.all_tools():
        lines.append(f"| {t.server} | {t.name} | {t.classification.value} | {t.risk.value} "
                     f"| {'yes' if t.egress else '-'} | {'' if t.verified is None else t.verified} |")
    lines.append("")
    lines.append("## Security findings")
    lines.append("")
    for f in sorted(doc.security_findings, key=lambda x: -x.severity.rank):
        loc = "/".join(x for x in (f.server, f.tool) if x)
        lines.append(f"- **[{f.severity.value}] {f.id} {f.type}** {('('+loc+') ') if loc else ''}- {f.description}")
    if doc.definition_findings:
        lines.append("")
        lines.append("## Definition-plane findings (tool poisoning surface)")
        lines.append("")
        for f in sorted(doc.definition_findings, key=lambda x: -x.severity.rank):
            loc = "/".join(x for x in (f.server, f.tool) if x)
            tax = (" " + ",".join(f.taxonomy)) if f.taxonomy else ""
            lines.append(f"- **[{f.severity.value}] {f.type}**{tax} {('('+loc+') ') if loc else ''}- {f.description}")
    if doc.tests:
        lines.append("")
        lines.append("## Active probes")
        lines.append("")
        lines.append("| Probe | Tool | Result | Expected | Boundary holds |")
        lines.append("|---|---|---|---|---|")
        for t in doc.tests:
            lines.append(f"| {t.name} | {t.tool} | {t.result.value} | {t.expected.value} | {t.boundary_holds} |")
    return "\n".join(lines) + "\n"
