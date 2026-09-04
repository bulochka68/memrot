"""Cross-server reasoner, verdict builder, summary and security findings.

The verdict is built from effective + verified facts only; declared facts are
carried as divergence markers, never as evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import (AuditDocument, Finding, Operation, Provenance, Risk,
                      ToolRecord)


def _next_id(existing: List[Finding], prefix: str = "MCP") -> str:
    n = sum(1 for f in existing if f.id.startswith(prefix + "-")) + 1
    return f"{prefix}-{n:03d}"


def build_security_findings(doc: AuditDocument) -> List[Finding]:
    """Promote the highest-signal capability facts into numbered findings."""
    findings: List[Finding] = list(doc.security_findings)  # keep behavioral ones already added

    tools = doc.all_tools()
    exec_tools = [t for t in tools if t.classification == Operation.EXEC]
    if exec_tools:
        findings.append(Finding(
            id=_next_id(findings), type="ARBITRARY_CODE_EXECUTION", severity=Risk.CRITICAL,
            title="Arbitrary code execution available to the agent",
            description="One or more tools can execute arbitrary commands: "
                        + ", ".join(t.qualified_name for t in exec_tools),
            plane="capability",
            provenance=Provenance.VERIFIED if any(t.verified for t in exec_tools) else Provenance.EFFECTIVE,
            evidence={"tools": [t.qualified_name for t in exec_tools]},
        ))

    destructive = [t for t in tools if t.destructive]
    if destructive:
        findings.append(Finding(
            id=_next_id(findings), type="DESTRUCTIVE_OPERATIONS", severity=Risk.CRITICAL,
            title="Destructive operations available",
            description="Tools can delete/destroy data: " + ", ".join(t.qualified_name for t in destructive),
            plane="capability", provenance=Provenance.EFFECTIVE,
            evidence={"tools": [t.qualified_name for t in destructive]},
        ))

    write_tools = [t for t in tools if t.classification in (Operation.WRITE, Operation.DELETE)]
    if write_tools:
        findings.append(Finding(
            id=_next_id(findings), type="PROJECT_WRITE_ACCESS", severity=Risk.HIGH,
            title="Write access to project / data",
            description=f"{len(write_tools)} tool(s) can modify data",
            plane="capability", provenance=Provenance.EFFECTIVE,
            evidence={"tools": [t.qualified_name for t in write_tools]},
        ))

    # Boundary violations found by active probing are already in doc.security_findings.
    # Trifecta -> a finding.
    tri = doc.summary.get("trifecta", {})
    if tri.get("assembled"):
        sev = Risk.CRITICAL if tri.get("single_tool_trifecta") else Risk.HIGH
        findings.append(Finding(
            id=_next_id(findings), type="LETHAL_TRIFECTA", severity=sev,
            title="Lethal trifecta assembled",
            description=tri.get("explanation", ""),
            plane="correlation", provenance=Provenance.EFFECTIVE,
            evidence={"legs_present": tri.get("legs_present"),
                      "single_tool_trifecta": tri.get("single_tool_trifecta")},
        ))

    # Elevate critical definition-plane findings into the security list too.
    for f in doc.definition_findings:
        if f.severity in (Risk.CRITICAL, Risk.HIGH) and f.type in (
            "HIDDEN_UNICODE", "INSTRUCTION_OVERRIDE", "CONCEALMENT", "HIDDEN_INSTRUCTION_MARKER",
            "CROSS_TOOL_STEERING", "TOOL_NAME_COLLISION", "CROSS_SERVER_REFERENCE", "SENSITIVE_DEFAULT",
            "AUTHORIZATION_STEERING",
        ):
            g = Finding(
                id=_next_id(findings), type=f"TOOL_POISONING_{f.type}", severity=f.severity,
                title=f"Tool poisoning signal: {f.title}", description=f.description,
                plane="definition", provenance=f.provenance, server=f.server, tool=f.tool,
                evidence=f.evidence, taxonomy=f.taxonomy,
            )
            findings.append(g)

    return findings


def _cross_server(doc: AuditDocument) -> Dict[str, Any]:
    """Shadowing potential: >1 server, collisions, or cross-server references."""
    servers = doc.servers
    collision_findings = [f for f in doc.definition_findings
                          if f.type in ("TOOL_NAME_COLLISION", "CROSS_SERVER_REFERENCE", "TOOL_NAME_NEAR_COLLISION")]
    return {
        "server_count": len(servers),
        "shadowing_possible": len(servers) > 1 and bool(collision_findings),
        "signals": [f.to_dict() for f in collision_findings],
        "note": "Shadowing risk grows with server count; review collisions and cross-references."
                if len(servers) >= 4 else "",
    }


def build_summary(doc: AuditDocument) -> Dict[str, Any]:
    tools = doc.all_tools()
    counts = {r.value: 0 for r in Risk}
    for t in tools:
        counts[t.risk.value] += 1
    overall = Risk.LOW
    for t in tools:
        overall = Risk.max(overall, t.risk)
    for f in doc.security_findings:
        overall = Risk.max(overall, f.severity)

    return {
        "server_count": len(doc.servers),
        "tool_count": len(tools),
        "by_risk": counts,
        "critical": counts[Risk.CRITICAL.value],
        "high": counts[Risk.HIGH.value],
        "medium": counts[Risk.MEDIUM.value],
        "low": counts[Risk.LOW.value],
        "definition_findings": len(doc.definition_findings),
        "context_findings": sum(len(c.findings) for c in doc.agent_context),
        "overall_risk": overall.value,
        "trifecta": doc.summary.get("trifecta", {}),
    }


def build_verdict(doc: AuditDocument) -> Dict[str, Any]:
    tools = doc.all_tools()
    tri = doc.summary.get("trifecta", {})
    arbitrary_exec = any(t.classification == Operation.EXEC for t in tools)
    fs = doc.server_by_kind("filesystem") if hasattr(doc, "server_by_kind") else None
    full_project_access = any(
        (s.effective_access.get("unbounded") or
         any(p in ("/**", "/") for p in (s.effective_access.get("paths", {}) or {}).get("allowed", [])))
        for s in doc.servers if s.kind in ("filesystem", "git")
    ) or any(t.classification in (Operation.WRITE, Operation.DELETE) for t in tools)

    reasons: List[str] = []
    if arbitrary_exec:
        reasons.append("arbitrary command execution is available")
    if tri.get("assembled"):
        reasons.append("lethal trifecta is assembled")
    if full_project_access:
        reasons.append("write access to project data")
    poisoning = [f for f in doc.definition_findings if f.severity == Risk.CRITICAL]
    if poisoning:
        reasons.append(f"{len(poisoning)} critical definition-plane (tool poisoning) finding(s)")

    overall = doc.summary.get("overall_risk", Risk.LOW.value)
    # confidence: higher when facts are verified, lower when purely declared/effective
    verified_ratio = (sum(1 for t in tools if t.verified) / len(tools)) if tools else 0.0
    if doc.mode.value == "active":
        confidence = round(0.6 + 0.4 * verified_ratio, 2)
    elif doc.mode.value == "drift":
        confidence = 0.5
    else:
        confidence = 0.6

    return {
        "overall_risk": overall,
        "arbitrary_code_execution": arbitrary_exec,
        "full_project_access": full_project_access,
        "lethal_trifecta": bool(tri.get("assembled")),
        "cross_server": _cross_server(doc),
        "reasons": reasons,
        "confidence": confidence,
        "basis": "effective+verified",
        "declared_divergences": _declared_divergences(doc),
    }


def _declared_divergences(doc: AuditDocument) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in doc.servers:
        dc = s.declared_capabilities or {}
        if dc.get("tools") and not s.tools:
            out.append({"server": s.name, "declared": "tools", "observed": "no tools enumerated"})
        for t in s.tools:
            ann = t.definition.annotations or {}
            if ann.get("readOnlyHint") is True and t.classification in (Operation.WRITE, Operation.DELETE, Operation.EXEC):
                out.append({"server": s.name, "tool": t.name,
                            "declared": "readOnlyHint=true", "observed": f"classified {t.classification.value}"})
    return out
