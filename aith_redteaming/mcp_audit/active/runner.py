"""Active verification runner: executes probes through a live introspector,
inside the isolation guard, and records verified rights + boundaries.
"""
from __future__ import annotations

from typing import List, Optional

from ..models import (AuditDocument, Finding, ProbeResult, Provenance, Risk,
                      ServerRecord, TestResult)
from ..discovery.introspector import Introspector, MCPError
from .isolation import IsolationGuard
from .probes import Probe, default_probes


def _is_error(result: dict) -> bool:
    return bool(result.get("isError")) or result.get("is_error") is True


def _run_probe(client: Introspector, probe: Probe) -> ProbeResult:
    try:
        raw = client.call_tool(probe.tool, probe.arguments)
    except MCPError as e:
        # A refusal (permission denied / path outside root) is a held boundary.
        outcome = TestResult.BLOCKED
        details = f"server refused: {e}"
        raw = {"error": str(e)}
    except (TimeoutError, OSError) as e:
        outcome = TestResult.FAIL
        details = f"probe error: {e}"
        raw = {"error": str(e)}
    else:
        if probe.interpret:
            outcome = probe.interpret(raw)
        elif _is_error(raw):
            outcome = TestResult.BLOCKED
        else:
            outcome = TestResult.PASS
        details = "isError" if _is_error(raw) else "ok"

    boundary_broken = (probe.kind == "boundary" and outcome != probe.expected)
    severity = probe.severity_if_unexpected if boundary_broken else Risk.LOW
    return ProbeResult(
        id=probe.id, name=probe.name, server=probe.server, tool=probe.tool,
        result=outcome, expected=probe.expected, severity=severity,
        details=probe.note + ("; " + details if details else ""),
        evidence={"arguments": probe.arguments, "kind": probe.kind, "raw_summary": str(raw)[:400]},
    )


def run_active_verification(doc: AuditDocument, guard: IsolationGuard,
                            timeout: float = 20.0, cwd: Optional[str] = None) -> None:
    """Run probes against every live server.  Refuses outside the sandbox."""
    guard.ensure_sandbox()
    results: List[ProbeResult] = []
    findings: List[Finding] = []

    for server in doc.servers:
        if server.transport == "stdio" and not server.command:
            continue
        probes = default_probes(server, guard.canary_token, guard.sinkhole)
        if not probes:
            continue
        try:
            with Introspector(server, timeout=timeout, cwd=cwd) as client:
                client.initialize()
                for probe in probes:
                    guard.note(f"probe {probe.id} -> {server.name}/{probe.tool}")
                    res = _run_probe(client, probe)
                    results.append(res)
                    _mark_verified(server, res)
                    if res.result != res.expected and probe.kind == "boundary":
                        findings.append(Finding(
                            id=f"BEHAV-{probe.id}", type="BOUNDARY_VIOLATION", severity=res.severity,
                            title=f"Claimed boundary does not hold: {probe.name}",
                            description=f"{probe.note}; expected {probe.expected.value}, got {res.result.value}",
                            plane="behavioral", provenance=Provenance.VERIFIED,
                            server=server.name, tool=probe.tool, evidence=res.evidence,
                        ))
        except (MCPError, TimeoutError, OSError) as e:
            findings.append(Finding(
                id="BEHAV-PROBE-ERROR", type="PROBE_ERROR", severity=Risk.LOW,
                title="Active probing could not connect", description=str(e),
                plane="behavioral", provenance=Provenance.VERIFIED, server=server.name,
            ))

    doc.tests = results
    doc.security_findings.extend(findings)


def _mark_verified(server: ServerRecord, res: ProbeResult) -> None:
    for t in server.tools:
        if t.name == res.tool:
            # A capability probe that PASSed verifies the tool; a boundary probe
            # verifies the boundary, not the tool's benign use.
            if res.evidence.get("kind") == "capability":
                t.verified = (res.result == TestResult.PASS)
                t.provenance["verified"] = "verified"
