"""Probe catalog for behavioral verification.

Each probe declares which tool it exercises, the arguments to send, and the
result it *expects* (PASS if the capability is real, BLOCKED if a boundary is
supposed to hold).  Probes are chosen from the classified tools so we only
run what the server actually exposes.

Boundary probes (path traversal, DDL, denied path) expect BLOCKED - a PASS
there is a CRITICAL finding because a claimed boundary does not hold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..models import Operation, Risk, ServerRecord, TestResult, ToolRecord


@dataclass
class Probe:
    id: str
    name: str
    server: str
    tool: str
    arguments: Dict[str, Any]
    expected: TestResult
    severity_if_unexpected: Risk
    kind: str = "capability"          # capability | boundary
    interpret: Optional[Callable[[Dict[str, Any]], TestResult]] = None
    note: str = ""


def _find(server: ServerRecord, *substrings: str) -> Optional[ToolRecord]:
    for t in server.tools:
        low = t.name.lower()
        if any(sub in low for sub in substrings):
            return t
    return None


def default_probes(server: ServerRecord, canary_token: str, sinkhole: str) -> List[Probe]:
    """Build a safe probe set for one server, based on its kind and tools."""
    probes: List[Probe] = []
    k = server.kind

    if k in ("filesystem", "git"):
        writer = _find(server, "write", "create", "put", "save")
        reader = _find(server, "read", "cat", "get")
        allowed = (server.effective_access.get("paths") or {}).get("allowed") or ["/workspace"]
        root = allowed[0].replace("/**", "").rstrip("/") or "/workspace"
        canary_file = f"{root}/{canary_token}.txt"
        if writer:
            probes.append(Probe(
                id="FS-WRITE-INSIDE", name="write_project_file", server=server.name, tool=writer.name,
                arguments={"path": canary_file, "content": canary_token},
                expected=TestResult.PASS, severity_if_unexpected=Risk.LOW, note="write within allowed root",
            ))
            probes.append(Probe(
                id="FS-TRAVERSAL", name="path_traversal", server=server.name, tool=writer.name,
                arguments={"path": f"{root}/../{canary_token}-outside.txt", "content": canary_token},
                expected=TestResult.BLOCKED, severity_if_unexpected=Risk.CRITICAL, kind="boundary",
                note="write outside allowed root must be blocked",
            ))
            probes.append(Probe(
                id="FS-DENIED-ETC", name="denied_path", server=server.name, tool=writer.name,
                arguments={"path": "/etc/mcp-audit-canary", "content": canary_token},
                expected=TestResult.BLOCKED, severity_if_unexpected=Risk.CRITICAL, kind="boundary",
                note="write to /etc must be blocked",
            ))
        if reader:
            probes.append(Probe(
                id="FS-READ-INSIDE", name="read_project_file", server=server.name, tool=reader.name,
                arguments={"path": canary_file},
                expected=TestResult.PASS, severity_if_unexpected=Risk.LOW, note="read within allowed root",
            ))
            probes.append(Probe(
                id="FS-READ-SECRET", name="read_secret_traversal", server=server.name, tool=reader.name,
                arguments={"path": "/etc/passwd"},
                expected=TestResult.BLOCKED, severity_if_unexpected=Risk.CRITICAL, kind="boundary",
                note="reading /etc/passwd must be blocked",
            ))

    elif k in ("postgres", "sqlite"):
        q = _find(server, "query", "select", "read", "execute", "sql")
        if q:
            probes.append(Probe(
                id="DB-SELECT", name="select_probe", server=server.name, tool=q.name,
                arguments={"sql": "SELECT 1"}, expected=TestResult.PASS,
                severity_if_unexpected=Risk.LOW, note="read query",
            ))
            ddl_allowed = server.effective_access.get("ddl", False)
            probes.append(Probe(
                id="DB-DDL", name="ddl_probe", server=server.name, tool=q.name,
                arguments={"sql": f"CREATE TABLE mcp_audit_canary_{canary_token[:8]} (id int)"},
                expected=TestResult.PASS if ddl_allowed else TestResult.BLOCKED,
                severity_if_unexpected=Risk.HIGH, kind="boundary",
                note="DDL must be blocked unless explicitly allowed",
            ))

    elif k == "shell":
        ex = _find(server, "exec", "run", "command", "shell")
        if ex:
            probes.append(Probe(
                id="EXEC-ARBITRARY", name="arbitrary_command", server=server.name, tool=ex.name,
                arguments={"command": f"echo {canary_token}"},
                expected=TestResult.PASS, severity_if_unexpected=Risk.CRITICAL, kind="boundary",
                interpret=lambda r, c=canary_token: TestResult.PASS if c in str(r) else TestResult.BLOCKED,
                note="arbitrary command execution (expected to succeed = CRITICAL capability)",
            ))
            probes.append(Probe(
                id="EXEC-EGRESS", name="egress_probe", server=server.name, tool=ex.name,
                arguments={"command": f"curl -s {sinkhole}/{canary_token}"},
                expected=TestResult.BLOCKED, severity_if_unexpected=Risk.HIGH, kind="boundary",
                note="network egress from exec should be blocked in the sandbox",
            ))

    elif k in ("fetch",):
        f = _find(server, "fetch", "get", "http", "request")
        if f:
            probes.append(Probe(
                id="FETCH-SINKHOLE", name="fetch_probe", server=server.name, tool=f.name,
                arguments={"url": f"{sinkhole}/{canary_token}"},
                expected=TestResult.PASS, severity_if_unexpected=Risk.LOW,
                note="outbound fetch reaches the network (to sinkhole only)",
            ))
    return probes
