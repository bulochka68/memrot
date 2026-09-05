"""Optional integration with Invariant Labs' ``mcp-scan``.

If the ``mcp-scan`` binary is on PATH it is run against the config file and
its JSON output is attached under ``definition_analysis.mcp_scan``.  Its
issues become TOOL-05 *signals* (hypotheses).  Note: running an external
scanner is an execution step; it is never done in offline mode unless
explicitly requested.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Tuple

from ..models import ClaimStatus, Finding, Severity

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
    "error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.LOW,
}


def run_mcp_scan(config_path: str, timeout: float = 120.0, binary: str = "mcp-scan") -> Tuple[Dict[str, Any], List[Finding]]:
    exe = shutil.which(binary)
    if not exe:
        return {"available": False, "ran": False, "reason": f"{binary} not found on PATH"}, []
    cmd = [exe, "scan", "--json", config_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"available": True, "ran": False, "error": str(e), "command": cmd}, []
    raw = proc.stdout.strip()
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"available": True, "ran": True, "error": "non-JSON output", "stdout": raw[:2000],
                "stderr": proc.stderr[-2000:], "command": cmd}, []
    findings = _convert(data)
    return {"available": True, "ran": True, "exit_code": proc.returncode, "command": cmd,
            "result": data, "issue_count": len(findings)}, findings


def _convert(data: Any) -> List[Finding]:
    findings: List[Finding] = []

    def walk(node: Any, server: str = None, tool: str = None) -> None:  # type: ignore[assignment]
        if isinstance(node, dict):
            srv = node.get("server") or node.get("server_name") or server
            tl = node.get("tool") or node.get("tool_name") or node.get("name") if node.get("issues") is not None else tool
            issues = node.get("issues") or node.get("findings") or node.get("problems")
            if isinstance(issues, list):
                for issue in issues:
                    if not isinstance(issue, dict):
                        issue = {"message": str(issue)}
                    sev = _SEVERITY_MAP.get(str(issue.get("severity") or issue.get("level") or "high").lower(), Severity.HIGH)
                    code = str(issue.get("code") or issue.get("type") or issue.get("category") or "ISSUE").upper()
                    findings.append(Finding(
                        code=f"MCP_SCAN_{code}", title="mcp-scan finding",
                        description=str(issue.get("message") or issue.get("description") or issue),
                        rule_id="TOOL-05", plane="definition", verification_status=ClaimStatus.HYPOTHESIS,
                        potential_severity=sev, server=srv, tool=tl,
                        evidence={"raw": issue, "where": "mcp-scan", "rule": code, "explanation": "external scanner signal"},
                        limitations=["external scanner output; a hypothesis until reviewed"],
                    ))
            for v in node.values():
                walk(v, srv, tl)
        elif isinstance(node, list):
            for v in node:
                walk(v, server, tool)

    walk(data)
    return findings
