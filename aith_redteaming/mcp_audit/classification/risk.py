"""Risk scorer: LOW/MEDIUM/HIGH/CRITICAL from operation x scope x destructiveness."""
from __future__ import annotations

import re

from ..models import Operation, Risk, ToolRecord

_SECRET_TEXT = re.compile(r"secret|credential|token|api[_ -]?key|password|\\.ssh|private[_ -]?key|\\.env\\b|environment", re.I)
_SECRET_KINDS = {"filesystem", "git", "memory", "email", "slack"}

_BASE = {
    Operation.EXEC: Risk.CRITICAL,
    Operation.DELETE: Risk.CRITICAL,
    Operation.WRITE: Risk.HIGH,
    Operation.READ: Risk.MEDIUM,
    Operation.UNKNOWN: Risk.MEDIUM,
}


def score_tool(tool: ToolRecord, server_kind: str = "generic") -> ToolRecord:
    risk = _BASE[tool.classification]
    reasons = [f"operation={tool.classification.value}"]

    if tool.destructive and risk.rank < Risk.CRITICAL.rank:
        risk = Risk.CRITICAL
        reasons.append("destructive")
    # A READ that reaches secret-grade data (filesystem, env, credentials) is
    # worse than a plain READ; a bare DB SELECT stays MEDIUM (per the risk model).
    if tool.classification == Operation.READ and tool.sensitive_source:
        text = f"{tool.name} {tool.definition.description}"
        if server_kind in _SECRET_KINDS or _SECRET_TEXT.search(text):
            risk = Risk.max(risk, Risk.HIGH)
            reasons.append("secret_grade_source")
    # Anything that can move data off-host is at least HIGH.
    if tool.egress and tool.classification != Operation.READ:
        risk = Risk.max(risk, Risk.HIGH)
        reasons.append("egress")
    # Broad / unbounded scope bumps risk.
    scope = tool.effective_access or {}
    if scope.get("unbounded") or scope.get("scope") == "all":
        risk = Risk.max(risk, Risk.HIGH)
        reasons.append("unbounded_scope")

    tool.risk = risk
    tool.risk_reasons = reasons
    tool.provenance["risk"] = "effective"
    return tool
