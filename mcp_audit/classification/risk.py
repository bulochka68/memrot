"""Capability risk scorer.

``capability_risk`` is the *potential damage* of a capability (operation x
scope x destructiveness x secret-grade source x egress).  It is not a finding
severity and not a confidence: findings appear only when a requirement is
violated (TZ §7, §13.3).  A WRITE by itself never creates a "full project
access" conclusion.
"""
from __future__ import annotations

import re

from ..models import Operation, Severity, ToolRecord

_SECRET_TEXT = re.compile(r"secret|credential|token|api[_ -]?key|password|\.ssh|private[_ -]?key|\.env\b|environment", re.I)
_SECRET_KINDS = {"filesystem", "git", "memory", "email", "slack"}

_BASE = {
    Operation.EXEC: Severity.CRITICAL,
    Operation.DELETE: Severity.CRITICAL,
    Operation.WRITE: Severity.HIGH,
    Operation.READ: Severity.MEDIUM,
    Operation.UNKNOWN: Severity.MEDIUM,
}


def score_tool(tool: ToolRecord, server_kind: str = "generic") -> ToolRecord:
    risk = _BASE[tool.classification]
    reasons = [f"operation={tool.classification.value}"]
    if tool.classification == Operation.UNKNOWN:
        reasons.append("class unknown: potential damage not lowered by assumption")

    if tool.destructive and risk.rank < Severity.CRITICAL.rank:
        risk = Severity.CRITICAL
        reasons.append("destructive")
    if tool.classification == Operation.READ and tool.sensitive_source:
        text = f"{tool.name} {tool.definition.description}"
        if server_kind in _SECRET_KINDS or _SECRET_TEXT.search(text):
            risk = Severity.max(risk, Severity.HIGH)
            reasons.append("secret_grade_source")
    if tool.egress and tool.classification != Operation.READ:
        risk = Severity.max(risk, Severity.HIGH)
        reasons.append("egress")
    scope = tool.effective_access or {}
    if scope.get("unbounded"):
        risk = Severity.max(risk, Severity.HIGH)
        reasons.append("unbounded_scope(inferred)")

    tool.capability_risk = risk
    tool.risk_reasons = reasons
    tool.provenance["capability_risk"] = "definition+inferred scope; potential damage, not a finding severity"
    return tool
