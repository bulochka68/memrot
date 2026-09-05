"""Operation classifier: each tool -> READ / WRITE / EXEC / DELETE.

Classification uses the tool name, description verbs, MCP annotations
(as *hints* only, since they are self-report) and schema shape.  It also
sets the three trifecta-relevant booleans:

  * sensitive_source - reads secrets / private data (feeds "sensitive access")
  * untrusted_input  - returns attacker-controllable content (feeds "untrusted input")
  * egress           - can move data off-host (feeds "external channel")
"""
from __future__ import annotations

import re
from typing import List

from ..models import AuditDocument, Operation, ToolRecord

_EXEC = re.compile(r"\b(exec|execute|command|shell|spawn|eval|bash|subprocess|terminal|run_command)\b", re.I)
# stricter than _EXEC: only true shell/code execution phrasing in a description,
# so "run a SQL query" is not misread as arbitrary execution.
_EXEC_DESC = re.compile(r"\b(execute|run)\b[^.\n]{0,30}\b(command|shell|script|code|binary|process|program)\b|"
                        r"\b(shell\s+command|arbitrary\s+(code|command))\b", re.I)
_DELETE = re.compile(r"\b(delete|remove|rm|unlink|drop|truncate|purge|destroy|erase|rmdir|wipe)\b", re.I)
_WRITE = re.compile(r"\b(write|create|update|edit|modify|append|put|post|insert|set|save|upload|patch|move|rename|mkdir|chmod|push|commit|merge|send|publish|comment)\b", re.I)
_READ = re.compile(r"\b(read|get|list|search|find|fetch|query|show|describe|cat|view|stat|info|head|tail|grep|resolve|check|scan|analyze|inspect)\b", re.I)

# What counts as sensitive to read.
_SENSITIVE = re.compile(r"\b(secret|credential|token|key|password|env|environment|config|\.ssh|private|billing|payment|customer|user|personal|pii|email|message|dm|inbox)\b", re.I)
# What counts as attacker-controllable content coming back.
_UNTRUSTED = re.compile(r"\b(read|fetch|get|list|search|query|web|http|url|browse|issue|pull|comment|review|message|email|inbox|log|stdout|output|page|content|document|file)\b", re.I)
# What can move data out.
_EGRESS = re.compile(r"\b(http|https|url|fetch|request|post|upload|send|email|mail|slack|webhook|publish|create_pull|create_issue|comment|push|forward|transmit|net|network|browse|dns)\b", re.I)


def _split(s: str) -> str:
    """Turn ``read_file``/``readFile``/``read-file`` into space-separated words so
    ``\\b`` boundaries work (underscore is a word char, which defeats ``\\bread\\b``)."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)      # camelCase
    return re.sub(r"[^A-Za-z0-9]+", " ", s)


def _text(t: ToolRecord) -> str:
    return _split(f"{t.name} {t.definition.title or ''} {t.definition.description}")


def classify_tool(tool: ToolRecord, server_kind: str = "generic", network_access: bool = False) -> ToolRecord:
    text = _text(tool)
    ann = tool.definition.annotations or {}
    name = _split(tool.name)

    op = Operation.UNKNOWN
    if _EXEC.search(name) or (server_kind == "shell") or _EXEC_DESC.search(tool.definition.description[:300]):
        op = Operation.EXEC
    elif _DELETE.search(name):
        op = Operation.DELETE
    elif _WRITE.search(name):
        op = Operation.WRITE
    elif _READ.search(name):
        op = Operation.READ
    else:
        # fall back to description verbs, then annotations
        if _DELETE.search(text):
            op = Operation.DELETE
        elif _WRITE.search(text):
            op = Operation.WRITE
        elif _READ.search(text):
            op = Operation.READ
        elif ann.get("readOnlyHint") is True:
            op = Operation.READ
        else:
            op = Operation.WRITE  # unknown mutators are treated as WRITE, not READ (fail safe)

    tool.classification = op
    tool.destructive = (op == Operation.DELETE) or bool(_DELETE.search(name)) or \
        (ann.get("destructiveHint") is True) or bool(re.search(r"truncate|drop|purge|force", text, re.I))

    # trifecta booleans
    reads = op in (Operation.READ, Operation.EXEC)
    tool.sensitive_source = bool(reads and (_SENSITIVE.search(text) or server_kind in ("filesystem", "postgres", "sqlite", "memory", "email", "slack")))
    tool.untrusted_input = bool((op in (Operation.READ, Operation.EXEC)) and _UNTRUSTED.search(text)) or server_kind in ("fetch", "github", "gitlab", "slack", "email")
    tool.egress = bool(_EGRESS.search(text)) or (op == Operation.EXEC) or \
        (network_access and op != Operation.READ) or server_kind in ("fetch", "github", "gitlab", "slack", "email")
    if op == Operation.EXEC:
        # execution can read secrets and reach the network regardless of name
        tool.sensitive_source = True
        tool.egress = True
    return tool


def classify_all(doc: AuditDocument) -> None:
    for s in doc.servers:
        net = bool(s.overrides.get("network_access")) or s.kind in ("fetch", "github", "gitlab", "slack", "email")
        for t in s.tools:
            classify_tool(t, server_kind=s.kind, network_access=net)
            t.provenance["classification"] = "effective"
