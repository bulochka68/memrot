"""Schema analyzer: suspicious parameters and schema/purpose mismatch.

Signals:
  * sink parameters - free-form string fields whose name suggests the model
    should put something in them that the tool does not need (``context``,
    ``notes``, ``sidenote``, ``extra``, ``reasoning``, ``conversation`` ...).
    These are the classic exfil channel for tool poisoning.
  * secret-shaped parameters on tools that should not need them
    (``api_key``, ``token``, ``password``, ``ssh_key`` ...).
  * schema/purpose mismatch - a READ-looking tool that takes ``content``,
    a filesystem tool that takes a ``url``, etc.
  * unconstrained shell-ish parameters (``command``, ``cmd``, ``script``)
    without an enum -> arbitrary execution surface.
  * ``additionalProperties: true`` / no schema at all -> hidden parameters.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..models import Finding, Provenance, Risk, ToolRecord

_SINK_NAMES = re.compile(
    r"^(side_?note|notes?|context|extra|additional(_info|_context)?|metadata|comment|reasoning|"
    r"thoughts?|conversation(_history)?|history|memory|summary|feedback|hidden|debug|"
    r"user_?(data|info|profile|message)|system_?prompt|instructions?|prompt)$", re.I)
_SECRET_NAMES = re.compile(
    r"(api_?key|secret|token|password|passwd|credential|private_?key|ssh_?key|auth|bearer|cookie|session_?id)", re.I)
_EXEC_NAMES = re.compile(r"^(command|cmd|script|shell|code|exec|expression)$", re.I)
# query/sql are an execution surface only on database servers; on a search tool
# a "query" parameter is just free-text search input, not command execution.
_DB_EXEC_NAMES = re.compile(r"^(query|sql|statement)$", re.I)
_DB_KINDS = {"postgres", "sqlite", "mysql", "mssql", "database", "db"}
_READ_HINT = re.compile(r"^(read|get|list|search|find|fetch|query|show|describe|cat|view|stat|info)", re.I)
_URL_NAMES = re.compile(r"(url|uri|endpoint|webhook|callback|href)", re.I)
_FS_KIND = {"filesystem", "git"}


def _properties(schema: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def analyze_schema(tool: ToolRecord, server_kind: str = "generic") -> List[Finding]:
    findings: List[Finding] = []
    schema = tool.definition.input_schema or {}
    name = tool.name
    props = _properties(schema)
    required = set(schema.get("required") or []) if isinstance(schema, dict) else set()

    def add(ftype: str, sev: Risk, title: str, desc: str, **evidence: Any) -> None:
        findings.append(Finding(
            id=f"SCHEMA-{ftype}", type=ftype, severity=sev, title=title, description=desc,
            plane="definition", provenance=Provenance.EFFECTIVE, server=tool.server, tool=name,
            evidence=evidence,
        ))

    if not schema or not isinstance(schema, dict):
        add("MISSING_SCHEMA", Risk.MEDIUM, "Tool has no input schema",
            f"{name} declares no inputSchema; parameters cannot be reviewed")
        return findings

    if schema.get("additionalProperties") is True:
        add("OPEN_SCHEMA", Risk.MEDIUM, "Schema accepts arbitrary extra properties",
            f"{name} sets additionalProperties=true; hidden parameters can be smuggled")

    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        ptype = pdef.get("type")
        pdesc = str(pdef.get("description") or "")
        if _SINK_NAMES.match(pname) and ptype in (None, "string", "object", "array"):
            add("SINK_PARAMETER", Risk.HIGH, "Free-form sink parameter",
                f"{name}.{pname} is a free-form field a poisoned description can route data into",
                parameter=pname, required=pname in required, description=pdesc[:200])
        if _SECRET_NAMES.search(pname):
            sev = Risk.HIGH if _READ_HINT.match(name) or server_kind in _FS_KIND else Risk.MEDIUM
            add("SECRET_PARAMETER", sev, "Secret-shaped parameter",
                f"{name}.{pname} asks the model to supply a credential", parameter=pname)
        is_exec_param = _EXEC_NAMES.match(pname) or (_DB_EXEC_NAMES.match(pname) and server_kind in _DB_KINDS)
        if is_exec_param and ptype in (None, "string") and not pdef.get("enum") and not pdef.get("pattern"):
            add("UNCONSTRAINED_EXEC_PARAMETER", Risk.HIGH, "Unconstrained execution parameter",
                f"{name}.{pname} is a free string with no enum/pattern - arbitrary execution surface",
                parameter=pname)
        if _URL_NAMES.search(pname) and server_kind in _FS_KIND:
            add("PURPOSE_MISMATCH", Risk.HIGH, "Schema does not match tool purpose",
                f"{name} on a {server_kind} server takes a URL parameter ({pname}) - possible egress channel",
                parameter=pname)
        if _READ_HINT.match(name) and pname.lower() in ("content", "contents", "data", "body", "payload") \
                and ptype in (None, "string", "object"):
            add("PURPOSE_MISMATCH", Risk.MEDIUM, "Schema does not match tool purpose",
                f"read-style tool {name} accepts a payload parameter ({pname})", parameter=pname)
        if pname.lower() in ("path", "file", "filepath", "file_path", "filename") and isinstance(pdef.get("default"), str) \
                and re.search(r"\.ssh|\.env|\.aws|passwd|shadow|mcp\.json", pdef["default"]):
            add("SENSITIVE_DEFAULT", Risk.CRITICAL, "Sensitive default path",
                f"{name}.{pname} defaults to {pdef['default']!r}", parameter=pname, default=pdef["default"])

    # Declared MCP annotations vs. what the name says (annotations are self-report).
    ann = tool.definition.annotations or {}
    if ann.get("readOnlyHint") is True and re.search(r"(write|delete|remove|exec|run|create|update|drop)", name, re.I):
        add("ANNOTATION_MISMATCH", Risk.HIGH, "readOnlyHint contradicts tool name",
            f"{name} is annotated readOnlyHint=true but its name implies mutation", annotations=ann)
    if ann.get("destructiveHint") is False and re.search(r"(delete|remove|drop|truncate|purge|rm)", name, re.I):
        add("ANNOTATION_MISMATCH", Risk.HIGH, "destructiveHint contradicts tool name",
            f"{name} is annotated destructiveHint=false but its name implies destruction", annotations=ann)
    return findings
