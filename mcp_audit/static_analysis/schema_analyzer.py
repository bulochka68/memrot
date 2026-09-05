"""Schema analyzer: suspicious parameters, schema/purpose mismatch and contract comparison.

Signals are hypotheses under TOOL-05 (they carry parameter, rule and
explanation).  :func:`compare_contracts` supports TOOL-02: it reports the
differences between two definitions of the same operation (configured vs
source-defined vs live) so that a schema mismatch is visible *before* any
check is interpreted.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models import ClaimStatus, Finding, Severity, ToolRecord

RULE_ID = "TOOL-05"
_SINK_NAMES = re.compile(
    r"^(side_?note|notes?|context|extra|additional(_info|_context)?|metadata|comment|reasoning|"
    r"thoughts?|conversation(_history)?|history|memory|summary|feedback|hidden|debug|"
    r"user_?(data|info|profile|message)|system_?prompt|instructions?|prompt)$", re.I)
_SECRET_NAMES = re.compile(
    r"(api_?key|secret|token|password|passwd|credential|private_?key|ssh_?key|auth|bearer|cookie|session_?id)", re.I)
_EXEC_NAMES = re.compile(r"^(command|cmd|script|shell|code|exec|expression)$", re.I)
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

    def add(code: str, sev: Severity, title: str, desc: str, explanation: str, **evidence: Any) -> None:
        findings.append(Finding(
            code=code, title=title, description=desc, rule_id=RULE_ID, plane="definition",
            verification_status=ClaimStatus.HYPOTHESIS, potential_severity=sev,
            severity_rationale="potential severity if the parameter is abused as described",
            requirement="TOOL-05: schema signals are recorded with parameter, rule and explanation",
            expected_invariant="parameters match the tool's purpose; no free-form sinks or credential inputs",
            server=tool.server, tool=name,
            evidence={**evidence, "where": f"inputSchema.{evidence.get('parameter', '')}".rstrip("."), "rule": code, "explanation": explanation},
            limitations=["schema heuristic: a hypothesis about misuse potential, not an observed abuse"],
            remediation="review the parameter with the definition owner; constrain or remove it",
            closure_criterion="parameter constrained (enum/pattern) or removed; annotation corrected",
        ))

    if not schema or not isinstance(schema, dict):
        add("MISSING_SCHEMA", Severity.MEDIUM, "Tool has no input schema",
            f"{name} declares no inputSchema; parameters cannot be reviewed", "no schema means no contract to review")
        return findings
    if schema.get("additionalProperties") is True:
        add("OPEN_SCHEMA", Severity.MEDIUM, "Schema accepts arbitrary extra properties",
            f"{name} sets additionalProperties=true; hidden parameters can be smuggled", "open schemas accept undeclared inputs")
    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        ptype = pdef.get("type")
        pdesc = str(pdef.get("description") or "")
        if _SINK_NAMES.match(pname) and ptype in (None, "string", "object", "array"):
            add("SINK_PARAMETER", Severity.HIGH, "Free-form sink parameter",
                f"{name}.{pname} is a free-form field a poisoned description can route data into",
                "classic exfiltration channel of tool poisoning", parameter=pname, required=pname in required, description=pdesc[:200])
        if _SECRET_NAMES.search(pname):
            sev = Severity.HIGH if _READ_HINT.match(name) or server_kind in _FS_KIND else Severity.MEDIUM
            add("SECRET_PARAMETER", sev, "Secret-shaped parameter", f"{name}.{pname} asks the model to supply a credential",
                "credentials should be bound server-side, not passed by the model", parameter=pname)
        is_exec_param = _EXEC_NAMES.match(pname) or (_DB_EXEC_NAMES.match(pname) and server_kind in _DB_KINDS)
        if is_exec_param and ptype in (None, "string") and not pdef.get("enum") and not pdef.get("pattern"):
            add("UNCONSTRAINED_EXEC_PARAMETER", Severity.HIGH, "Unconstrained execution parameter",
                f"{name}.{pname} is a free string with no enum/pattern - arbitrary execution surface",
                "free-form execution input", parameter=pname)
        if _URL_NAMES.search(pname) and server_kind in _FS_KIND:
            add("PURPOSE_MISMATCH", Severity.HIGH, "Schema does not match tool purpose",
                f"{name} on a {server_kind} server takes a URL parameter ({pname}) - possible egress channel",
                "a filesystem tool has no reason to take a URL", parameter=pname)
        if _READ_HINT.match(name) and pname.lower() in ("content", "contents", "data", "body", "payload") \
                and ptype in (None, "string", "object"):
            add("PURPOSE_MISMATCH", Severity.MEDIUM, "Schema does not match tool purpose",
                f"read-style tool {name} accepts a payload parameter ({pname})", "read tools rarely need a payload", parameter=pname)
        if pname.lower() in ("path", "file", "filepath", "file_path", "filename") and isinstance(pdef.get("default"), str) \
                and re.search(r"\.ssh|\.env|\.aws|passwd|shadow|mcp\.json", pdef["default"]):
            add("SENSITIVE_DEFAULT", Severity.CRITICAL, "Sensitive default path",
                f"{name}.{pname} defaults to {pdef['default']!r}", "a default pointing at secret material", parameter=pname, default=pdef["default"])

    ann = tool.definition.annotations or {}
    if ann.get("readOnlyHint") is True and re.search(r"(write|delete|remove|exec|run|create|update|drop)", name, re.I):
        add("ANNOTATION_MISMATCH", Severity.HIGH, "readOnlyHint contradicts tool name",
            f"{name} is annotated readOnlyHint=true but its name implies mutation",
            "annotations are self-report; they describe but do not enforce behaviour", parameter="", annotations=ann)
    if ann.get("destructiveHint") is False and re.search(r"(delete|remove|drop|truncate|purge|rm)", name, re.I):
        add("ANNOTATION_MISMATCH", Severity.HIGH, "destructiveHint contradicts tool name",
            f"{name} is annotated destructiveHint=false but its name implies destruction",
            "annotations are self-report; they describe but do not enforce behaviour", parameter="", annotations=ann)
    return findings


def _ptype(p: Dict[str, Any]) -> Optional[str]:
    t = p.get("type")
    if isinstance(t, list):
        t = [x for x in t if x != "null"]
        t = t[0] if t else None
    return t


def compare_contracts(a: Dict[str, Any], b: Dict[str, Any], *, label_a: str = "a", label_b: str = "b") -> List[Dict[str, Any]]:
    """Differences between two input schemas of the same operation."""
    pa, pb = _properties(a or {}), _properties(b or {})
    ra, rb = set((a or {}).get("required") or []), set((b or {}).get("required") or [])
    diffs: List[Dict[str, Any]] = []
    for name in sorted(set(pa) - set(pb)):
        diffs.append({"parameter": name, "kind": "missing", "breaking": name in ra,
                      "detail": f"present in {label_a}, absent in {label_b}" + (" (required)" if name in ra else " (optional)")})
    for name in sorted(set(pb) - set(pa)):
        diffs.append({"parameter": name, "kind": "missing", "breaking": name in rb,
                      "detail": f"present in {label_b}, absent in {label_a}" + (" (required)" if name in rb else " (optional)")})
    for name in sorted(set(pa) & set(pb)):
        ta, tb = _ptype(pa[name]), _ptype(pb[name])
        if ta and tb and ta != tb:
            diffs.append({"parameter": name, "kind": "type", "breaking": True, "detail": f"{label_a}: {ta}, {label_b}: {tb}"})
        if (name in ra) != (name in rb):
            diffs.append({"parameter": name, "kind": "required", "breaking": True,
                          "detail": f"required in {label_a}: {name in ra}, in {label_b}: {name in rb}"})
    return diffs
