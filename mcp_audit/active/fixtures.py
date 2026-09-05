"""Registered control cases for controlled validation (TZ §12.2, §14, §19).

A case is only runnable when the tool's *declared schema agrees* with the
arguments the case sends: there is no universal probing by guessing a tool
from its name.  ``kind_cases`` offers a small catalogue of cases for known
server kinds, but each is still validated against the advertised schema
before it is used, and each declares how its effect is observed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..models import ServerRecord, ToolRecord


@dataclass
class ControlCase:
    id: str
    name: str
    server: str
    tool: str
    arguments: Dict[str, Any]
    expected: str                              # allowed | denied
    rule_id: Optional[str] = None
    boundary_ref: Optional[str] = None
    expected_invariant: str = ""
    effect_check: Dict[str, Any] = field(default_factory=lambda: {"kind": "none"})
    destructive: bool = False
    prepared_by: Optional[str] = None
    note: str = ""
    setup: List[Dict[str, Any]] = field(default_factory=list)
    teardown: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "fixture"                    # fixture | kind_catalogue


def _render(value: Any, vars_: Dict[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in vars_.items():
            value = value.replace("{" + k + "}", v)
        return value
    if isinstance(value, dict):
        return {k: _render(v, vars_) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, vars_) for v in value]
    return value


def schema_agrees(tool: Optional[ToolRecord], arguments: Dict[str, Any]) -> List[str]:
    """Return the reasons why ``arguments`` do not fit the tool's declared schema (empty = agrees)."""
    if tool is None:
        return ["tool not present in the advertised catalogue"]
    schema = tool.definition.input_schema or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return ["tool has no input schema; the case cannot be matched to an agreed contract"]
    reasons = []
    for k in arguments:
        if k not in props and schema.get("additionalProperties") is not True:
            reasons.append(f"argument {k!r} not in schema properties {sorted(props)}")
    for req in schema.get("required") or []:
        if req not in arguments:
            reasons.append(f"required parameter {req!r} not provided by the case")
    for k, v in arguments.items():
        t = (props.get(k) or {}).get("type")
        if t == "string" and not isinstance(v, str):
            reasons.append(f"argument {k!r} should be a string")
        if t == "array" and not isinstance(v, list):
            reasons.append(f"argument {k!r} should be an array")
        if t == "integer" and not isinstance(v, int):
            reasons.append(f"argument {k!r} should be an integer")
    return reasons


def cases_from_fixtures(fixtures: List[Dict[str, Any]], vars_: Dict[str, str]) -> List[ControlCase]:
    out: List[ControlCase] = []
    for c in fixtures:
        out.append(ControlCase(
            id=c["id"], name=c.get("name", c["id"]), server=c["server"], tool=c["tool"],
            arguments=_render(c.get("arguments") or {}, vars_), expected=c.get("expected", "denied"),
            rule_id=c.get("rule_id"), boundary_ref=c.get("boundary_ref"), expected_invariant=c.get("expected_invariant", ""),
            effect_check=_render(c.get("effect_check") or {"kind": "none"}, vars_), destructive=bool(c.get("destructive")),
            prepared_by=c.get("prepared_by"), note=c.get("note", ""), setup=list(c.get("setup") or []),
            teardown=list(c.get("teardown") or []), source="fixture",
        ))
    return out


def _find(server: ServerRecord, *names: str) -> Optional[ToolRecord]:
    for t in server.tools:
        if t.name in names:
            return t
    return None


def kind_cases(server: ServerRecord, vars_: Dict[str, str], *, root: Optional[str] = None) -> List[ControlCase]:
    """Catalogue cases for well-known server kinds; each is checked against the advertised
    schema by the runner, so a tool with a different contract yields INCONCLUSIVE, never a guess."""
    out: List[ControlCase] = []
    k = server.kind
    canary = vars_["canary"]
    sink = vars_["sinkhole"]
    if k in ("filesystem", "git"):
        allowed = (((server.effective_access.get("policy_expected") or {}).get("paths_allowed"))
                   or ((server.effective_access.get("inferred") or {}).get("paths_allowed")) or [])
        root = root or (allowed[0].replace("/**", "").rstrip("/") if allowed else None)
        if not root:
            return out
        canary_file = f"{root}/{canary}.txt"
        writer = _find(server, "write_file", "create_file", "put_file", "save_file")
        reader = _find(server, "read_file", "cat_file", "get_file")
        if writer:
            out.append(ControlCase("FS-WRITE-INSIDE", "write_project_file", server.name, writer.name,
                                   {"path": canary_file, "content": canary}, "allowed", rule_id=None,
                                   expected_invariant="an allowed write inside the root succeeds",
                                   effect_check={"kind": "file_exists", "path": canary_file, "needle": canary},
                                   note="capability confirmation for one allowed object only", source="kind_catalogue"))
            out.append(ControlCase("FS-TRAVERSAL", "path_traversal", server.name, writer.name,
                                   {"path": f"{root}/../{canary}-outside.txt", "content": canary}, "denied", rule_id="AUTH-02",
                                   boundary_ref="fs-root", expected_invariant="a write outside the allowed root is refused and leaves no file",
                                   effect_check={"kind": "file_absent", "path": f"{root}/../{canary}-outside.txt"},
                                   note="resource boundary of the filesystem root", source="kind_catalogue"))
            out.append(ControlCase("FS-DENIED-ETC", "denied_path", server.name, writer.name,
                                   {"path": "/etc/mcp-audit-canary", "content": canary}, "denied", rule_id="AUTH-02",
                                   boundary_ref="fs-root", expected_invariant="a write to /etc is refused",
                                   effect_check={"kind": "file_absent", "path": "/etc/mcp-audit-canary"}, source="kind_catalogue"))
        if reader:
            out.append(ControlCase("FS-READ-INSIDE", "read_project_file", server.name, reader.name, {"path": canary_file}, "allowed",
                                   expected_invariant="an allowed read inside the root returns the canary",
                                   effect_check={"kind": "response_contains", "needle": canary}, source="kind_catalogue"))
            out.append(ControlCase("FS-READ-SECRET", "read_secret_traversal", server.name, reader.name, {"path": "/etc/passwd"}, "denied",
                                   rule_id="AUTH-02", boundary_ref="fs-root", expected_invariant="reading /etc/passwd is refused",
                                   effect_check={"kind": "response_not_contains", "needle": "root:"}, source="kind_catalogue"))
    elif k in ("postgres", "sqlite"):
        q = _find(server, "query", "execute_query", "sql")
        if q:
            out.append(ControlCase("DB-SELECT", "select_probe", server.name, q.name, {"sql": "SELECT 1"}, "allowed",
                                   expected_invariant="a read query succeeds", effect_check={"kind": "response_contains", "needle": "1"},
                                   source="kind_catalogue"))
            ddl_expected = ((server.effective_access.get("policy_expected") or {}).get("ddl"))
            out.append(ControlCase("DB-DDL", "ddl_probe", server.name, q.name,
                                   {"sql": f"CREATE TABLE mcp_audit_canary_{canary[-8:]} (id int)"},
                                   "allowed" if ddl_expected else "denied", rule_id="AUTH-02", boundary_ref="db-ddl",
                                   expected_invariant="DDL is refused unless policy allows it", destructive=True,
                                   teardown=[{"sql": f"DROP TABLE IF EXISTS mcp_audit_canary_{canary[-8:]}"}], source="kind_catalogue"))
    elif k == "shell":
        ex = _find(server, "execute_command", "run_command", "exec", "shell")
        if ex:
            out.append(ControlCase("EXEC-ARBITRARY", "arbitrary_command", server.name, ex.name, {"command": f"echo {canary}"}, "allowed",
                                   expected_invariant="execution capability is confirmed when the canary echoes back",
                                   effect_check={"kind": "response_contains", "needle": canary}, source="kind_catalogue"))
            out.append(ControlCase("EXEC-EGRESS", "egress_probe", server.name, ex.name, {"command": f"curl -s {sink}/{canary}"}, "denied",
                                   rule_id="EGRESS-02", boundary_ref="egress",
                                   expected_invariant="network egress from exec is refused in the fixture (observed by the local sink)",
                                   effect_check={"kind": "sink_received", "needle": canary}, source="kind_catalogue"))
    elif k == "fetch":
        f = _find(server, "fetch", "http_get", "request")
        if f:
            out.append(ControlCase("FETCH-SINKHOLE", "fetch_probe", server.name, f.name, {"url": f"{sink}/{canary}"}, "allowed",
                                   rule_id="EGRESS-02", boundary_ref="egress",
                                   expected_invariant="the outbound fetch reaches only the local sink",
                                   effect_check={"kind": "sink_received", "needle": canary}, source="kind_catalogue"))
    return out
