"""Access resolver: *policy expected* vs *inferred* vs *observed* (TZ §2, §19).

* ``policy_expected`` - what the config author / policy states (``x_audit``);
  including the auditor's conventional denials, which are labelled as an
  expectation and never as an enforced ACL;
* ``inferred``        - derived from server kind, command args and URLs; an
  assumption with its basis recorded;
* ``observed``        - filled only by controlled validation / traces.

Nothing here is "effective" in the v1 sense: an enforced access scope needs a
policy snapshot, a DB/process/network adapter or an observation.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from ..models import Operation, ServerRecord

CONVENTIONAL_DENIALS = ["/etc/**", "/root/**", "~/.ssh/**", "/proc/**", "/sys/**", "**/.env", "**/.git/config"]
_ALWAYS_DENY = CONVENTIONAL_DENIALS   # legacy name


def _fs_paths_from_args(args: List[str]) -> List[str]:
    paths = []
    for a in args:
        if a.startswith("-"):
            continue
        if a.startswith("@") or a.endswith((".js", ".ts")) or "/server-" in a or a in ("npx", "-y", "node"):
            continue
        if a.startswith("/") or a.startswith("~") or a.startswith("./") or os.path.isabs(os.path.expanduser(a)):
            paths.append(os.path.expanduser(a))
    return paths


def _norm_paths(paths: List[str]) -> List[str]:
    return [p if p.endswith("**") or p.endswith("/") else p.rstrip("/") + "/**" for p in paths]


def resolve_effective_access(server: ServerRecord) -> Dict[str, Any]:
    ov = server.overrides or {}
    expected: Dict[str, Any] = {"basis": "x_audit / config author statement", "enforced": "unknown"}
    inferred: Dict[str, Any] = {"basis": "server kind, command arguments and URL", "knowledge_state": "assumed"}
    observed: Dict[str, Any] = {"basis": "controlled validation / trace", "items": []}

    if ov.get("allowed_paths") is not None:
        expected["paths_allowed"] = _norm_paths(list(ov["allowed_paths"]))
    if ov.get("denied_paths") is not None:
        expected["paths_denied"] = list(ov["denied_paths"])
    for key in ("operations", "ddl", "network_access", "scope", "readonly", "tables", "all_tables"):
        if key in ov:
            expected[key] = ov[key]

    if server.kind in ("filesystem", "git"):
        roots = _fs_paths_from_args(server.args)
        inferred["paths_allowed"] = _norm_paths(roots)
        inferred["conventional_denials"] = {
            "paths": list(CONVENTIONAL_DENIALS),
            "note": "auditor convention for expected policy; not an ACL observed on the server",
        }
        allowed = expected.get("paths_allowed") or inferred["paths_allowed"]
        inferred["unbounded"] = (not allowed) or any(p in ("/**", "/") for p in allowed)
        if not allowed:
            inferred["knowledge_state"] = "unknown"
            inferred["note"] = "no root given in config; scope unknown (not assumed to be everything, not assumed to be nothing)"
    elif server.kind in ("postgres", "sqlite", "mysql"):
        ro = ov.get("readonly") or any("readonly" in a.lower() or "read-only" in a.lower() for a in server.args)
        inferred["operations"] = ["SELECT"] if ro else ["SELECT", "INSERT", "UPDATE", "DELETE"]
        inferred["operations_note"] = "from a readonly flag if present; otherwise the connection is assumed to allow DML - unverified"
        inferred["ddl"] = None if "ddl" not in ov else ov["ddl"]
        inferred["unbounded"] = (ov.get("ddl") is True) or ("DELETE" in (ov.get("operations") or inferred["operations"]))
    elif server.kind == "shell":
        inferred["execution"] = "arbitrary"
        inferred["unbounded"] = True
        inferred["network_access"] = True
        inferred["knowledge_state"] = "assumed"
    else:
        inferred["scope"] = "declared-only"

    if "network_access" not in inferred:
        inferred["network_access"] = bool(ov.get("network_access")) if "network_access" in ov else \
            (True if server.kind in ("fetch", "github", "gitlab", "slack", "email", "native") else None)
        if inferred["network_access"] is None:
            inferred["network_access_note"] = "unknown: no override and kind does not imply a network"

    acc = {"kind": server.kind, "policy_expected": expected, "inferred": inferred, "observed": observed,
           "enforcement": "unknown", "note": "expected/inferred access is not an enforced ACL; enforcement needs policy, adapter or observation"}
    server.effective_access = acc
    for t in server.tools:
        t.effective_access = _tool_scope(t, acc)
        t.provenance["access"] = "expected+inferred"
    return acc


def _tool_scope(tool, acc: Dict[str, Any]) -> Dict[str, Any]:
    inf = acc.get("inferred", {})
    exp = acc.get("policy_expected", {})
    scope: Dict[str, Any] = {"network_access": exp.get("network_access", inf.get("network_access")),
                             "basis": "expected+inferred", "enforcement": "unknown"}
    if "paths_allowed" in inf or "paths_allowed" in exp:
        scope["paths"] = {"allowed": exp.get("paths_allowed") or inf.get("paths_allowed") or [],
                          "denied_expected": (exp.get("paths_denied") or []) + list(CONVENTIONAL_DENIALS)}
        scope["unbounded"] = inf.get("unbounded", False)
    if "operations" in inf or "operations" in exp:
        ops = exp.get("operations") or inf.get("operations") or []
        scope["operations"] = [o for o in ops if o == "SELECT"] or ["SELECT"] if tool.classification == Operation.READ else ops
        scope["ddl"] = exp.get("ddl", inf.get("ddl"))
        scope["unbounded"] = inf.get("unbounded", False)
    if inf.get("execution") == "arbitrary":
        scope["execution"] = "arbitrary"
        scope["unbounded"] = True
    return scope
