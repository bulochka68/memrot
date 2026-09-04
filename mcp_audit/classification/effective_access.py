"""Effective-access resolver: declared config -> effective scope.

Derives what a server can *actually* touch from its command args, env, and
the ``x_audit`` overrides, rather than trusting ``declared_capabilities``.

Examples handled:
  * filesystem: positional path args -> allowed roots; default deny of
    /etc, /root, ~/.ssh unless explicitly allowed.
  * postgres/sqlite: read-only vs. write connection; DDL flag.
  * shell: always unbounded EXEC.
  * network: from ``x_audit.network_access`` or a known network kind.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from ..models import AuditDocument, Operation, ServerRecord

_ALWAYS_DENY = ["/etc/**", "/root/**", "~/.ssh/**", "/proc/**", "/sys/**", "**/.env", "**/.git/config"]


def _fs_paths_from_args(args: List[str]) -> List[str]:
    paths = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            # flags like --root <path>
            if a in ("--root", "--allow", "--dir", "--path"):
                skip_next = False  # value is a path we DO want; handle below
            continue
        # npx package specifiers are not paths
        if a.startswith("@") or a.endswith((".js", ".ts")) or "/server-" in a or a in ("npx", "-y", "node"):
            continue
        if a.startswith("/") or a.startswith("~") or a.startswith("./") or os.path.isabs(os.path.expanduser(a)):
            paths.append(os.path.expanduser(a))
    return paths


def resolve_effective_access(server: ServerRecord) -> Dict[str, Any]:
    ov = server.overrides or {}
    acc: Dict[str, Any] = {"kind": server.kind, "provenance": "effective"}

    if server.kind in ("filesystem", "git"):
        allowed = ov.get("allowed_paths") or _fs_paths_from_args(server.args)
        allowed = [p if p.endswith("**") or p.endswith("/") else p.rstrip("/") + "/**" for p in allowed]
        denied = list(dict.fromkeys((ov.get("denied_paths") or []) + _ALWAYS_DENY))
        acc["paths"] = {"allowed": allowed, "denied": denied}
        acc["unbounded"] = (not allowed) or any(p in ("/**", "/") for p in allowed)
    elif server.kind in ("postgres", "sqlite"):
        ops = ov.get("operations")
        if ops is None:
            # infer from a readonly flag / URL, else assume full DML
            ro = ov.get("readonly") or any("readonly" in a.lower() or "read-only" in a.lower() for a in server.args)
            ops = ["SELECT"] if ro else ["SELECT", "INSERT", "UPDATE", "DELETE"]
        acc["operations"] = ops
        acc["ddl"] = bool(ov.get("ddl", False))
        acc["scope"] = "all" if ov.get("all_tables", True) else ov.get("tables", [])
        acc["unbounded"] = acc["ddl"] or "DELETE" in ops
    elif server.kind == "shell":
        acc["execution"] = "arbitrary"
        acc["unbounded"] = True
        acc["network_access"] = True
    else:
        acc["scope"] = ov.get("scope", "declared")

    if "network_access" not in acc:
        acc["network_access"] = bool(ov.get("network_access")) or server.kind in ("fetch", "github", "gitlab", "slack", "email")

    server.effective_access = acc
    # propagate the scope to each tool so the risk scorer can see it
    for t in server.tools:
        t.effective_access = _tool_scope(t, acc)
        t.provenance["effective_access"] = "effective"
    return acc


def _tool_scope(tool, acc: Dict[str, Any]) -> Dict[str, Any]:
    scope: Dict[str, Any] = {"network_access": acc.get("network_access", False)}
    if "paths" in acc:
        scope["paths"] = acc["paths"]
        scope["unbounded"] = acc.get("unbounded", False)
    if "operations" in acc:
        # a READ tool only exercises SELECT even if the connection allows more
        if tool.classification == Operation.READ:
            scope["operations"] = [o for o in acc["operations"] if o in ("SELECT",)] or ["SELECT"]
        else:
            scope["operations"] = acc["operations"]
        scope["ddl"] = acc.get("ddl", False)
        scope["unbounded"] = acc.get("unbounded", False)
    if acc.get("execution") == "arbitrary":
        scope["execution"] = "arbitrary"
        scope["unbounded"] = True
    return scope
