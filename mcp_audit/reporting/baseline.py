"""Baseline store for drift detection (P8).

Persists the definition hashes plus a capability snapshot so a later audit
can detect rug pulls (changed definitions) and newly appeared servers/tools.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from ..models import AuditDocument


def build_baseline(doc: AuditDocument) -> Dict[str, Any]:
    return {
        "created_at": time.time(),
        "schema": "audit-baseline",
        "version": "1.1",
        "hash_baseline": dict(sorted(doc.hash_baseline.items())),
        "servers": sorted(s.name for s in doc.servers),
        "tools": sorted(t.qualified_name for t in doc.all_tools()),
        "instructions": {s.name: (s.handshake.instructions or "") for s in doc.servers},
    }


def save_baseline(doc: AuditDocument, path: str) -> Dict[str, Any]:
    baseline = build_baseline(doc)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, ensure_ascii=False)
    return baseline


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def diff_baseline(old: Dict[str, Any], doc: AuditDocument) -> Dict[str, Any]:
    """Compare a stored baseline to the current audit."""
    cur = build_baseline(doc)
    old_hashes: Dict[str, str] = old.get("hash_baseline", {})
    cur_hashes: Dict[str, str] = cur["hash_baseline"]

    changed: List[Dict[str, str]] = []
    for key, h in cur_hashes.items():
        if key in old_hashes and old_hashes[key] != h:
            changed.append({"key": key, "old": old_hashes[key], "new": h})
    added_tools = sorted(set(cur_hashes) - set(old_hashes))
    removed_tools = sorted(set(old_hashes) - set(cur_hashes))
    added_servers = sorted(set(cur["servers"]) - set(old.get("servers", [])))
    removed_servers = sorted(set(old.get("servers", [])) - set(cur["servers"]))

    alerts: List[str] = []
    if changed:
        alerts.append(f"RUG_PULL: {len(changed)} definition(s) changed after approval")
    if added_servers:
        alerts.append(f"NEW_SERVER: {added_servers} - requires a full re-audit")
    if added_tools:
        alerts.append(f"NEW_TOOL: {len(added_tools)} tool definition(s) appeared")
    if removed_servers or removed_tools:
        alerts.append("REMOVED: servers/tools disappeared since baseline")

    return {
        "rug_pull": bool(changed),
        "changed_definitions": changed,
        "added_tools": added_tools,
        "removed_tools": removed_tools,
        "added_servers": added_servers,
        "removed_servers": removed_servers,
        "alerts": alerts,
        "clean": not (changed or added_tools or removed_tools or added_servers or removed_servers),
    }
