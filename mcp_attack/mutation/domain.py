"""Domain profile for adapting a neutral prompt to a target's vocabulary.

Kept a standalone module so the mutation layer, the synthesis generator, and
the audit-JSON importer can share one structure without importing ``mcp_audit``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DomainProfile:
    domain: str                    # 'investment banking', 'healthcare triage', ...
    persona: str = ""              # how the agent refers to itself
    example_entities: List[str] = field(default_factory=list)  # tickers, account ids, ...
    tool_names: List[str] = field(default_factory=list)        # discovered target tools


def profile_from_audit(audit_path: str) -> DomainProfile:
    """Best-effort DomainProfile from an mcp_audit JSON report. Pure JSON
    parsing -- this package never imports ``mcp_audit``."""
    with open(audit_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    target = (doc.get("meta") or {}).get("target") or doc.get("target") or {}
    domain = str(target.get("id") or target.get("name") or "unknown target")
    persona = str(target.get("persona") or "")
    tool_names = _collect_tool_names(doc)
    entities = list(target.get("boundaries") or [])[:8]
    return DomainProfile(domain=domain, persona=persona, example_entities=entities, tool_names=tool_names)


def _collect_tool_names(doc: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    seen = set()

    def add(name: Optional[str]) -> None:
        if not name or name in seen:
            return
        seen.add(name)
        names.append(name)

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if "name" in obj and ("digest" in obj or "inputSchema" in obj or "input_schema" in obj):
                add(str(obj.get("name")))
            tools = obj.get("tools")
            if isinstance(tools, list):
                for t in tools:
                    if isinstance(t, dict):
                        add(t.get("name"))
                    elif isinstance(t, str):
                        add(t)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(doc.get("inventory") or doc.get("servers") or {})
    if not names:
        walk(doc)
    return names[:40]
