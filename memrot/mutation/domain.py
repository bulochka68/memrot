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
    profile_id: str = ""           # mcp_audit meta.profile.id when present (genai-invest-stand, mempalace, ...)


def profile_from_audit(audit_path: str) -> DomainProfile:
    """Best-effort DomainProfile from an mcp_audit JSON report. Pure JSON
    parsing -- this package never imports ``mcp_audit``."""
    with open(audit_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    meta = doc.get("meta") or {}
    profile_meta = meta.get("profile") or {}
    target = meta.get("target") or doc.get("target") or {}
    profile_id = str(profile_meta.get("id") or target.get("id") or "")
    domain = profile_id or str(target.get("name") or "unknown target")
    persona = str(target.get("persona") or profile_meta.get("id") or "")
    tool_names = _collect_tool_names(doc)
    entities = _collect_entities(doc, target)
    return DomainProfile(domain=domain, persona=persona, example_entities=entities,
                         tool_names=tool_names, profile_id=profile_id)


def audit_looks_like_invest_stand(audit_path: str) -> bool:
    """True when the audit JSON was produced against this repo's investment stand.

    Used to decide whether the ``invest_bank`` catalog overlay is in-scope.
    Other profiles (mempalace, rest_native_agent, unknown) stay on the
    generic pool -- the same portability split as ``mcp_audit`` profiles.
    """
    profile = profile_from_audit(audit_path)
    blob = f"{profile.profile_id} {profile.domain}".lower()
    return any(marker in blob for marker in ("genai-invest", "genai_invest", "invest_bank", "invest-stand"))


def _collect_entities(doc: Dict[str, Any], target: Dict[str, Any]) -> List[str]:
    entities: List[str] = []
    seen = set()

    def add(value: Optional[str]) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        entities.append(value)

    for boundary in target.get("boundaries") or []:
        add(str(boundary))
    for principal in doc.get("principals") or []:
        if isinstance(principal, dict):
            add(principal.get("id") or principal.get("name"))
    return entities[:12]


def _collect_tool_names(doc: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    seen = set()

    def add(name: Optional[str]) -> None:
        if not name or name in seen:
            return
        seen.add(name)
        names.append(name)

    inventory = doc.get("inventory") or {}
    for server in inventory.get("servers") or []:
        if not isinstance(server, dict):
            continue
        sources = server.get("inventory_sources") or {}
        for source in sources.values() if isinstance(sources, dict) else []:
            if not isinstance(source, dict):
                continue
            for tool in source.get("tools") or []:
                if isinstance(tool, dict):
                    add(tool.get("name"))
                elif isinstance(tool, str):
                    add(tool)
            for definition in source.get("definitions") or []:
                if isinstance(definition, dict):
                    add(definition.get("name"))
        handshake = server.get("handshake") or {}
        for tool in handshake.get("tools") or []:
            if isinstance(tool, dict):
                add(tool.get("name"))

    for cap in doc.get("capabilities") or []:
        if isinstance(cap, dict):
            add(cap.get("name") or cap.get("tool"))

    if not names:
        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                if "name" in obj and ("digest" in obj or "inputSchema" in obj or "input_schema" in obj):
                    add(str(obj.get("name")))
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
        walk(inventory or doc.get("servers") or {})
    return names[:40]
