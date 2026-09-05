"""Config parser: reads MCP client configs and records where every field came from.

Supported shapes:
  * Claude Desktop / Cursor / Windsurf: ``{"mcpServers": {name: {...}}}``
  * VS Code:                            ``{"servers": {name: {...}}}``
  * bare mapping:                        ``{name: {"command": ...}}``
  * list form:                           ``[{"name": ..., "command": ...}]``

Audit-only extensions (ignored by real clients):
  * ``x_audit``: expected-policy statements (``allowed_paths``, ``denied_paths``,
    ``operations``, ``ddl``, ``network_access``, ``kind``, ``native``) - they are
    recorded as *policy expected by the config author*, never as an enforced ACL;
  * ``tools``: an offline tools snapshot (``configured`` inventory) so an offline
    audit can run without spawning anything;
  * ``capture``: how the snapshot was obtained (method, time, identity).

A config never fabricates a live handshake: ``handshake.performed`` stays False.
Missing permissions stay unknown - there is no default allow or deny here.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from ..models import ServerRecord, ToolDefinition, ToolRecord, Handshake

_KNOWN_KINDS = (
    ("filesystem", re.compile(r"server-filesystem|mcp-filesystem|filesystem", re.I)),
    ("postgres", re.compile(r"server-postgres|postgres|pg-mcp|mcp-postgres", re.I)),
    ("sqlite", re.compile(r"server-sqlite|sqlite", re.I)),
    ("github", re.compile(r"server-github|github-mcp|github", re.I)),
    ("gitlab", re.compile(r"server-gitlab|gitlab", re.I)),
    ("git", re.compile(r"server-git(?![a-z])|mcp-server-git", re.I)),
    ("shell", re.compile(r"shell|server-commands|mcp-exec|terminal|bash|run-command", re.I)),
    ("fetch", re.compile(r"server-fetch|fetch|http|browser|puppeteer|playwright|web", re.I)),
    ("memory", re.compile(r"server-memory|memory|knowledge", re.I)),
    ("slack", re.compile(r"slack", re.I)),
    ("email", re.compile(r"mail|smtp|imap", re.I)),
)


def infer_kind(name: str, command: Optional[str], args: List[str], url: Optional[str]) -> str:
    haystack = " ".join([name or "", command or "", *(args or []), url or ""])
    for kind, rx in _KNOWN_KINDS:
        if rx.search(haystack):
            return kind
    return "generic"


def _server_from_entry(name: str, entry: Dict[str, Any], origin: str = "config") -> ServerRecord:
    command = entry.get("command")
    args = [str(a) for a in (entry.get("args") or [])]
    url = entry.get("url") or entry.get("serverUrl")
    transport = (entry.get("transport") or entry.get("type") or "").lower()
    field_sources: Dict[str, str] = {}
    if transport:
        field_sources["transport"] = origin
    else:
        if url:
            transport = "sse" if url.rstrip("/").endswith("/sse") else "http"
        else:
            transport = "stdio"
        field_sources["transport"] = "inferred"
    if transport in ("streamable-http", "streamable_http", "streamablehttp"):
        transport = "http"
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    overrides = dict(entry.get("x_audit") or entry.get("x-audit") or {})
    if overrides.get("kind"):
        kind = overrides["kind"]
        field_sources["kind"] = "x_audit"
    else:
        kind = infer_kind(name, command, args, url)
        field_sources["kind"] = "inferred"
    for key in ("command", "args", "url", "env"):
        if entry.get(key) is not None:
            field_sources[key] = origin
    is_mcp = not bool(overrides.get("native")) and command != "internal"

    rec = ServerRecord(
        name=name, transport=transport, command=command, args=args, env=env, url=url, kind=kind,
        overrides=overrides, field_sources=field_sources, is_mcp=is_mcp,
        component_id=f"server:{name}",
    )
    rec.declared_capabilities = dict(entry.get("capabilities") or {})
    if rec.declared_capabilities:
        field_sources["declared_capabilities"] = origin
    rec.capture = dict(entry.get("capture") or overrides.get("capture") or {})

    # Offline tools snapshot embedded in the config: this is the *configured* inventory.
    if isinstance(entry.get("tools"), list):
        rec.tools = [ToolRecord(server=name, definition=ToolDefinition.from_mcp(t)) for t in entry["tools"]]
        rec.inventory_sources["configured"] = {"count": len(rec.tools), "origin": origin}
        rec.handshake = Handshake(performed=False, ok=None, source="config",
                                  completeness="unknown",
                                  notes=["tools listed in the config; no handshake was performed"])
        field_sources["tools"] = origin
    else:
        rec.inventory_sources["configured"] = {"count": 0, "origin": origin, "note": "no tools listed in config"}
    return rec


def parse_config(data: Any, origin: str = "config") -> List[ServerRecord]:
    """Parse an already-loaded config object into ServerRecords."""
    servers: List[ServerRecord] = []
    if isinstance(data, dict):
        mapping = None
        for key in ("mcpServers", "mcp_servers", "servers"):
            if isinstance(data.get(key), dict):
                mapping = data[key]
                break
        if mapping is None:
            mapping = {k: v for k, v in data.items()
                       if isinstance(v, dict) and ({"command", "url", "serverUrl", "args"} & set(v))}
        for name, entry in mapping.items():
            if not isinstance(entry, dict) or entry.get("disabled") is True:
                continue
            servers.append(_server_from_entry(str(name), entry, origin))
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and entry.get("name"):
                servers.append(_server_from_entry(str(entry["name"]), entry, origin))
    return servers


def looks_like_mcp_config(data: Any) -> bool:
    if isinstance(data, dict):
        if any(isinstance(data.get(k), dict) for k in ("mcpServers", "mcp_servers", "servers")):
            return True
        return any(isinstance(v, dict) and ({"command", "url", "serverUrl"} & set(v)) for v in data.values())
    if isinstance(data, list):
        return all(isinstance(e, dict) and e.get("name") for e in data) and bool(data)
    return False


def load_config_file(path: str) -> List[ServerRecord]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    text = _strip_json_comments(text)
    return parse_config(json.loads(text), origin=f"config:{os.path.basename(path)}")


def parse_snapshot(path: str) -> Dict[str, Dict[str, Any]]:
    """Load a tools snapshot ``{server: {"tools": [...], "resources": [...], ...}}``
    (or ``{server: [tools]}``) captured by a previous live handshake.  A full
    audit JSON (v1 or v2) can be used as a snapshot too; its inventory is then
    treated as ``snapshot``, never as a fresh live handshake."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, dict) and data.get("schema") in ("audit", "agent-security-audit"):
        servers = data.get("servers") if data.get("schema") == "audit" else (data.get("inventory") or {}).get("servers", [])
        for s in servers or []:
            out[s["name"]] = {
                "tools": [{"name": t["name"], "description": t.get("description", ""),
                           "inputSchema": t.get("input_schema", {}), "annotations": t.get("annotations", {})}
                          for t in s.get("tools", [])],
                "resources": s.get("resources", []),
                "prompts": s.get("prompts", []),
                "capabilities": s.get("declared_capabilities", {}),
                "instructions": (s.get("handshake") or {}).get("instructions"),
                "captured_at": (s.get("handshake") or {}).get("captured_at"),
                "identity": (s.get("handshake") or {}).get("identity"),
                "origin": f"audit:{data.get('version') or data.get('schema_version')}",
            }
        return out
    for name, entry in (data or {}).items():
        if isinstance(entry, list):
            out[name] = {"tools": entry}
        elif isinstance(entry, dict):
            out[name] = entry
    return out


_COMMENT_RX = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.S)


def _strip_json_comments(text: str) -> str:
    """JSONC support (VS Code style configs)."""
    def repl(m: "re.Match[str]") -> str:
        return m.group(1) if m.group(1) else ""
    text = _COMMENT_RX.sub(repl, text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text
