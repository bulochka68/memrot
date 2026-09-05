"""Config parser: reads MCP server configs in the common client formats.

Supported shapes:
  * Claude Desktop / Cursor / Windsurf: ``{"mcpServers": {name: {...}}}``
  * VS Code:                            ``{"servers": {name: {...}}}``
  * bare mapping:                        ``{name: {"command": ...}}``
  * list form:                           ``[{"name": ..., "command": ...}]``

Non-standard extension (ignored by real clients, consumed by the audit):
  * ``"x_audit": {"allowed_paths": [...], "denied_paths": [...],
                  "kind": "filesystem", "network_access": true, ...}``
    -> explicit effective-access overrides.
  * ``"tools": [...]`` -> an offline tools snapshot for passive audits that
    cannot spawn the server.
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


def _expand(value: str) -> str:
    return os.path.expandvars(os.path.expanduser(value))


def _server_from_entry(name: str, entry: Dict[str, Any]) -> ServerRecord:
    command = entry.get("command")
    args = [str(a) for a in (entry.get("args") or [])]
    url = entry.get("url") or entry.get("serverUrl")
    transport = (entry.get("transport") or entry.get("type") or "").lower()
    if not transport:
        if url:
            transport = "sse" if url.rstrip("/").endswith("/sse") else "http"
        else:
            transport = "stdio"
    if transport in ("streamable-http", "streamable_http", "streamablehttp"):
        transport = "http"
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    overrides = dict(entry.get("x_audit") or entry.get("x-audit") or {})
    kind = overrides.get("kind") or infer_kind(name, command, args, url)

    rec = ServerRecord(
        name=name,
        transport=transport,
        command=command,
        args=args,
        env=env,
        url=url,
        kind=kind,
        overrides=overrides,
    )
    rec.declared_capabilities = dict(entry.get("capabilities") or {})

    # Offline tools snapshot embedded in the config (non-standard).
    if isinstance(entry.get("tools"), list):
        rec.tools = [ToolRecord(server=name, definition=ToolDefinition.from_mcp(t)) for t in entry["tools"]]
        rec.handshake = Handshake(ok=True, source="config")
    return rec


def parse_config(data: Any) -> List[ServerRecord]:
    """Parse an already-loaded config object into ServerRecords."""
    servers: List[ServerRecord] = []
    if isinstance(data, dict):
        mapping = None
        for key in ("mcpServers", "mcp_servers", "servers"):
            if isinstance(data.get(key), dict):
                mapping = data[key]
                break
        if mapping is None:
            # bare mapping: every value that looks like a server entry
            mapping = {k: v for k, v in data.items()
                       if isinstance(v, dict) and ({"command", "url", "serverUrl", "args"} & set(v))}
        for name, entry in mapping.items():
            if not isinstance(entry, dict) or entry.get("disabled") is True:
                continue
            servers.append(_server_from_entry(str(name), entry))
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and entry.get("name"):
                servers.append(_server_from_entry(str(entry["name"]), entry))
    return servers


def load_config_file(path: str) -> List[ServerRecord]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    text = _strip_json_comments(text)
    return parse_config(json.loads(text))


def parse_snapshot(path: str) -> Dict[str, Dict[str, Any]]:
    """Load a tools snapshot ``{server: {"tools": [...], "resources": [...], ...}}``
    (or ``{server: [tools]}``) captured by a previous live handshake."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: Dict[str, Dict[str, Any]] = {}
    # A full audit JSON can be used as a snapshot too.
    if isinstance(data, dict) and data.get("schema") == "audit":
        for s in data.get("servers", []):
            out[s["name"]] = {
                "tools": [{"name": t["name"], "description": t.get("description", ""),
                           "inputSchema": t.get("input_schema", {}), "annotations": t.get("annotations", {})}
                          for t in s.get("tools", [])],
                "resources": s.get("resources", []),
                "prompts": s.get("prompts", []),
                "capabilities": s.get("declared_capabilities", {}),
                "instructions": (s.get("handshake") or {}).get("instructions"),
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
    # trailing commas
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text
