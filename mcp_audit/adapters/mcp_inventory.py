"""MCP inventory adapter: configured / snapshot / live-advertised catalogues.

Returns the server identity, protocol version, definitions, resources /
prompts, the source and time of the snapshot.  It does not assume that the
absence of a tool in one answer proves its absence for another role, and a
config never fabricates a live handshake (TZ §5.3, §6).
"""
from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, List, Optional

from ..models import (AuditDocument, Method, RunMode, ServerRecord, SourceType, ToolDefinition,
                      ToolRecord, digest as _digest)
from ..evidence import EvidenceStore
from ..discovery.config_parser import load_config_file, parse_snapshot
from ..discovery.introspector import introspect_server, apply_snapshot
from ..discovery.context_parser import discover_context_files, parse_context_file
from .base import Adapter, AdapterResult
from .registry import register


def _file_digest(path: str) -> str:
    with open(path, "rb") as fh:
        return "sha256:" + hashlib.sha256(fh.read()).hexdigest()


def _credential_headers(binding: Dict[str, Any]) -> Dict[str, str]:
    """Credentials are never in the manifest: ``credential_binding`` names an
    environment variable ``MCP_AUDIT_CRED_<NAME>`` holding the header value."""
    name = binding.get("credential_binding")
    if not name:
        return {}
    val = os.environ.get(f"MCP_AUDIT_CRED_{name}")
    if not val:
        return {}
    header = binding.get("credential_header", "Authorization")
    return {header: val}


@register
class MCPInventoryAdapter(Adapter):
    kind = "mcp_inventory"
    adapter_version = "2.0.0"
    supported = ["configured_inventory", "snapshot_inventory", "live_inventory(stdio,http,sse)",
                 "resources_list", "prompts_list", "server_instructions", "agent_context_files"]
    unsupported = {
        "role_enumeration": "a handshake shows the catalogue for one identity only",
        "runtime_observed": "runtime usage comes from the trace adapter",
        "policy_authorized": "authorized tool lists come from the policy adapter",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        reasons: List[str] = []
        cfg_path = self.binding.path("path")
        if not cfg_path or not os.path.isfile(cfg_path):
            return AdapterResult(self.status("unavailable", [f"config not found: {cfg_path}"]))
        servers = load_config_file(cfg_path)
        cfg_ev = store.add(SourceType.CONFIG, Method.PARSING, {"path": os.path.relpath(cfg_path), "kind": "mcp_config"},
                           digest=_file_digest(cfg_path), adapter=self.kind, adapter_version=self.adapter_version,
                           summary=f"MCP client config with {len(servers)} server entr(ies)")
        snapshot: Dict[str, Dict[str, Any]] = {}
        snap_path = self.binding.path("snapshot")
        if snap_path:
            if os.path.isfile(snap_path):
                snapshot = parse_snapshot(snap_path)
            else:
                reasons.append(f"snapshot not found: {snap_path}")
        live = doc.mode.spawns_processes and bool(self.binding.binding.get("live", True))
        identity = self.binding.binding.get("identity")
        headers = _credential_headers(self.binding.binding)
        evidence_count = 1
        partial = False
        capture = self.binding.binding.get("capture") or {}

        for s in servers:
            existing = doc.server(s.name)
            if existing is not None:
                reasons.append(f"server {s.name!r} already present; second definition ignored")
                continue
            if capture and not s.capture:
                s.capture = dict(capture)
            configured_defs = [t.definition for t in s.tools]
            if configured_defs:
                s.inventory_sources["configured"]["tools"] = [
                    {"name": d.name, "digest": _digest(d.raw or {"name": d.name})} for d in configured_defs]
                s.inventory_sources["configured"]["definitions"] = [d.raw for d in configured_defs]
                ev = store.add(SourceType.DEFINITION, Method.PARSING,
                               {"path": os.path.relpath(cfg_path), "server": s.name, "inventory": "configured"},
                               digest=_digest([d.raw for d in configured_defs]), adapter=self.kind,
                               adapter_version=self.adapter_version,
                               summary=f"{len(configured_defs)} configured tool definition(s) for {s.name}",
                               limitations=["configured catalogue: what the client config lists, not what a server advertises"])
                s.inventory_sources["configured"]["evidence_ref"] = ev.evidence_id
                evidence_count += 1
            if s.name in snapshot:
                apply_snapshot(s, snapshot[s.name])
                ev = store.add(SourceType.DEFINITION, Method.PARSING,
                               {"path": os.path.relpath(snap_path or ""), "server": s.name, "inventory": "snapshot"},
                               digest=_digest([t.definition.raw for t in s.tools]), adapter=self.kind,
                               adapter_version=self.adapter_version, captured_at=s.handshake.captured_at,
                               summary=f"{len(s.tools)} tool definition(s) replayed from snapshot for {s.name}",
                               limitations=["snapshot of an earlier handshake; identity/time recorded if the snapshot carried them"])
                s.inventory_sources["snapshot"]["evidence_ref"] = ev.evidence_id
                evidence_count += 1
                if configured_defs:
                    s.inventory_sources["configured"]["superseded_by"] = "snapshot"
            elif live and s.is_mcp:
                introspect_server(s, timeout=float(self.binding.options.get("timeout", 20.0)),
                                  cwd=self.binding.options.get("cwd"), identity=identity, headers=headers or None,
                                  env_allow=self.binding.binding.get("env_allow"))
                ev = store.add(SourceType.DEFINITION, Method.OBSERVATION,
                               {"server": s.name, "inventory": "live_advertised", "identity": identity,
                                "transport": s.transport, "url": s.url},
                               digest=_digest([t.definition.raw for t in s.tools]) if s.handshake.ok else None,
                               adapter=self.kind, adapter_version=self.adapter_version,
                               captured_at=s.handshake.captured_at,
                               summary=(f"live handshake ok; {len(s.tools)} tool(s) advertised to identity {identity!r}"
                                        if s.handshake.ok else f"live handshake failed: {s.handshake.error}"),
                               limitations=["catalogue advertised to this identity at this moment only"])
                s.inventory_sources["live_advertised"]["evidence_ref"] = ev.evidence_id
                evidence_count += 1
                if not s.handshake.ok:
                    partial = True
                    reasons.append(f"{s.name}: live handshake failed ({s.handshake.error}); catalogue unavailable")
                    if configured_defs:
                        # keep the configured catalogue for review, but say so
                        s.tools = [ToolRecord(server=s.name, definition=d) for d in configured_defs]
                        s.handshake.notes.append("configured definitions retained for review; not a live catalogue")
                elif configured_defs:
                    s.inventory_sources["configured"]["superseded_by"] = "live_advertised"
            elif live and not s.is_mcp:
                s.handshake.notes.append("native component: no MCP handshake possible")
            doc.servers.append(s)

        # agent context files (instructions are data under audit)
        ctx_root = self.binding.path("context_root")
        paths: List[str] = []
        for p in self.binding.binding.get("context_files") or []:
            paths.append(p if os.path.isabs(p) else os.path.join(self.binding.base_dir, p))
        if ctx_root and os.path.isdir(ctx_root):
            paths += discover_context_files(ctx_root)
        seen = set()
        for p in paths:
            if p in seen or not os.path.isfile(p):
                continue
            seen.add(p)
            cf = parse_context_file(p)
            doc.agent_context.append(cf)
            store.add(SourceType.CONFIG, Method.PARSING, {"path": os.path.relpath(p), "kind": cf.kind},
                      digest="sha256:" + cf.sha256, adapter=self.kind, adapter_version=self.adapter_version,
                      summary=f"agent context file ({cf.kind}), {cf.size} bytes",
                      limitations=["content is data under audit; it does not configure the auditor"])
            evidence_count += 1

        state = "partial" if partial else "available"
        return AdapterResult(self.status(state, reasons, captured_at=time.time(), evidence_count=evidence_count),
                             facts={"config_evidence": cfg_ev.evidence_id})
