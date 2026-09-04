"""Audit orchestrator.

Owns the single data model (the audit JSON) and drives the layers per mode:

  passive : 1 discovery (config + live/snapshot) -> 2 static -> 3 classify -> 5 correlate -> 6 report
  active  : passive + 4 active probes (sandbox only)
  drift   : 1 discovery + 2 static, then compare hashes against a baseline

Discovery sources, in order of preference per server:
  live handshake (if allowed) -> config-embedded tools -> external snapshot.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from . import AUDIT_SCHEMA_VERSION, __version__
from .models import AuditDocument, Mode, ServerRecord
from .discovery import (parse_config, load_config_file, parse_snapshot,
                        introspect_server, discover_context_files, parse_context_file)
from .discovery.introspector import apply_snapshot
from .static_analysis import run_static_analysis
from .classification import classify_all, resolve_effective_access, score_tool
from .correlation import assess_trifecta, build_summary, build_verdict, build_security_findings
from .active import IsolationGuard, run_active_verification


class Orchestrator:
    def __init__(self, mode: Mode = Mode.PASSIVE):
        self.mode = mode

    # -- layer 1 ------------------------------------------------------------ #
    def discover(self, servers: List[ServerRecord], *, live: bool = False,
                 snapshot: Optional[Dict[str, Dict[str, Any]]] = None,
                 context_root: Optional[str] = None, context_files: Optional[List[str]] = None,
                 timeout: float = 20.0, cwd: Optional[str] = None) -> AuditDocument:
        doc = AuditDocument(mode=self.mode, servers=servers)
        snapshot = snapshot or {}
        for s in servers:
            if s.tools:                       # config-embedded snapshot already present
                continue
            if s.name in snapshot:
                apply_snapshot(s, snapshot[s.name])
            elif live:
                introspect_server(s, timeout=timeout, cwd=cwd)

        # context files
        paths: List[str] = list(context_files or [])
        if context_root:
            paths += discover_context_files(context_root)
        seen = set()
        for p in paths:
            if p in seen:
                continue
            seen.add(p)
            try:
                doc.agent_context.append(parse_context_file(p))
            except OSError:
                continue

        doc.meta = {
            "tool": "mcp-audit", "version": __version__, "schema_version": AUDIT_SCHEMA_VERSION,
            "generated_at": time.time(), "mode": self.mode.value,
            "discovery": {"live": live, "snapshot": bool(snapshot),
                          "context_files": len(doc.agent_context)},
        }
        return doc

    # -- full pipeline ------------------------------------------------------ #
    def run(self, doc: AuditDocument, *, config_path: Optional[str] = None,
            use_mcp_scan: bool = False, guard: Optional[IsolationGuard] = None,
            baseline_path: Optional[str] = None, timeout: float = 20.0,
            cwd: Optional[str] = None) -> AuditDocument:

        # Layer 3 first: effective access & classification feed everything else.
        for s in doc.servers:
            resolve_effective_access(s)
        classify_all(doc)

        # Layer 2: definition plane.
        run_static_analysis(doc, config_path=config_path, use_mcp_scan=use_mcp_scan)

        if self.mode is Mode.DRIFT:
            from .reporting import run_drift
            if not baseline_path:
                raise ValueError("drift mode requires baseline_path")
            run_drift(doc, baseline_path)
            doc.summary = {"mode": "drift", "drift": doc.drift}
            doc.verdict = {"drift": doc.drift, "clean": doc.drift.get("clean")}
            return doc

        # Layer 3 (risk) after effective access is known.
        for t in doc.all_tools():
            score_tool(t, server_kind=(doc.server(t.server).kind if doc.server(t.server) else "generic"))

        # Layer 4: active probes (sandbox only).
        if self.mode is Mode.ACTIVE:
            guard = guard or IsolationGuard(sandbox=True)
            run_active_verification(doc, guard, timeout=timeout, cwd=cwd)

        # Layer 5: correlation.
        doc.summary["trifecta"] = assess_trifecta(doc)
        doc.security_findings = build_security_findings(doc)
        doc.summary = {**build_summary(doc), "trifecta": doc.summary["trifecta"]}
        doc.verdict = build_verdict(doc)
        return doc


# -- convenience one-shots -------------------------------------------------- #

def audit_from_config(config_path: str, *, mode: Mode = Mode.PASSIVE, live: bool = False,
                      snapshot_path: Optional[str] = None, context_root: Optional[str] = None,
                      use_mcp_scan: bool = False, sandbox: bool = False,
                      baseline_path: Optional[str] = None, timeout: float = 20.0,
                      cwd: Optional[str] = None) -> AuditDocument:
    servers = load_config_file(config_path)
    snapshot = parse_snapshot(snapshot_path) if snapshot_path else None
    orch = Orchestrator(mode)
    doc = orch.discover(servers, live=live, snapshot=snapshot, context_root=context_root,
                        timeout=timeout, cwd=cwd)
    guard = IsolationGuard(sandbox=sandbox) if mode is Mode.ACTIVE else None
    return orch.run(doc, config_path=config_path, use_mcp_scan=use_mcp_scan, guard=guard,
                    baseline_path=baseline_path, timeout=timeout, cwd=cwd)
