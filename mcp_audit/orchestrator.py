"""Audit orchestrator v2.

Data flow (TZ §5): manifest + profile -> applicability plan -> adapters (evidence)
-> inventory/classification/static signals -> graph & correlation -> control rules
-> coverage -> verdict -> report.

Rules:
  * offline mode never spawns processes or connects anywhere;
  * a missing adapter shows up in the plan, in coverage and in the affected
    controls as NOT_EVALUATED - never as an empty list of findings with a green verdict;
  * adapter failures produce partial results, not exceptions.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from . import AUDIT_SCHEMA_VERSION, ENGINE_VERSION, RULESET_VERSION, __version__
from .models import (AccessProfile, AuditDocument, ClaimStatus, Confidence, Handshake, Mode, RunMode, ServerRecord,
                     SourceType, Method, ToolDefinition, ToolRecord, coerce_mode)
from .evidence import EvidenceStore
from .manifest import Manifest, load_manifest, load_profile, wrap_legacy_config
from .adapters import AdapterBinding, build as build_adapter
from .adapters.registry import load_entry_point_plugins, load_plugins
from .adapters.base import AdapterResult
from .models import AdapterStatus
from .static_analysis import run_static_analysis
from .classification import classify_all, resolve_effective_access, score_tool
from .graph import build_graph, correlate_paths
from .memory import observe_cases
from .control_rules import evaluate_all, plan as plan_rules, ALL_RULES
from .correlation import assess_trifecta, build_summary, build_verdict, capability_indicators
from .coverage import build_coverage
from .active import IsolationGuard, run_controlled_validation
from .reporting.baseline import run_drift


class Orchestrator:
    def __init__(self, manifest: Manifest, profile: Optional[Dict[str, Any]] = None):
        self.manifest = manifest
        self.profile = profile if profile is not None else load_profile(manifest.profile_ref, manifest.base_dir)

    # -- setup -------------------------------------------------------------- #
    def new_document(self) -> AuditDocument:
        m = self.manifest
        doc = AuditDocument(mode=m.mode, access_profile=m.access_profile, run_id=f"run-{uuid.uuid4().hex[:12]}",
                            target=dict(m.target), profile=self.profile)
        doc.meta = {
            "tool": "mcp-audit", "engine_version": ENGINE_VERSION, "schema_version": AUDIT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION, "generated_at": time.time(),
            "manifest": {"path": m.path, "schema_version": m.schema_version, "legacy_wrapped": m.legacy_wrapped,
                         "adapters": [{"id": a.adapter_id, "kind": a.kind} for a in m.adapters]},
            "profile": {"id": self.profile.get("profile_id"), "version": self.profile.get("profile_version"),
                        "path": self.profile.get("_path")} if self.profile else None,
            "reproducibility": m.reproducibility,
            "reporting": m.reporting,
        }
        if m.legacy_wrapped:
            doc.limitations.append("legacy MCP config wrapped into a manifest: target identity, build and environment were not declared")
        return doc

    # -- adapters ----------------------------------------------------------- #
    def load_adapter_plugins(self, doc: AuditDocument) -> None:
        """Register adapters declared outside the package (entry points + manifest)."""
        kinds, problems = load_entry_point_plugins()
        more, more_problems = load_plugins(self.manifest.adapter_plugins)
        loaded = kinds + more
        problems += more_problems
        if loaded or problems:
            doc.meta["adapter_plugins"] = {"loaded": loaded, "problems": problems,
                                           "declared": list(self.manifest.adapter_plugins)}
        for problem in problems:
            # a source that could not be loaded is a gap in coverage, not a silent pass
            doc.limitations.append(f"adapter plugin not loaded: {problem}")

    def collect(self, doc: AuditDocument, store: EvidenceStore, *, timeout: float = 20.0, cwd: Optional[str] = None) -> None:
        self.load_adapter_plugins(doc)
        for b in self.manifest.adapters:
            b.options.setdefault("timeout", timeout)
            if cwd:
                b.options.setdefault("cwd", cwd)
            try:
                adapter = build_adapter(b)
            except KeyError as e:
                doc.adapters.append(AdapterStatus(adapter_id=b.adapter_id, kind=b.kind, adapter_version="?", status="unavailable",
                                                  reasons=[str(e)]))
                continue
            if adapter.allowed_modes and doc.mode.value not in adapter.allowed_modes:
                doc.adapters.append(adapter.status("skipped", [f"adapter not allowed in mode {doc.mode.value}"]))
                continue
            try:
                res: AdapterResult = adapter.collect(doc, store)
            except Exception as exc:     # an adapter failure is partial coverage, not a crash
                res = AdapterResult(adapter.status("unavailable", [f"{type(exc).__name__}: {exc}"]))
            doc.adapters.append(res.status)
        # order: profile-declared components must exist before the graph is built
        avail = {a.kind for a in doc.adapters if a.status in ("available", "partial", "stale")}
        doc.plan = plan_rules(avail, self.manifest.required_controls or None, mode=doc.mode.value)

    def available_kinds(self, doc: AuditDocument) -> set:
        return {a.kind for a in doc.adapters if a.status in ("available", "partial", "stale")}

    # -- pipeline ----------------------------------------------------------- #
    def run(self, *, timeout: float = 20.0, cwd: Optional[str] = None, use_mcp_scan: bool = False,
            guard: Optional[IsolationGuard] = None, baseline_path: Optional[str] = None,
            approvals_path: Optional[str] = None, sink: Optional[Dict[str, Any]] = None) -> AuditDocument:
        doc = self.new_document()
        store = EvidenceStore(doc)
        try:
            self.collect(doc, store, timeout=timeout, cwd=cwd)
            self._materialize_source_tools(doc)
            # layer 3: access expectations & classification
            for s in doc.servers:
                resolve_effective_access(s)
            classify_all(doc)
            # layer 2: definition plane (signals, hashes, reconciliation)
            cfg = self.manifest.adapter("mcp-config")
            run_static_analysis(doc, store, config_path=(cfg.path("path") if cfg else None),
                                use_mcp_scan=use_mcp_scan and doc.mode != RunMode.OFFLINE)
            for t in doc.all_tools():
                s = doc.server(t.server)
                score_tool(t, server_kind=s.kind if s else "generic")
            # declaration claims for source-defined tools
            for d in doc.source_facts.get("tool_declarations") or []:
                if d.get("status") == "unknown" or not d.get("evidence_refs"):
                    continue
                store.claim(f"CL-DECL-{d.get('component')}-{d['name']}", f"{d.get('component')}/{d['name']} is declared in {d.get('path')}",
                            ClaimStatus.STATIC_SUPPORTED, evidence_refs=d["evidence_refs"], confidence=Confidence.HIGH,
                            source_type=SourceType.SOURCE_CODE, method=Method.STATIC_ANALYSIS,
                            limitations=["declaration in this build; the running server's catalogue was not checked"])
            # baseline comparison (drift)
            if baseline_path:
                run_drift(doc, baseline_path, store, approvals_path=approvals_path)
            # layer 4: controlled validation
            if doc.mode == RunMode.CONTROLLED_VALIDATION:
                guard = guard or IsolationGuard(sandbox=False)
                run_controlled_validation(doc, guard, store, timeout=timeout, cwd=cwd, sink=sink)
            # memory cases from fixtures / traces
            self._memory_cases(doc)
            # graph & correlation
            graph = build_graph(doc)
            correlation = correlate_paths(doc, graph)
            doc.trifecta = assess_trifecta(doc, correlation)
            doc.summary["capability_indicators"] = capability_indicators(doc, store)
            # control rules
            required = self.manifest.required_controls or [r.rule_id for r in ALL_RULES]
            evaluate_all(doc, store, self.available_kinds(doc), required, correlation=correlation)
            doc.summary["correlation"] = correlation
            # coverage & verdict
            build_coverage(doc, required)
            if baseline_path:
                run_drift(doc, baseline_path, store, approvals_path=approvals_path)   # refresh coverage comparison
            doc.summary = {**build_summary(doc), "capability_indicators": doc.summary["capability_indicators"], "correlation": correlation}
            doc.status = "completed"
            doc.verdict = build_verdict(doc, required)
            if doc.verdict["assessment_state"] != "complete_for_scope":
                doc.status = "partial"
        except Exception as exc:
            doc.status = "failed"
            doc.limitations.append(f"audit aborted: {type(exc).__name__}: {exc}")
            required = self.manifest.required_controls or [r.rule_id for r in ALL_RULES]
            try:
                build_coverage(doc, required)
                doc.summary = build_summary(doc)
                doc.verdict = build_verdict(doc, required)
            except Exception:
                doc.verdict = {"assessment_state": "not_assessed", "security_conclusion": "undetermined",
                               "basis": [], "limitations": doc.limitations}
            doc.meta["error"] = f"{type(exc).__name__}: {exc}"
        doc.finished_at = time.time()
        return doc

    def _materialize_source_tools(self, doc: AuditDocument) -> None:
        """Tools declared only in source (native functions of a component without an MCP entry)
        become inventory entries with ``source_defined`` as their only catalogue (TZ §6.4)."""
        aliases = self.profile.get("servers") or {}
        comp_types = {c["id"]: c for c in self.profile.get("components") or []}
        by_component: Dict[str, List[Dict[str, Any]]] = {}
        for d in doc.source_facts.get("tool_declarations") or []:
            if d.get("status") == "unknown" or not d.get("component"):
                continue
            by_component.setdefault(d["component"], []).append(d)
        for comp, decls in by_component.items():
            server_name = next((k for k, v in aliases.items() if v == comp), comp)
            if doc.server(server_name) or doc.server(comp):
                continue
            ctype = (comp_types.get(comp) or {}).get("type", "native_function")
            rec = ServerRecord(name=server_name, transport="native", command=None, kind="native", is_mcp=False,
                               component_id=comp)
            rec.tools = [ToolRecord(server=server_name, definition=ToolDefinition.from_mcp(
                {"name": d["name"], "description": d.get("description") or "", "inputSchema": d.get("input_schema") or {},
                 "annotations": d.get("annotations") or {}, "x_audit": d.get("declared") or {}}))
                for d in decls]
            rec.handshake = Handshake(performed=False, ok=None, source="source", completeness="unknown",
                                      notes=[f"native {ctype}: declarations extracted from source; no handshake exists for native functions"])
            rec.inventory_sources["source_defined"] = {"count": len(decls), "origin": "source_snapshot"}
            doc.servers.append(rec)

    def _memory_cases(self, doc: AuditDocument) -> None:
        fx = doc.meta.get("control_fixtures") or {}
        cases = list(fx.get("memory_cases") or []) + list(self.profile.get("memory_cases") or [])
        if not cases:
            return
        coverage = dict(doc.meta.get("memory_coverage") or {})
        events = doc.memory_events + doc.trace_events
        observations = observe_cases(cases, events, coverage)
        doc.memory_cases = [o.to_dict() for o in observations]


# -- convenience one-shots -------------------------------------------------- #

def audit_from_manifest(path: str, *, mode: Optional[Any] = None, timeout: float = 20.0, cwd: Optional[str] = None,
                        use_mcp_scan: bool = False, guard: Optional[IsolationGuard] = None,
                        baseline_path: Optional[str] = None, approvals_path: Optional[str] = None,
                        profile_ref: Optional[str] = None, extra_adapters: Optional[List[AdapterBinding]] = None) -> AuditDocument:
    manifest = load_manifest(path, mode_override=mode)
    if profile_ref:
        manifest.profile_ref = profile_ref
    if extra_adapters:
        manifest.adapters.extend(extra_adapters)
    orch = Orchestrator(manifest)
    return orch.run(timeout=timeout, cwd=cwd, use_mcp_scan=use_mcp_scan, guard=guard, baseline_path=baseline_path,
                    approvals_path=approvals_path)


def audit_from_config(config_path: str, *, mode: Any = RunMode.OFFLINE, live: bool = False,
                      snapshot_path: Optional[str] = None, context_root: Optional[str] = None,
                      use_mcp_scan: bool = False, sandbox: bool = False, baseline_path: Optional[str] = None,
                      timeout: float = 20.0, cwd: Optional[str] = None, profile_ref: Optional[str] = None,
                      extra_adapters: Optional[List[AdapterBinding]] = None, guard: Optional[IsolationGuard] = None,
                      approvals_path: Optional[str] = None) -> AuditDocument:
    """Legacy-compatible entry point: a plain MCP config, optional live handshake."""
    run_mode = coerce_mode(mode)
    if live and run_mode == RunMode.OFFLINE:
        run_mode = RunMode.LIVE_INVENTORY
    manifest = wrap_legacy_config(config_path, mode=run_mode, snapshot=snapshot_path, context_root=context_root,
                                  extra_adapters=extra_adapters, profile_ref=profile_ref)
    if not live:
        manifest.adapter("mcp-config").binding["live"] = False
    orch = Orchestrator(manifest)
    g = guard if guard is not None else (IsolationGuard(sandbox=sandbox) if run_mode == RunMode.CONTROLLED_VALIDATION else None)
    return orch.run(timeout=timeout, cwd=cwd, use_mcp_scan=use_mcp_scan, guard=g, baseline_path=baseline_path,
                    approvals_path=approvals_path)
