"""Trace adapter: execution events (JSONL) with subject, component, causality and versions.

Minimum event fields (TZ §15.4): ``event_id``, ``run_id``, ``trace_id``,
``parent_event_refs``, ``component``, ``ts``, ``config_version``, ``principal``.
Memory events add ``memory``; tool events add ``tool``; declared data flows add
``flow``; pre-defined behavioural effects add ``observation``.

The adapter records observation quality (missing fields, unlinked events) and
never treats the text of a service response as true without independent
confirmation.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from ..models import AuditDocument, Method, SourceType
from ..evidence import EvidenceStore
from .base import Adapter, AdapterResult
from .registry import register

REQUIRED = ("event_id", "run_id", "trace_id", "component", "ts", "principal")
OPTIONAL = ("parent_event_refs", "config_version")


@register
class TraceAdapter(Adapter):
    kind = "trace"
    adapter_version = "2.0.0"
    supported = ["jsonl_events", "memory_operations", "tool_calls", "declared_flows", "effect_observations",
                 "observation_quality"]
    unsupported = {
        "response_text_truth": "the text of a service response is not treated as true without independent confirmation",
        "prompt_capture": "full prompts / chain-of-thought are not required and not parsed",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        path = self.binding.path("path")
        if not path or not os.path.isfile(path):
            return AdapterResult(self.status("unavailable", [f"trace not found: {path}"]))
        raw = self._read_json(path)
        events: List[Dict[str, Any]] = raw if isinstance(raw, list) else list(raw.get("events") or [])
        header = {} if isinstance(raw, list) else raw
        coverage = dict(self.binding.binding.get("coverage") or header.get("coverage") or {})
        for ev in list(events):
            if "_coverage" in ev:
                coverage.update(ev["_coverage"])
                events.remove(ev)
        with open(path, "rb") as fh:
            dg = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        ids = {e.get("event_id") for e in events}
        missing_fields = 0
        unlinked = 0
        for e in events:
            miss = [f for f in REQUIRED if f not in e]
            if miss:
                missing_fields += 1
                e["_quality"] = {"missing": miss}
            for p in e.get("parent_event_refs") or []:
                if p not in ids:
                    unlinked += 1
                    e.setdefault("_quality", {}).setdefault("unlinked_parents", []).append(p)
        quality = {"events": len(events), "events_missing_required_fields": missing_fields,
                   "unlinked_parent_refs": unlinked, "coverage": coverage,
                   "linkage": "complete" if not unlinked and not missing_fields else "partial"}
        base = store.add(SourceType.RUNTIME_TRACE, Method.OBSERVATION, {"path": os.path.relpath(path)},
                         digest=dg, adapter=self.kind, adapter_version=self.adapter_version,
                         captured_at=header.get("captured_at"),
                         summary=f"trace with {len(events)} event(s); quality {quality['linkage']}",
                         limitations=[] if coverage else ["coverage undeclared: absence of an event is not evidence"])
        count = 1
        for e in events:
            ev = store.add(SourceType.RUNTIME_TRACE, Method.OBSERVATION,
                           {"path": os.path.relpath(path), "event_id": e.get("event_id"), "trace_id": e.get("trace_id")},
                           adapter=self.kind, adapter_version=self.adapter_version,
                           captured_at=e.get("ts") if isinstance(e.get("ts"), (int, float)) else None,
                           summary=f"event {e.get('event_id')} @ {e.get('component')}",
                           scope={"principal": e.get("principal"), "config_version": e.get("config_version"),
                                  "run_id": e.get("run_id")})
            e["_evidence_id"] = ev.evidence_id
            count += 1
        doc.trace_events.extend(events)
        doc.meta["trace_quality"] = quality
        doc.meta.setdefault("memory_coverage", {}).update(coverage)
        state = "available" if coverage and quality["linkage"] == "complete" else "partial"
        reasons = []
        if not coverage:
            reasons.append("coverage undeclared")
        if quality["linkage"] != "complete":
            reasons.append("events with missing fields or unlinked parents; correlation keeps uncertainty")
        return AdapterResult(self.status(state, reasons, captured_at=header.get("captured_at"), evidence_count=count),
                             facts={"trace_evidence": base.evidence_id})
