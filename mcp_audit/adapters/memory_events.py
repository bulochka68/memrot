"""Memory event snapshot adapter: normalized memory records and lifecycle events.

Input (JSON):
    {"schema": "memory-events", "store_ref": "...", "captured_at": ..., "field_map": {...},
     "coverage": {"write": true, "retrieve": true, "context_include": false, "behavior": false},
     "records": [...raw records...], "events": [...events per TZ §15.4...]}

Unknown values stay unknown; a missing owner is never replaced by the current
user; ``trusted``/``verified`` flags inside content are kept apart as
``self_asserted`` (TZ §8.3).  Redis / MongoDB / vector stores are not assumed
to isolate users by themselves.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from ..models import AuditDocument, Method, SourceType
from ..evidence import EvidenceStore
from ..memory import normalize_record
from .base import Adapter, AdapterResult
from .registry import register

MEMORY_SCHEMA = "memory-events"


@register
class MemoryEventsAdapter(Adapter):
    kind = "memory_event_snapshot"
    adapter_version = "2.0.0"
    supported = ["normalized_records(memory_snapshot)", "write/retrieve/context_include/revoke/delete events(runtime_trace)",
                 "coverage_declaration", "self_asserted_metadata_separation"]
    unsupported = {
        "store_isolation_assumption": "the backing store is not assumed to isolate tenants or users",
        "live_store_query": "stores are not queried; provide an exported snapshot",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        path = self.binding.path("path")
        if not path or not os.path.isfile(path):
            return AdapterResult(self.status("unavailable", [f"memory snapshot not found: {path}"]))
        data = self._read_json(path)
        if isinstance(data, list):
            data = {"events": data}
        if data.get("schema") not in (None, MEMORY_SCHEMA):
            return AdapterResult(self.status("unavailable", [f"{path}: not a {MEMORY_SCHEMA} document"]))
        with open(path, "rb") as fh:
            dg = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        field_map = dict(self.binding.binding.get("field_map") or data.get("field_map") or
                         (doc.profile.get("memory_field_map") or {}))
        store_ref = data.get("store_ref") or self.binding.binding.get("store_ref")
        records = [normalize_record(r, store_ref=store_ref, field_map=field_map) for r in data.get("records") or []]
        events = list(data.get("events") or [])
        coverage = dict(data.get("coverage") or self.binding.binding.get("coverage") or {})
        base_ev = store.add(SourceType.MEMORY_SNAPSHOT, Method.OBSERVATION,
                            {"path": os.path.relpath(path), "store_ref": store_ref},
                            digest=dg, adapter=self.kind, adapter_version=self.adapter_version,
                            captured_at=data.get("captured_at"),
                            summary=f"{len(records)} memory record(s), {len(events)} event(s); coverage {coverage or 'undeclared'}",
                            limitations=([] if coverage else ["event coverage undeclared: absence of an event is not evidence"]))
        count = 1
        for ev in events:
            eid = ev.get("event_id")
            e = store.add(SourceType.RUNTIME_TRACE, Method.OBSERVATION,
                          {"path": os.path.relpath(path), "event_id": eid, "kind": "memory_event"},
                          digest=None, adapter=self.kind, adapter_version=self.adapter_version,
                          captured_at=ev.get("ts") if isinstance(ev.get("ts"), (int, float)) else data.get("captured_at"),
                          summary=f"memory event {eid}: {(ev.get('memory') or {}).get('operation')}")
            ev["_evidence_id"] = e.evidence_id
            count += 1
        for r in records:
            r["_evidence_id"] = base_ev.evidence_id
        doc.memory_records.extend(records)
        doc.memory_events.extend(events)
        doc.meta.setdefault("memory_coverage", {}).update(coverage)
        reasons: List[str] = []
        if not coverage:
            reasons.append("coverage undeclared; W/R/C/B stages will be 'unknown' where events are absent")
        unknown_owner = sum(1 for r in records if r.get("subject_ref") is None and r.get("read_audience_ref") is None)
        if unknown_owner:
            reasons.append(f"{unknown_owner} record(s) without owner/audience metadata kept as unknown (not defaulted)")
        return AdapterResult(self.status("available" if coverage else "partial", reasons,
                                         captured_at=data.get("captured_at"), evidence_count=count))
