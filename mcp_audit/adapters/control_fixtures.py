"""Control fixtures adapter: registered control cases for controlled validation.

A fixture declares, for an isolated synthetic environment, which tool is
called with which arguments, what the *expected invariant* is, how the effect
is observed and which rule / boundary the case evaluates.  There is no
universal probing by guessing tool names (TZ §14, §19).
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from ..models import AuditDocument, Method, SourceType
from ..evidence import EvidenceStore
from .base import Adapter, AdapterResult
from .registry import register

FIXTURE_SCHEMA = "control-fixtures"
REQUIRED = ("id", "server", "tool", "arguments", "expected")


@register
class ControlFixturesAdapter(Adapter):
    kind = "control_fixtures"
    adapter_version = "2.0.0"
    supported = ["registered_cases", "effect_checks(file_exists,file_absent,response_contains,none)",
                 "isolation_declaration", "memory_cases"]
    unsupported = {
        "tool_name_guessing": "cases are only run for tools with an agreed schema",
        "remote_isolation_guarantee": "isolation of a remote target must be declared by its own fixture evidence",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        path = self.binding.path("path")
        if not path or not os.path.isfile(path):
            return AdapterResult(self.status("unavailable", [f"fixtures not found: {path}"]))
        data = self._read_json(path)
        if data.get("schema") not in (None, FIXTURE_SCHEMA):
            return AdapterResult(self.status("unavailable", [f"{path}: not a {FIXTURE_SCHEMA} document"]))
        with open(path, "rb") as fh:
            dg = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        cases: List[Dict[str, Any]] = []
        bad: List[str] = []
        for c in data.get("cases") or []:
            missing = [f for f in REQUIRED if f not in c]
            if missing:
                bad.append(f"{c.get('id', '?')}: missing {missing}")
                continue
            cases.append(c)
        ev = store.add(SourceType.CONFIG, Method.PARSING, {"path": os.path.relpath(path), "kind": "control_fixtures"},
                       digest=dg, adapter=self.kind, adapter_version=self.adapter_version,
                       summary=f"{len(cases)} registered control case(s)")
        doc.meta["control_fixtures"] = {"cases": cases, "isolation": data.get("isolation") or {},
                                        "memory_cases": data.get("memory_cases") or [], "evidence_ref": ev.evidence_id,
                                        "path": os.path.relpath(path)}
        return AdapterResult(self.status("partial" if bad else "available", bad, evidence_count=1))
