"""Reader for ``audit`` v1.0 / v1.1 documents.

Migration rules (TZ §18):
 1. the old document is validated against *its* version; unknown versions are not guessed;
 2. original values and import details are kept in ``import_history`` without new evidence;
 3. ``declared`` -> a source statement; ``effective`` -> a conclusion that still needs policy or observation;
 4. old ``verified=true`` becomes runtime-supported only with a matching valid test result;
 5. old PASS is read with its expected effect; without data the new outcome is INCONCLUSIVE;
 6. ``tests=[]`` means no checks were executed - not a list of passed checks;
 7. a handshake is never restored as performed from ``source=config`` + ``ok=true``;
 8. ``full_project_access`` / ``arbitrary_code_execution`` / ``rug_pull`` are recomputed by the new
    definitions; the old interpretation stays in the import history;
 9. comparison with an old baseline is marked limited.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .. import LEGACY_SCHEMA_VERSIONS
from ..models import (AccessProfile, AuditDocument, ClaimStatus, Confidence, ControlCaseResult, ControlOutcome,
                      ErrorClass, ExecutionStatus, Handshake, KnowledgeState, Method, RunMode, ServerRecord,
                      SourceType, ToolDefinition, ToolRecord, Applicability)
from ..evidence import EvidenceStore

LEGACY_VERSIONS = LEGACY_SCHEMA_VERSIONS


def _validate_legacy(data: Dict[str, Any]) -> str:
    if data.get("schema") != "audit":
        raise ValueError("not a legacy 'audit' document")
    version = str(data.get("version") or "")
    if version not in LEGACY_VERSIONS:
        raise ValueError(f"unknown legacy audit version {version!r}; supported: {LEGACY_VERSIONS}; versions are not guessed")
    for key in ("servers", "summary", "verdict"):
        if key not in data:
            raise ValueError(f"legacy v{version} document lacks required key {key!r}")
    if version == "1.1" and "definition_analysis" not in data:
        raise ValueError("legacy v1.1 document lacks 'definition_analysis'")
    return version


def import_legacy_dict(data: Dict[str, Any], *, source_path: Optional[str] = None) -> AuditDocument:
    version = _validate_legacy(data)
    mode = {"passive": RunMode.OFFLINE, "active": RunMode.CONTROLLED_VALIDATION, "drift": RunMode.BASELINE_COMPARISON}.get(
        data.get("mode", "passive"), RunMode.OFFLINE)
    doc = AuditDocument(mode=mode, access_profile=AccessProfile.GREY_BOX, run_id=f"import-{int(time.time())}",
                        target={"id": (data.get("meta") or {}).get("target") or "imported-legacy", "build_ref": None,
                                "environment": "unknown", "note": "imported from a legacy audit; identity not declared in v1"})
    store = EvidenceStore(doc)
    src_ev = store.add(SourceType.IMPORTED, Method.IMPORT, {"path": source_path or "<memory>", "legacy_version": version},
                       summary=f"legacy audit v{version} imported", limitations=["imported values carry no new evidence"])
    history: Dict[str, Any] = {"legacy_version": version, "imported_at": time.time(), "source_evidence": src_ev.evidence_id,
                               "original": {"mode": data.get("mode"), "verdict": data.get("verdict"), "summary": data.get("summary"),
                                            "tests_count": len(data.get("tests") or [])},
                               "interpretation": {}, "limitations": []}
    tests = data.get("tests") or []
    valid_tests: Dict[str, Dict[str, Any]] = {}
    for t in tests:
        if t.get("result") in ("PASS", "BLOCKED") and t.get("tool"):
            valid_tests.setdefault(f"{t.get('server')}/{t['tool']}", t)
    if not tests:
        history["interpretation"]["tests"] = "tests=[] means no checks were executed in this artifact; it is not a list of passed checks"
        history["limitations"].append("no runtime checks in the legacy artifact")

    for s in data.get("servers") or []:
        hs_old = s.get("handshake") or {}
        rec = ServerRecord(name=s["name"], transport=s.get("transport", "stdio"), command=s.get("command"),
                           args=list(s.get("args") or []), url=s.get("url"), kind=s.get("kind", "generic"),
                           declared_capabilities=dict(s.get("declared_capabilities") or {}),
                           is_mcp=s.get("command") != "internal", component_id=f"server:{s['name']}")
        source = hs_old.get("source", "none")
        performed = source == "live" and bool(hs_old.get("ok"))
        rec.handshake = Handshake(performed=performed, ok=(hs_old.get("ok") if performed else None), source=source,
                                  instructions=hs_old.get("instructions"), server_info=hs_old.get("server_info") or {},
                                  completeness="unknown",
                                  notes=[] if performed else [f"legacy handshake source={source}, ok={hs_old.get('ok')}: not restored as a performed handshake"])
        rec.inventory_sources[{"config": "configured", "snapshot": "snapshot", "live": "live_advertised"}.get(source, "configured")] = {
            "count": len(s.get("tools") or []), "origin": f"legacy audit v{version}", "definitions": [
                {"name": t["name"], "description": t.get("description", ""), "inputSchema": t.get("input_schema") or {},
                 "annotations": t.get("annotations") or {}} for t in s.get("tools") or []]}
        rec.field_sources = {"all": f"legacy audit v{version}"}
        legacy_access = s.get("effective_access") or {}
        rec.effective_access = {"kind": rec.kind, "policy_expected": {"basis": "legacy 'effective' block re-read as expectation", **{k: v for k, v in legacy_access.items() if k not in ("kind", "provenance")}},
                                "inferred": {"basis": "legacy", "knowledge_state": "assumed"}, "observed": {"basis": "legacy tests", "items": []},
                                "enforcement": "unknown", "note": "legacy 'effective' access is a conclusion that needs policy or observation"}
        for t in s.get("tools") or []:
            tr = ToolRecord(server=rec.name, definition=ToolDefinition.from_mcp(
                {"name": t["name"], "description": t.get("description", ""), "inputSchema": t.get("input_schema") or {},
                 "annotations": t.get("annotations") or {}, "title": t.get("title")}))
            tr.classification_basis = "definition"
            tr.knowledge_state = KnowledgeState.ASSUMED
            tr.provenance = {"legacy_provenance": json.dumps(t.get("provenance") or {}), "legacy_verified": str(t.get("verified"))}
            if t.get("verified") is True:
                key = f"{rec.name}/{t['name']}"
                if key in valid_tests:
                    tr.provenance["verified_import"] = "runtime-supported by a matching legacy test result"
                else:
                    tr.provenance["verified_import"] = "legacy verified=true without a matching valid test: NOT promoted"
                    history["limitations"].append(f"{key}: verified=true had no matching test; kept as history only")
            rec.tools.append(tr)
        doc.servers.append(rec)

    for t in tests:
        exp = t.get("expected")
        res = t.get("result")
        if res in ("FAIL", "SKIPPED") or exp is None:
            outcome, status = ControlOutcome.INCONCLUSIVE, ExecutionStatus.ERROR if res == "FAIL" else ExecutionStatus.SKIPPED
            note = "legacy result without an interpretable expected effect -> INCONCLUSIVE"
        elif res == exp == "PASS":
            outcome, status, note = ControlOutcome.INCONCLUSIVE, ExecutionStatus.COMPLETED, "legacy PASS: effect not independently observed in v1; kept INCONCLUSIVE"
        elif res == exp == "BLOCKED":
            outcome, status, note = ControlOutcome.PASS, ExecutionStatus.COMPLETED, "legacy BLOCKED as expected: refusal observed (object-level semantics unknown)"
        else:
            outcome, status, note = ControlOutcome.INCONCLUSIVE, ExecutionStatus.COMPLETED, "legacy mismatch of result/expected: not promoted to a violation without an observed effect"
        doc.tests.append(ControlCaseResult(id=t.get("id", "legacy"), name=t.get("name", ""), server=t.get("server", ""), tool=t.get("tool"),
                                           rule_id="", expected="denied" if exp == "BLOCKED" else "allowed", execution_status=status,
                                           control_outcome=outcome, applicability=Applicability.UNKNOWN,
                                           error_class=ErrorClass.NONE, details=note,
                                           limitations=["imported legacy probe; semantics limited"], arguments=(t.get("evidence") or {}).get("arguments") or {}))
    legacy_verdict = data.get("verdict") or {}
    history["interpretation"].update({
        "declared": "declared facts are source statements",
        "effective": "effective facts are conclusions requiring policy or observation",
        "full_project_access": f"legacy value {legacy_verdict.get('full_project_access')} kept in history; recomputed from inferred filesystem scope only",
        "arbitrary_code_execution": f"legacy value {legacy_verdict.get('arbitrary_code_execution')} kept in history; recomputed from classification",
        "confidence": f"legacy numeric confidence {legacy_verdict.get('confidence')} dropped: it was not a calibrated probability",
        "basis": f"legacy basis {legacy_verdict.get('basis')!r} dropped: v2 basis is a list of claim ids",
    })
    if data.get("drift"):
        history["interpretation"]["rug_pull"] = f"legacy rug_pull={data['drift'].get('rug_pull')} kept in history; v2 records definition_changed with approval state"
    doc.import_history = history
    doc.limitations.append(f"imported from legacy audit v{version}: statuses were not upgraded; see import_history")
    doc.meta["import"] = {"legacy_version": version, "path": source_path}
    return doc


def load_legacy_audit(path: str) -> AuditDocument:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return import_legacy_dict(data, source_path=path)
