"""Validation of an ``agent-security-audit`` v2.0 JSON document.

Two layers:
  * structural - required keys, enum values (a JSON Schema is published in
    ``schemas/agent-security-audit-2.0.schema.json``; if ``jsonschema`` is
    installed it is applied, otherwise a stdlib subset check runs);
  * semantic   - referential integrity (claims -> evidence, findings -> claims/evidence,
    verdict.basis -> claims, control results -> rules), runtime status without
    runtime evidence, build consistency, duplicate ids, assessment-state consistency.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "schemas", "agent-security-audit-2.0.schema.json")

_ENUMS = {
    "claim_status": {"hypothesis", "static_supported", "runtime_supported", "contradicted", "inconclusive"},
    "control_outcome": {"PASS", "FAIL", "INCONCLUSIVE", "NOT_EVALUATED", "NOT_APPLICABLE"},
    "execution_status": {"completed", "error", "timeout", "skipped"},
    "applicability": {"applicable", "not_applicable", "unknown"},
    "assessment_state": {"complete_for_scope", "partial", "not_assessed"},
    "security_conclusion": {"findings_present", "no_violations_observed", "undetermined"},
    "source_type": {"config", "definition", "source_code", "policy_snapshot", "deployment_snapshot", "memory_snapshot",
                    "runtime_trace", "fixture_observation", "baseline", "imported"},
    "stage": {"observed", "not_observed", "unknown", "not_evaluated"},
}
RUNTIME_SOURCES = {"runtime_trace", "fixture_observation"}
TOP_REQUIRED = ("schema", "schema_version", "meta", "target", "adapters", "plan", "inventory", "components", "principals",
                "capabilities", "memory_stores", "boundaries", "edges", "definition_analysis", "evidence", "claims",
                "control_results", "findings", "tests", "memory_cases", "coverage", "trifecta", "summary", "verdict",
                "downstream", "drift", "import_history", "limitations")


class ValidationError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors[:10]) + (f" (+{len(errors) - 10} more)" if len(errors) > 10 else ""))
        self.errors = errors


def _structural(doc: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for k in TOP_REQUIRED:
        if k not in doc:
            errors.append(f"missing top-level key {k!r}")
    if doc.get("schema") != "agent-security-audit":
        errors.append(f"schema must be 'agent-security-audit', got {doc.get('schema')!r}")
    if str(doc.get("schema_version")) != "2.0":
        errors.append(f"schema_version must be '2.0', got {doc.get('schema_version')!r}")
    try:
        import jsonschema  # type: ignore
        with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
        v = jsonschema.Draft202012Validator(schema)
        for e in sorted(v.iter_errors(doc), key=lambda e: list(e.path)):
            errors.append("schema: " + "/".join(str(p) for p in e.path) + ": " + e.message[:160])
    except ImportError:
        for c in doc.get("claims") or []:
            if c.get("claim_status") not in _ENUMS["claim_status"]:
                errors.append(f"claim {c.get('claim_id')}: bad claim_status {c.get('claim_status')!r}")
        for r in doc.get("control_results") or []:
            if r.get("control_outcome") not in _ENUMS["control_outcome"]:
                errors.append(f"control {r.get('rule_id')}: bad control_outcome")
            if r.get("execution_status") not in _ENUMS["execution_status"]:
                errors.append(f"control {r.get('rule_id')}: bad execution_status")
            if r.get("applicability") not in _ENUMS["applicability"]:
                errors.append(f"control {r.get('rule_id')}: bad applicability")
        for e in doc.get("evidence") or []:
            if e.get("source_type") not in _ENUMS["source_type"]:
                errors.append(f"evidence {e.get('evidence_id')}: bad source_type")
        v = doc.get("verdict") or {}
        if v.get("assessment_state") not in _ENUMS["assessment_state"]:
            errors.append("verdict.assessment_state invalid")
        if v.get("security_conclusion") not in _ENUMS["security_conclusion"]:
            errors.append("verdict.security_conclusion invalid")
    return errors


def _semantic(doc: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    ev_ids = [e.get("evidence_id") for e in doc.get("evidence") or []]
    ev_set = set(ev_ids)
    if len(ev_ids) != len(ev_set):
        errors.append("duplicate evidence ids")
    ev_by = {e["evidence_id"]: e for e in doc.get("evidence") or []}
    claim_ids = [c.get("claim_id") for c in doc.get("claims") or []]
    claim_set = set(claim_ids)
    if len(claim_ids) != len(claim_set):
        errors.append("duplicate claim ids")
    f_ids = [f.get("finding_id") for f in doc.get("findings") or []]
    if len(f_ids) != len(set(f_ids)):
        errors.append("duplicate finding ids (one defect must be one stable finding)")
    build = (doc.get("target") or {}).get("build_ref")
    compatible = set((doc.get("meta") or {}).get("compatible_builds") or [])
    for c in doc.get("claims") or []:
        for r in c.get("evidence_refs") or []:
            if r not in ev_set:
                errors.append(f"claim {c.get('claim_id')} references unknown evidence {r}")
        if c.get("claim_status") == "runtime_supported":
            if not any(ev_by.get(r, {}).get("source_type") in RUNTIME_SOURCES for r in c.get("evidence_refs") or []):
                errors.append(f"claim {c.get('claim_id')}: runtime_supported without runtime evidence")
        if c.get("claim_status") in ("static_supported", "runtime_supported") and not c.get("evidence_refs"):
            errors.append(f"claim {c.get('claim_id')}: supported status without evidence")
    for f in doc.get("findings") or []:
        for r in f.get("claim_refs") or []:
            if r not in claim_set:
                errors.append(f"finding {f.get('finding_id')} references unknown claim {r}")
        for r in f.get("evidence_refs") or []:
            if r not in ev_set:
                errors.append(f"finding {f.get('finding_id')} references unknown evidence {r}")
        if f.get("verification_status") in ("static_supported", "runtime_supported") and not (f.get("claim_refs") or f.get("evidence_refs")):
            errors.append(f"finding {f.get('finding_id')}: supported status without claims/evidence")
        if f.get("verification_status") == "runtime_supported":
            refs = f.get("evidence_refs") or []
            if not any(ev_by.get(r, {}).get("source_type") in RUNTIME_SOURCES for r in refs):
                errors.append(f"finding {f.get('finding_id')}: runtime_supported without runtime evidence")
        for st in (f.get("memory_stages") or {}).values():
            if st not in _ENUMS["stage"]:
                errors.append(f"finding {f.get('finding_id')}: bad memory stage value {st!r}")
    for r in doc.get("control_results") or []:
        for cr in r.get("claim_refs") or []:
            if cr not in claim_set:
                errors.append(f"control {r.get('rule_id')} references unknown claim {cr}")
        if r.get("control_outcome") in ("PASS", "FAIL") and r.get("execution_status") != "completed":
            errors.append(f"control {r.get('rule_id')}: PASS/FAIL requires execution_status=completed")
        if r.get("control_outcome") == "NOT_APPLICABLE" and r.get("applicability") == "applicable":
            errors.append(f"control {r.get('rule_id')}: NOT_APPLICABLE with applicability=applicable")
    v = doc.get("verdict") or {}
    for b in v.get("basis") or []:
        if b not in claim_set:
            errors.append(f"verdict.basis references unknown claim {b}")
    if v.get("assessment_state") == "complete_for_scope":
        bad = [r.get("rule_id") for r in doc.get("control_results") or [] if r.get("control_outcome") in ("NOT_EVALUATED", "INCONCLUSIVE")]
        if bad:
            errors.append(f"assessment_state=complete_for_scope with unresolved controls {bad}")
    if v.get("security_conclusion") == "findings_present" and not v.get("confirmed_finding_refs"):
        errors.append("findings_present without confirmed findings")
    if v.get("security_conclusion") == "no_violations_observed" and v.get("confirmed_finding_refs"):
        errors.append("no_violations_observed while confirmed findings exist")
    if (doc.get("meta") or {}).get("runtime_validation_performed") is False:
        if any(c.get("claim_status") == "runtime_supported" for c in doc.get("claims") or []):
            errors.append("runtime_validation_performed=false but runtime_supported claims exist")
    for e in doc.get("evidence") or []:
        eb = (e.get("scope") or {}).get("build_ref")
        if build and eb and eb != build and eb not in compatible:
            errors.append(f"evidence {e.get('evidence_id')} belongs to build {eb}, report build is {build}")
    return errors


def validate_document(doc: Dict[str, Any], *, semantic: bool = True) -> List[str]:
    errors = _structural(doc)
    if semantic:
        errors += _semantic(doc)
    return errors
