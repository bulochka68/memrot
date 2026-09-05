"""ObSec export (TZ §16.2).

* repeatable and idempotent: the same document yields the same export;
* findings are matched by rule, logical boundary, component and scope
  (the stable ``finding_id``), never by list position; timestamps, run id and
  a changing severity are not part of the identity;
* a new build produces a new *observation instance* (``instance_id``) linked
  to the same root cause;
* the same cause in the definition and security sections is one defect;
* exporter errors are reported independently of the audit result;
* closure / exclusion / risk acceptance carry owner, reason, deadline and scope.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..models import AuditDocument, ControlOutcome

EXPORT_VERSION = "1.0"

# machine codes for the release gate: incompleteness and violation are different codes
GATE_CODES = {
    ("complete_for_scope", "no_violations_observed"): "GATE_OK",
    ("complete_for_scope", "findings_present"): "GATE_BLOCK_FINDINGS",
    ("partial", "findings_present"): "GATE_BLOCK_FINDINGS_PARTIAL",
    ("partial", "no_violations_observed"): "GATE_INCOMPLETE",
    ("partial", "undetermined"): "GATE_INCOMPLETE",
    ("complete_for_scope", "undetermined"): "GATE_INCOMPLETE",
    ("not_assessed", "undetermined"): "GATE_NOT_ASSESSED",
    ("not_assessed", "findings_present"): "GATE_BLOCK_FINDINGS_PARTIAL",
    ("not_assessed", "no_violations_observed"): "GATE_NOT_ASSESSED",
}


def build_obsec_export(doc: AuditDocument, dispositions: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    dispositions = dispositions or {}
    errors: List[str] = []
    v = doc.verdict or {}
    gate = GATE_CODES.get((v.get("assessment_state"), v.get("security_conclusion")), "GATE_NOT_ASSESSED")
    findings = []
    for f in doc.findings:
        disp = dispositions.get(f.finding_id) or {}
        if disp and not all(disp.get(k) for k in ("state", "owner", "reason", "until", "scope")):
            errors.append(f"disposition for {f.finding_id} lacks owner/reason/deadline/scope")
        findings.append({
            "stable_id": f.finding_id, "instance_id": f.instance_id or f"{doc.run_id}:{f.finding_id}",
            "rule_id": f.rule_id, "rule_version": f.rule_version, "code": f.code, "title": f.title,
            "component_refs": f.component_refs, "boundary_refs": f.boundary_refs, "scope": f.scope,
            "verification_status": f.verification_status.value, "severity": f.severity.value if f.severity else None,
            "potential_severity": f.potential_severity.value if f.potential_severity else None,
            "remediation_priority": f.remediation_priority.value if f.remediation_priority else None,
            "claim_refs": f.claim_refs, "evidence_refs": f.evidence_refs, "limitations": f.limitations,
            "closure_criterion": f.closure_criterion, "remediation_state": disp.get("state", f.remediation_state),
            "disposition": disp or None, "build_ref": doc.target.get("build_ref"),
            "sections": sorted({f.plane} | ({"definition"} if f.plane == "definition" else set())),
        })
    controls = [{"rule_id": r.rule_id, "rule_version": r.rule_version, "outcome": r.control_outcome.value,
                 "applicability": r.applicability.value, "execution_status": r.execution_status.value,
                 "finding_refs": r.finding_refs, "missing_sources": r.missing_sources, "run_id": doc.run_id}
                for r in doc.control_results]
    unknown_required = [c["rule_id"] for c in controls if c["outcome"] in ("NOT_EVALUATED", "INCONCLUSIVE")]
    payload = {
        "export_version": EXPORT_VERSION, "schema_version": doc.to_dict()["schema_version"],
        "run": {"run_id": doc.run_id, "target": doc.target, "mode": doc.mode.value, "status": doc.status,
                "started_at": doc.started_at, "finished_at": doc.finished_at,
                "engine_version": doc.meta.get("engine_version"), "ruleset_version": doc.meta.get("ruleset_version")},
        "verdict": {"assessment_state": v.get("assessment_state"), "security_conclusion": v.get("security_conclusion"),
                    "gate_code": gate, "basis": v.get("basis"), "unresolved_controls": unknown_required,
                    "invariant": "an unknown result of a mandatory control never becomes a release allow"},
        "findings": sorted(findings, key=lambda x: x["stable_id"]),
        "controls": sorted(controls, key=lambda x: x["rule_id"]),
        "coverage": [c.to_dict() for c in doc.coverage],
        "exporter": {"status": "error" if errors else "ok", "errors": errors,
                     "note": "exporter status is independent of the audit result"},
    }
    return payload


def emit_obsec(doc: AuditDocument, dispositions: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
    return json.dumps(build_obsec_export(doc, dispositions), indent=2, ensure_ascii=False, sort_keys=False)
