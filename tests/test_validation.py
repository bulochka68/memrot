import json
from mcp_audit.orchestrator import audit_from_config
from mcp_audit.reporting import emit_json
from mcp_audit.validation import validate_document
import os

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "mcp_config.example.json")


def _doc():
    return json.loads(emit_json(audit_from_config(EXAMPLE)))


def test_dangling_references_are_errors():
    d = _doc()
    d["claims"][0]["evidence_refs"] = ["E-doesnotexist"]
    assert any("unknown evidence" in e for e in validate_document(d))
    d = _doc()
    d["verdict"]["basis"] = ["CL-nope"]
    assert any("verdict.basis" in e for e in validate_document(d))


def test_runtime_status_requires_runtime_evidence():
    d = _doc()
    d["claims"][0]["claim_status"] = "runtime_supported"
    errs = validate_document(d)
    assert any("runtime_supported without runtime evidence" in e for e in errs)


def test_complete_state_with_unresolved_controls_is_invalid():
    d = _doc()
    d["verdict"]["assessment_state"] = "complete_for_scope"
    assert any("unresolved controls" in e for e in validate_document(d))


def test_build_mismatch_is_an_error():
    d = _doc()
    d["target"]["build_ref"] = "b1"
    d["evidence"][0]["scope"]["build_ref"] = "b2"
    assert any("belongs to build" in e for e in validate_document(d))
