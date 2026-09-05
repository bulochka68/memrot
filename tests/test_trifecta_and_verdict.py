"""Verdict semantics on config-only input (acceptance criteria 1, 5, 6)."""
import json
import os
from mcp_audit.orchestrator import audit_from_config
from mcp_audit.models import ClaimStatus, PathState
from mcp_audit.reporting import emit_json
from mcp_audit.validation import validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(os.path.dirname(HERE), "examples", "mcp_config.example.json")
POISONED = os.path.join(HERE, "fixtures", "poisoned_config.json")


def test_config_only_audit_is_partial_and_has_no_runtime_claims():
    doc = audit_from_config(EXAMPLE)
    assert doc.tests == []
    assert doc.runtime_validation_performed is False
    assert not any(c.claim_status == ClaimStatus.RUNTIME_SUPPORTED for c in doc.claims)
    assert doc.verdict["assessment_state"] == "partial"
    assert doc.verdict["security_conclusion"] == "undetermined"
    assert doc.verdict["unresolved_controls"]
    assert "confidence" in doc.verdict and isinstance(doc.verdict["confidence"]["level"], str)
    assert not isinstance(doc.verdict["confidence"], float)
    assert doc.verdict["basis"] == sorted(doc.verdict["basis"])
    assert all(doc.claim(b) for b in doc.verdict["basis"])
    assert validate_document(json.loads(emit_json(doc))) == []


def test_trifecta_is_an_indicator_not_a_leak():
    doc = audit_from_config(EXAMPLE)
    tri = doc.trifecta
    assert tri["capability_combination"] is True
    assert tri["state"] == PathState.CAPABILITY_COMBINATION.value
    assert "not an observed leak" in tri["limitations"][0]
    assert not any(f.code == "LETHAL_TRIFECTA" for f in doc.findings)


def test_capability_indicators_are_claims_not_findings():
    doc = audit_from_config(EXAMPLE)
    ind = doc.summary["capability_indicators"]
    assert ind["arbitrary_code_execution"]["present"] is True
    assert doc.claim(ind["arbitrary_code_execution"]["claim_ref"]) is not None
    assert not any(f.code in ("ARBITRARY_CODE_EXECUTION", "PROJECT_WRITE_ACCESS", "DESTRUCTIVE_OPERATIONS") for f in doc.findings)


def test_single_write_tool_does_not_imply_full_project_access(write_json):
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w/p"],
                                 "x_audit": {"kind": "filesystem", "allowed_paths": ["/w/p/**"]},
                                 "tools": [{"name": "write_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}]}}}
    doc = audit_from_config(write_json("c.json", cfg))
    ind = doc.summary["capability_indicators"]
    assert ind["write_access"]["present"] is True
    assert ind["full_project_access"]["present"] is False
    assert "single allowed write" in ind["full_project_access"]["note"] or "one object" in ind["full_project_access"]["note"]


def test_poisoned_config_yields_hypotheses_only():
    doc = audit_from_config(POISONED)
    codes = {f.code for f in doc.findings}
    assert {"HIDDEN_INSTRUCTION_MARKER", "CONCEALMENT", "TOOL_NAME_COLLISION"} <= codes
    assert all(f.verification_status != ClaimStatus.RUNTIME_SUPPORTED for f in doc.findings)
    assert doc.verdict["security_conclusion"] == "undetermined"    # signals are not confirmed violations
    tool05 = doc.control_result("TOOL-05")
    assert tool05.control_outcome.value == "INCONCLUSIVE"


def test_collision_with_qualified_router_is_signal_only(write_json):
    cfg = {"mcpServers": {"a": {"command": "c", "tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]},
                          "b": {"command": "c", "tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}}}
    profile = write_json("p.json", {"profile_id": "p", "tool_routing": {"namespace": "qualified"}})
    doc = audit_from_config(write_json("c.json", cfg), profile_ref=profile)
    assert doc.control_result("TOOL-03").control_outcome.value == "PASS"
    assert not any(f.code == "AMBIGUOUS_TOOL_RESOLUTION" for f in doc.findings)
    flat = write_json("p2.json", {"profile_id": "p", "tool_routing": {"namespace": "flat"}})
    doc2 = audit_from_config(write_json("c2.json", cfg), profile_ref=flat)
    assert doc2.control_result("TOOL-03").control_outcome.value == "FAIL"
    f = [x for x in doc2.findings if x.code == "AMBIGUOUS_TOOL_RESOLUTION"][0]
    assert "substitution is not declared" in " ".join(f.limitations)


def test_declared_divergence_readonly_lie(write_json):
    cfg = {"mcpServers": {"x": {"command": "c", "tools": [
        {"name": "delete_thing", "description": "d", "annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"}}]}}}
    doc = audit_from_config(write_json("c.json", cfg))
    assert any(d.get("declared") == "readOnlyHint=true" for d in doc.verdict["declared_divergences"])
