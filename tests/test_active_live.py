"""End-to-end controlled validation against the bundled mock stdio MCP server (criteria 3, 4, 5, 12, 22)."""
import json
import os
import pytest

from mcp_audit.adapters import AdapterBinding
from mcp_audit.manifest import wrap_legacy_config
from mcp_audit.orchestrator import Orchestrator
from mcp_audit.discovery import parse_config
from mcp_audit.discovery.introspector import introspect_server
from mcp_audit.active import IsolationGuard
from mcp_audit.models import RunMode, ControlOutcome, ExecutionStatus, ErrorClass, ClaimStatus
from mcp_audit.reporting import emit_json
from mcp_audit.validation import validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
MOCK = os.path.join(HERE, "mock_mcp_server.py")
FIXTURES = os.path.join(HERE, "fixtures", "mcp", "control_fixtures.json")


@pytest.fixture()
def stand(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("MCP_AUDIT_SANDBOX", "1")
    cfg = {"mcpServers": {"filesystem": {"command": "python3", "args": [MOCK], "env": {"MOCK_ROOT": str(root)},
                                         "x_audit": {"kind": "filesystem", "allowed_paths": [str(root) + "/**"]}}}}
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    fx = json.load(open(FIXTURES))
    fx["roots"] = {"filesystem": str(root)}
    fx_path = tmp_path / "fx.json"
    fx_path.write_text(json.dumps(fx))
    return str(cfg_path), str(fx_path), str(root)


def test_live_discovery_records_identity_and_completeness():
    servers = parse_config({"mcpServers": {"filesystem": {"command": "python3", "args": [MOCK]}}})
    introspect_server(servers[0], timeout=15, identity="auditor")
    hs = servers[0].handshake
    assert hs.performed and hs.ok and hs.completeness == "complete" and hs.identity == "auditor"
    assert {t.name for t in servers[0].tools} == {"read_file", "write_file"}
    assert servers[0].inventory_sources["live_advertised"]["count"] == 2


def test_controlled_validation_separates_execution_and_outcome(stand):
    cfg_path, fx_path, root = stand
    m = wrap_legacy_config(cfg_path, mode=RunMode.CONTROLLED_VALIDATION,
                           extra_adapters=[AdapterBinding("fixtures", "control_fixtures", {"path": fx_path}, base_dir=str(root))])
    doc = Orchestrator(m).run(guard=IsolationGuard(sandbox=True), timeout=2)
    by_id = {t.id: t for t in doc.tests}
    assert by_id["FS-WRITE-INSIDE"].control_outcome == ControlOutcome.PASS
    assert by_id["FS-WRITE-INSIDE"].observed_effect["kind"] == "file_exists"
    assert by_id["FS-TRAVERSAL"].control_outcome == ControlOutcome.PASS
    assert by_id["FS-TRAVERSAL"].error_class == ErrorClass.AUTHORIZATION_REFUSAL
    assert by_id["FS-READ-SECRET"].control_outcome == ControlOutcome.PASS
    # criterion 3: a stale schema never becomes PASS
    assert by_id["FS-STALE-SCHEMA"].control_outcome == ControlOutcome.INCONCLUSIVE
    assert by_id["FS-STALE-SCHEMA"].execution_status == ExecutionStatus.SKIPPED
    # criterion 4: unknown tool / timeout are INCONCLUSIVE, never a boundary violation
    assert by_id["FS-UNKNOWN-TOOL"].error_class == ErrorClass.UNKNOWN_TOOL
    assert by_id["FS-TIMEOUT"].execution_status == ExecutionStatus.TIMEOUT
    assert by_id["FS-TIMEOUT"].control_outcome == ControlOutcome.INCONCLUSIVE
    assert not any(f.code == "CONTROL_VIOLATION_OBSERVED" for f in doc.findings)
    # criterion 12: admin-prepared record confirms later stages only
    adm = by_id["FS-ADMIN-PREPARED"]
    assert adm.control_outcome == ControlOutcome.PASS and any("fixture administrator" in l for l in adm.limitations)
    # criterion 5: a successful write of one object is only an observation for that object
    obs = doc.servers[0].effective_access["observed"]["items"]
    assert any(o["case"] == "FS-WRITE-INSIDE" and "one object" in o["note"] for o in obs)
    assert doc.summary["capability_indicators"]["full_project_access"]["present"] is False
    # no tool-wide verified flag; runtime claims carry fixture evidence
    assert not hasattr(doc.servers[0].tools[0], "verified")
    assert any(c.claim_status == ClaimStatus.RUNTIME_SUPPORTED for c in doc.claims)
    assert doc.runtime_validation_performed is True
    assert doc.meta["isolation"]["declared"] is True and "not proof" in doc.meta["isolation"]["declaration"]["note"]
    assert validate_document(json.loads(emit_json(doc))) == []
    eq = [c for c in doc.coverage if c.metric == "execution_quality"][0]
    assert eq.details["timeouts"] == 1 and eq.details["skipped"] >= 2


def test_allowed_operation_refused_is_a_functional_failure(stand, tmp_path):
    """criterion 22: mass blocking is not a quality control."""
    cfg_path, _, root = stand
    fx = {"schema": "control-fixtures", "cases": [
        {"id": "FS-WRITE-ELSEWHERE", "server": "filesystem", "tool": "write_file",
         "arguments": {"path": str(tmp_path / "outside.txt"), "content": "{canary}"}, "expected": "allowed",
         "expected_invariant": "a legitimately allowed write must keep working", "effect_check": {"kind": "file_exists", "path": str(tmp_path / "outside.txt")}}]}
    fx_path = tmp_path / "fx2.json"
    fx_path.write_text(json.dumps(fx))
    m = wrap_legacy_config(cfg_path, mode=RunMode.CONTROLLED_VALIDATION,
                           extra_adapters=[AdapterBinding("fixtures", "control_fixtures", {"path": str(fx_path)}, base_dir=str(tmp_path))])
    doc = Orchestrator(m).run(guard=IsolationGuard(sandbox=True), timeout=2)
    res = {t.id: t for t in doc.tests}["FS-WRITE-ELSEWHERE"]
    assert res.control_outcome == ControlOutcome.FAIL and "mass blocking" in res.details


def test_refused_without_sandbox_declaration_yields_no_tests(stand):
    cfg_path, fx_path, root = stand
    m = wrap_legacy_config(cfg_path, mode=RunMode.CONTROLLED_VALIDATION)
    doc = Orchestrator(m).run(guard=IsolationGuard(sandbox=False), timeout=2)
    assert doc.tests == [] and any("refused" in l for l in doc.limitations)
    assert doc.verdict["assessment_state"] != "complete_for_scope"
