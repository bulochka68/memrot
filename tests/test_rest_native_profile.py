"""Second topology without MCP and with a different memory family (criteria 9, 18)."""
import json
import os
from mcp_audit.adapters import AdapterBinding
from mcp_audit.manifest import Manifest
from mcp_audit.models import RunMode, AccessProfile, ControlOutcome
from mcp_audit.orchestrator import Orchestrator
from mcp_audit.reporting import emit_json
from mcp_audit.validation import validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "fixtures", "rest_native_agent")


def _run():
    m = Manifest(target={"id": "rest-native-agent", "build_ref": "fixture-1", "environment": "fixture"},
                 access_profile=AccessProfile.WHITE_BOX, mode=RunMode.OFFLINE, profile_ref="rest_native_agent",
                 adapters=[AdapterBinding("source", "source_snapshot", {"root": os.path.join(BASE, "src")}, base_dir=BASE),
                           AdapterBinding("policy", "policy_snapshot", {"path": os.path.join(BASE, "policy.json")}, base_dir=BASE)],
                 base_dir=BASE)
    return Orchestrator(m).run()


def test_same_rules_work_without_mcp():
    doc = _run()
    outcomes = {r.rule_id: r.control_outcome for r in doc.control_results}
    assert outcomes["MEM-01"] == ControlOutcome.PASS
    assert outcomes["MEM-02"] == ControlOutcome.PASS      # publisher separated with approval
    assert outcomes["MEM-03"] == ControlOutcome.PASS
    assert outcomes["MEM-04"] == ControlOutcome.PASS
    assert outcomes["AUTH-01"] == ControlOutcome.PASS
    assert outcomes["AUTH-02"] == ControlOutcome.PASS
    assert outcomes["AUTH-04"] == ControlOutcome.PASS
    assert outcomes["EGRESS-01"] == ControlOutcome.FAIL
    f = [x for x in doc.findings if x.rule_id == "EGRESS-01"][0]
    assert f.finding_id.startswith("F-") and f.closure_criterion and f.claim_refs
    assert validate_document(json.loads(emit_json(doc))) == []


def test_native_tools_are_inventory_without_a_handshake():
    doc = _run()
    s = doc.server("native-tools")
    assert s is not None and s.is_mcp is False and s.handshake.performed is False and s.handshake.source == "source"
    assert {t.name for t in s.tools} == {"search_docs", "send_summary"}
    tool = {t.name: t for t in s.tools}["send_summary"]
    assert tool.egress and "TRANSMIT" in tool.operations
    assert tool.classification_basis == "source_inference"
    assert {t.name: t.egress for t in s.tools}["search_docs"] is False
    assert doc.control_result("TOOL-05").control_outcome in (ControlOutcome.PASS, ControlOutcome.INCONCLUSIVE)
