"""Stand example (offline, snapshots only): criteria 1, 2, 3, 7, 9, 13, 16."""
import json
from collections import Counter
from mcp_audit.models import ClaimStatus, ControlOutcome, StageObservation
from mcp_audit.reporting import emit_json, emit_markdown, build_obsec_export
from mcp_audit.validation import validate_document


def _res(doc, rid):
    return doc.control_result(rid)


def test_stand_report_is_partial_with_findings_and_validates(stand_doc):
    doc = stand_doc
    assert doc.verdict["assessment_state"] == "partial"
    assert doc.verdict["security_conclusion"] == "findings_present"
    assert doc.runtime_validation_performed is False
    assert not any(c.claim_status == ClaimStatus.RUNTIME_SUPPORTED for c in doc.claims)
    assert validate_document(json.loads(emit_json(doc))) == []
    assert all(a.status == "available" for a in doc.adapters)


def test_inventory_mismatch_9_vs_14_is_separate_and_not_fabricated(stand_doc):
    doc = stand_doc
    mism = [r for r in doc.inventory_reconciliation if r["kind"] == "inventory_mismatch" and r["pair"] == "configured/source_defined"]
    assert mism and len(mism[0]["only_in_b"]) == 5 and mism[0]["common"] == 9
    assert "not a percentage of verified security" in mism[0]["ratio_note"]
    f = [x for x in doc.findings if x.code == "INVENTORY_MISMATCH"]
    assert f and f[0].verification_status == ClaimStatus.HYPOTHESIS
    assert _res(doc, "INV-01").control_outcome == ControlOutcome.INCONCLUSIVE
    # the five missing declarations have no fabricated results
    names = {t.name for t in doc.server("mcp-invest").tools}
    assert "bond_get_info" not in names
    assert not any("bond_get_info" in (f.tool or "") for f in doc.findings if f.rule_id != "INV-01")


def test_native_search_contract_mismatch_query_vs_queries(stand_doc):
    doc = stand_doc
    cm = [r for r in doc.inventory_reconciliation if r["kind"] == "contract_mismatch"]
    assert [r["tool"] for r in cm] == ["agent-native/duckduckgo_search"]
    assert {d["parameter"] for d in cm[0]["differences"]} == {"query", "queries"}
    assert _res(doc, "TOOL-02").control_outcome == ControlOutcome.FAIL
    f = [x for x in doc.findings if x.code == "CONTRACT_MISMATCH"]
    assert len(f) == 1 and f[0].verification_status == ClaimStatus.STATIC_SUPPORTED
    assert "stale schema" in f[0].potential_effect


def test_memory_publication_defect_is_a_standalone_finding(stand_doc):
    doc = stand_doc
    r = _res(doc, "MEM-02")
    assert r.control_outcome == ControlOutcome.FAIL
    f = [x for x in doc.findings if x.rule_id == "MEM-02"]
    assert len(f) == 1
    f = f[0]
    assert f.verification_status == ClaimStatus.STATIC_SUPPORTED and f.severity.value == "CRITICAL"
    assert f.memory_stages == {s: StageObservation.NOT_EVALUATED for s in ("W", "R", "C", "B")}
    assert f.remediation_priority.value == "P0"
    assert f.claim_refs and f.evidence_refs
    ev = doc.evidence_by_id(f.evidence_refs[0])
    assert ev.locator["path"] == "app/orchestrator/graph.py" and ev.locator["symbol"] == "persist_all"
    assert any("работающего deployment" in l or "deployment" in l for l in f.limitations)
    assert all(t.classification.value == "READ" for t in doc.all_tools())   # all visible tools are READ, defect still present


def test_auth_and_memory_controls_are_independent(stand_doc):
    doc = stand_doc
    assert _res(doc, "AUTH-02").control_outcome == ControlOutcome.FAIL
    assert _res(doc, "AUTH-01").control_outcome == ControlOutcome.PASS
    assert _res(doc, "MEM-01").control_outcome == ControlOutcome.PASS
    assert _res(doc, "MEM-02").control_outcome == ControlOutcome.FAIL
    assert _res(doc, "MEM-08").control_outcome in (ControlOutcome.INCONCLUSIVE, ControlOutcome.NOT_EVALUATED)
    per_hop = [x for x in doc.findings if x.code == "RESOURCE_AUTHORIZATION_MISSING"]
    assert {x.scope["transition"] for x in per_hop} == {"T2-agent-mcp", "T3-mcp-backend", "T3b-account-owner"}
    assert len([x for x in doc.findings if x.code == "CLIENT_CAN_WEAKEN_SERVER_POLICY"]) == 3
    tv = [x for x in doc.findings if x.code == "TOKEN_VALIDATION_INCOMPLETE"]
    assert {x.component_refs[0] for x in tv} == {"mcp-invest", "invest-server", "agent-api"}
    assert "RFC8725-3.9" in tv[0].taxonomy


def test_background_job_and_stores_are_components_without_tools(stand_doc):
    ids = {c.component_id for c in stand_doc.components}
    assert {"session-finalizer", "mongo:agent_policy_memories", "redis:working", "memory-store"} <= ids
    edges = {(e.from_ref, e.to_ref, e.kind) for e in stand_doc.edges}
    assert ("session-finalizer", "mongo:agent_policy_memories", "publish") in edges
    assert _res(stand_doc, "MEM-09").control_outcome == ControlOutcome.FAIL


def test_one_defect_one_stable_finding(stand_doc):
    ids = [f.finding_id for f in stand_doc.findings]
    assert len(ids) == len(set(ids))
    data = json.loads(emit_json(stand_doc))
    assert set(data["definition_analysis"]["finding_refs"]) <= set(ids)
    exp = build_obsec_export(stand_doc)
    assert exp["verdict"]["gate_code"] == "GATE_BLOCK_FINDINGS_PARTIAL"
    assert len({f["stable_id"] for f in exp["findings"]}) == len(exp["findings"])


def test_tool_result_path_and_egress_and_infra(stand_doc):
    doc = stand_doc
    assert _res(doc, "TOOL-04").control_outcome == ControlOutcome.FAIL
    assert doc.trifecta["state"] == "static_path_supported"
    assert _res(doc, "EGRESS-01").control_outcome == ControlOutcome.FAIL
    assert _res(doc, "INFRA-02").control_outcome == ControlOutcome.FAIL
    pub = [x for x in doc.findings if x.code == "STORAGE_PUBLISHED_ON_HOST"]
    assert {x.component_refs[0] for x in pub} == {"redis", "mongo"}
    assert any("reachability" in l for l in pub[0].limitations)
    assert _res(doc, "EGRESS-02").control_outcome == ControlOutcome.NOT_APPLICABLE
    assert _res(doc, "TOOL-01").control_outcome == ControlOutcome.NOT_EVALUATED


def test_markdown_separates_confirmed_from_hypotheses(stand_doc):
    md = emit_markdown(stand_doc)
    assert "### 5.1 Подтверждённые" in md and "### 5.2 Гипотезы" in md
    assert "USER_HANDLER_PUBLISHES_SHARED_POLICY" in md
    assert "AUTHORIZATION_STEERING" in md
    assert "9/14" in md or "9 configured vs 14" in md
    assert "<IMPORTANT>" not in md
