"""Memory rules on synthetic events, traces and cases (criteria 8, 10, 11, 12, 21)."""
import json
import os
from mcp_audit.adapters import AdapterBinding
from mcp_audit.manifest import Manifest
from mcp_audit.models import RunMode, AccessProfile, ClaimStatus, ControlOutcome
from mcp_audit.orchestrator import Orchestrator
from mcp_audit.memory import observe_cases, normalize_record

HERE = os.path.dirname(os.path.abspath(__file__))
STAND = os.path.join(HERE, "fixtures", "stand")
PROFILE = os.path.join(os.path.dirname(HERE), "profiles", "genai_invest_stand.json")
POLICY = os.path.join(os.path.dirname(HERE), "examples", "genai_invest_stand.policy.json")


def _run(adapters, profile_ref=PROFILE, mode=RunMode.TRACE_REVIEW):
    m = Manifest(target={"id": "t", "build_ref": "b1", "environment": "fixture"}, access_profile=AccessProfile.GREY_BOX,
                 mode=mode, profile_ref=profile_ref, adapters=adapters, base_dir=STAND)
    return Orchestrator(m).run()


def test_memory_events_runtime_failures_and_unknown_owner_kept():
    doc = _run([AdapterBinding("mem", "memory_event_snapshot", {"path": os.path.join(STAND, "memory_events.json")}, base_dir=STAND),
                AdapterBinding("policy", "policy_snapshot", {"path": POLICY}, base_dir=STAND)])
    r1 = doc.control_result("MEM-01")
    assert r1.control_outcome == ControlOutcome.FAIL
    f1 = [f for f in doc.findings if f.code == "MEMORY_ISOLATION_VIOLATED"][0]
    assert f1.verification_status == ClaimStatus.RUNTIME_SUPPORTED
    assert f1.memory_stages["C"].value == "unknown"          # context inclusion not covered by the events
    assert doc.control_result("MEM-02").control_outcome == ControlOutcome.FAIL
    assert any(f.code == "SHARED_POLICY_WRITTEN_BY_NON_PUBLISHER" for f in doc.findings)
    assert doc.control_result("MEM-03").control_outcome == ControlOutcome.FAIL
    orphan = [r for r in doc.memory_records if r["memory_id"] == "orphan-1"][0]
    assert orphan["subject_ref"] is None and "subject_ref" in orphan["unknown_fields"]
    trusted = [r for r in doc.memory_records if r["memory_id"] == "fact-A1"][0]
    assert trusted["self_asserted"] == {"trusted": True}      # self-asserted flag is kept apart, never promoted


def test_memory_cases_stage_semantics_unknown_vs_not_observed():
    doc = _run([AdapterBinding("mem", "memory_event_snapshot", {"path": os.path.join(STAND, "memory_events.json")}, base_dir=STAND),
                AdapterBinding("fx", "control_fixtures", {"path": os.path.join(STAND, "memory_cases.json")}, base_dir=STAND)])
    cases = {c["case_id"]: c for c in doc.memory_cases}
    c = cases["MC-policy-written"]
    assert c["stages"]["W"] == "observed" and c["stages"]["R"] == "observed"
    assert c["stages"]["C"] == "unknown" and c["stages"]["B"] == "unknown"     # criterion 11
    assert "unobservable" in c["conclusion"]
    adm = cases["MC-admin-prepared"]
    assert any("fixture administrator" in l for l in adm["limitations"])       # criterion 12
    mem_cov = [m for m in doc.coverage if m.metric == "memory_stage_C"][0]
    assert mem_cov.unknown == 2


def test_written_but_truncated_from_context_is_not_influence():
    doc = _run([AdapterBinding("trace", "trace", {"path": os.path.join(STAND, "trace_with_context.jsonl")}, base_dir=STAND),
                AdapterBinding("fx", "control_fixtures", {"path": os.path.join(STAND, "memory_cases_context.json")}, base_dir=STAND)])
    c = {c["case_id"]: c for c in doc.memory_cases}["MC-truncated"]
    assert c["stages"]["W"] == "observed" and c["stages"]["R"] == "observed"
    assert c["stages"]["C"] == "not_observed" and c["stages"]["B"] == "not_observed"   # criterion 10
    assert "no model influence" in c["conclusion"]
    assert doc.meta["trace_quality"]["linkage"] == "complete"
    # runtime flow observation upgrades the graph edge
    assert any(e.from_ref == "duckduckgo" and e.state.value == "runtime_path_observed" for e in doc.edges)


def test_revocation_with_pending_job_is_not_concluded_clean(write_json):
    events = {"schema": "memory-events", "coverage": {"write": True, "retrieve": True, "context_include": True, "behavior": False},
              "records": [], "events": [
                  {"event_id": "r1", "run_id": "x", "trace_id": "x", "component": "memory-store", "ts": 100.0, "principal": "u1",
                   "memory": {"memory_id": "m1", "operation": "revoke"}},
                  {"event_id": "j1", "run_id": "x", "trace_id": "x", "component": "session-finalizer", "ts": 101.0, "principal": "u1",
                   "job": {"job_id": "job-1", "status": "pending", "memory_ids": ["m1"]}}]}
    policy = {"schema": "access-policy", "policy_id": "p", "version": "1", "memory_policy": {"memory_types": [{"type": "shared_policy", "audience": "shared", "authority": "policy"}], "revocation": {"propagate_to_derived": True, "max_delay_seconds": 10}}}
    doc = _run([AdapterBinding("mem", "memory_event_snapshot", {"path": write_json("e.json", events)}, base_dir=STAND),
                AdapterBinding("policy", "policy_snapshot", {"path": write_json("p.json", policy)}, base_dir=STAND)])
    r = doc.control_result("MEM-08")
    assert r.control_outcome == ControlOutcome.INCONCLUSIVE
    assert any("consistency window not closed" in l for l in r.limitations)


def test_allowed_sharing_between_agents_is_not_a_violation(write_json, tmp_path):
    src = tmp_path / "src" / "app.py"
    src.parent.mkdir()
    src.write_text('def read_shared(agent, project):\n    return db.find({"project_id": project, "audience": "project"})\n')
    profile = {"profile_id": "two-agents",
               "memory_stores": [{"component_id": "db", "store_type": "mongodb", "memory_types": [{"type": "project_note", "audience": "project", "authority": "data"}]}],
               "source_facts": {"flows": [{"id": "S-read", "kind": "memory_read", "from": "agent-a", "to": "db", "path": "app.py", "symbol": "read_shared",
                                            "patterns": ["\"project_id\": project"], "memory_type": "project_note", "audience": "project",
                                            "filter_by": ["project_id"], "subject_bound": True, "audience_filter_before_context": True}]}}
    policy = {"schema": "access-policy", "policy_id": "p", "version": "1",
              "memory_policy": {"memory_types": [{"type": "project_note", "audience": "project", "authority": "data"}],
                                "allowed_sharing": [{"between": ["agent-a", "agent-b"], "memory_types": ["project_note"]}]}}
    doc = _run([AdapterBinding("src", "source_snapshot", {"root": str(tmp_path / "src")}, base_dir=str(tmp_path)),
                AdapterBinding("policy", "policy_snapshot", {"path": write_json("p.json", policy)}, base_dir=str(tmp_path))],
               profile_ref=write_json("prof.json", profile), mode=RunMode.OFFLINE)
    assert doc.control_result("MEM-01").control_outcome == ControlOutcome.PASS
    assert not any(f.rule_id == "MEM-01" for f in doc.findings)


def test_normalize_record_never_defaults_owner():
    r = normalize_record({"id": "x", "content": {"owner": "me", "verified": True}}, field_map={"memory_id": "id"})
    assert r["memory_id"] == "x" and r["subject_ref"] is None
    assert r["self_asserted"] == {"owner": "me", "verified": True}


def test_observe_cases_without_coverage_is_unknown():
    obs = observe_cases([{"case_id": "c", "memory_id": "m"}], [], {})
    assert all(v.value == "unknown" for v in obs[0].stages.values())
