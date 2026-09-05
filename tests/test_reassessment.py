"""criterion 20: closure by the remediation criterion on a new build, not by a vanished source."""
import os
from mcp_audit.adapters import AdapterBinding
from mcp_audit.manifest import Manifest
from mcp_audit.models import RunMode, ControlOutcome
from mcp_audit.orchestrator import Orchestrator


def _profile(write_json):
    return write_json("prof.json", {"profile_id": "p", "components": [{"id": "worker", "type": "background_job", "role": "background_worker"}],
        "memory_stores": [{"component_id": "db", "store_type": "mongodb", "memory_types": [{"type": "shared_policy", "audience": "shared", "authority": "policy", "trusted_publishers": ["admin"]}]}],
        "source_facts": {"flows": [{"id": "P", "kind": "publish", "from": "worker", "to": "db", "path": "w.py", "symbol": "persist",
                                    "patterns": ["save_policy\\("], "writer_principal": "worker", "writer_role": "background_worker",
                                    "memory_type": "shared_policy", "audience": "shared", "authority": "policy"}]}})


def _run(tmp_path, profile, build, code):
    src = tmp_path / build
    src.mkdir()
    (src / "w.py").write_text(code)
    m = Manifest(target={"id": "t", "build_ref": build, "environment": "fixture"}, mode=RunMode.OFFLINE, profile_ref=profile,
                 adapters=[AdapterBinding("src", "source_snapshot", {"root": str(src)}, base_dir=str(tmp_path))], base_dir=str(tmp_path))
    return Orchestrator(m).run()


def test_fix_closes_by_criterion_and_missing_source_does_not(tmp_path, write_json):
    profile = _profile(write_json)
    before = _run(tmp_path, profile, "build-a", "def persist(facts):\n    save_policy(facts)\n")
    assert before.control_result("MEM-02").control_outcome == ControlOutcome.FAIL
    fid = [f for f in before.findings if f.rule_id == "MEM-02"][0].finding_id
    after = _run(tmp_path, profile, "build-b", "def persist(facts):\n    save_user_facts(facts)\n")
    assert after.control_result("MEM-02").control_outcome == ControlOutcome.PASS
    assert not any(f.finding_id == fid for f in after.findings)
    # same defect on the new build keeps the same stable id (new instance, same root cause)
    again = _run(tmp_path, profile, "build-c", "def persist(facts):\n    save_policy(facts)\n")
    f = [f for f in again.findings if f.rule_id == "MEM-02"][0]
    assert f.finding_id == fid and f.instance_id != [x for x in before.findings if x.rule_id == "MEM-02"][0].instance_id
    # source gone: not a closure
    m = Manifest(target={"id": "t", "build_ref": "build-d", "environment": "fixture"}, mode=RunMode.OFFLINE, profile_ref=profile,
                 adapters=[AdapterBinding("src", "source_snapshot", {"root": str(tmp_path / "nowhere")}, base_dir=str(tmp_path))], base_dir=str(tmp_path))
    gone = Orchestrator(m).run()
    assert gone.control_result("MEM-02").control_outcome == ControlOutcome.NOT_EVALUATED
    assert gone.verdict["security_conclusion"] != "no_violations_observed"
