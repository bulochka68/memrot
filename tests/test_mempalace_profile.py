"""Acceptance stand: a foreign system audited without touching the engine.

MemPalace (https://github.com/MemPalace/mempalace, commit d9f0590) was written
without any knowledge of this auditor: 45 tools declared in a module-level
``TOOLS`` dictionary, its own domain vocabulary, an HTTP hub protected by one
shared bearer token and a mesh sync with peer nodes.  Connecting it required
three hand-written files (profile, policy, manifest) plus generated snapshots -
and no change inside ``mcp_audit``.

The test runs offline from the committed snapshots, so it needs neither the
clone nor the network: ``examples/mempalace.source_facts.json`` carries the
locators, digests and fragments captured from that commit.
"""
import json
import os

import pytest

from mcp_audit.models import ControlOutcome
from mcp_audit.orchestrator import audit_from_manifest
from mcp_audit.reporting import emit_json
from mcp_audit.validation import lint_profile, validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(ROOT, "examples", "mempalace.manifest.json")
PROFILE = os.path.join(ROOT, "profiles", "mempalace.json")
FACTS = os.path.join(ROOT, "examples", "mempalace.source_facts.json")


@pytest.fixture(scope="module")
def doc():
    return audit_from_manifest(MANIFEST)


def _profile():
    with open(PROFILE, encoding="utf-8") as fh:
        return json.load(fh)


def test_profile_lints_clean():
    report = lint_profile(_profile(), path=PROFILE, sources=["mcp_inventory", "policy_snapshot", "deployment"])
    assert report.errors == [], report.text()
    planned = [e for e in report.plan["entries"] if e["status"] == "planned"]
    assert len(planned) >= 20, report.text()


def test_every_declared_fact_is_confirmed_by_the_recorded_build():
    """A fact file is a claim about a commit: nothing here may be stale or unlocated."""
    with open(FACTS, encoding="utf-8") as fh:
        facts = json.load(fh)
    assert facts["captured_from"]["commit"] == "d9f059076c866fa6f29195679d75712436986024"
    for group in ("flows", "auth_transitions", "token_validation", "background_jobs", "break_points"):
        for item in facts[group]:
            assert item["status"] == "static_supported", f"{group}/{item.get('id')}: {item.get('reason') or item.get('matched')}"


def test_all_45_tools_are_classified_without_an_unmotivated_unknown(doc):
    server = doc.server("mempalace")
    assert server is not None and server.kind == "memory"      # kind inferred from the profile lexicon
    tools = server.tools
    assert len(tools) == 45
    assert [t.name for t in tools if t.classification.value == "UNKNOWN"] == []
    assert {t.classification_basis for t in tools} <= {"declared", "source_inference", "definition"}
    declared = [t for t in tools if t.classification_basis == "declared"]
    assert {t.name for t in declared} >= {"mempalace_reconnect", "mempalace_event_wait", "mempalace_artifact_get"}
    # a declaration is the profile author speaking; it never becomes an observation
    assert all(t.knowledge_state.value == "assumed" for t in declared)
    # the egress heuristic's false positives are corrected by evidence-backed declarations
    assert not any(t.egress for t in tools if t.name in ("mempalace_get_drawer", "mempalace_event_wait",
                                                         "mempalace_task_create", "mempalace_artifact_get"))


def test_the_engine_can_contradict_the_author_on_a_foreign_system(doc):
    outcomes = {r.rule_id: r.control_outcome for r in doc.control_results}
    evaluated = [r for r in doc.control_results
                 if r.control_outcome not in (ControlOutcome.NOT_EVALUATED, ControlOutcome.NOT_APPLICABLE)]
    assert len(evaluated) >= 12, sorted(r.rule_id for r in evaluated)
    fails = [r.rule_id for r in doc.control_results if r.control_outcome == ControlOutcome.FAIL]
    assert fails, "a demonstration in which the engine cannot object to the profile author demonstrates nothing"
    # the hub's own properties, each backed by a located fact in the recorded build
    assert outcomes["MEM-01"] == ControlOutcome.FAIL        # events are filtered by a caller-supplied to_agent
    assert outcomes["MEM-03"] == ControlOutcome.FAIL        # writer and placement come from the call
    assert outcomes["AUTH-01"] == ControlOutcome.FAIL       # the acting agent is a request field
    assert outcomes["AUTH-04"] == ControlOutcome.FAIL       # a static shared secret: no revocation, no subject
    assert outcomes["EGRESS-01"] == ControlOutcome.FAIL     # /sync serves artifact content to any token holder
    assert outcomes["MEM-05"] == ControlOutcome.PASS        # provenance is kept on writes and on mining
    assert outcomes["MEM-04"] == ControlOutcome.PASS        # memory reaches the model as tool-result data


def test_findings_are_traceable_to_the_recorded_build(doc):
    build = doc.target["build_ref"]
    confirmed = [f for f in doc.findings if f.verification_status.value == "static_supported"]
    assert confirmed
    for f in confirmed:
        assert f.claim_refs and f.closure_criterion
    for e in doc.evidence:
        if e.source_type.value == "source_code":
            assert e.scope.get("build_ref") == build
            assert e.locator.get("path", "").startswith("mempalace/")


def test_report_validates(doc):
    assert validate_document(json.loads(emit_json(doc))) == []
    assert doc.meta["reproducibility"]["lexicon"]["modified"] is True
