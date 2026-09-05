"""Legacy v1.0/v1.1 import (criterion 17)."""
import json
import os
import pytest
from mcp_audit.migration import load_legacy_audit, import_legacy_dict
from mcp_audit.models import ClaimStatus

HERE = os.path.dirname(os.path.abspath(__file__))
LEGACY = os.path.join(HERE, "fixtures", "legacy", "genai_invest_stand.audit.v1.1.json")


def test_legacy_import_keeps_history_without_new_evidence():
    doc = load_legacy_audit(LEGACY)
    h = doc.import_history
    assert h["legacy_version"] == "1.1"
    assert "not a list of passed checks" in h["interpretation"]["tests"]
    assert "dropped" in h["interpretation"]["confidence"]
    for s in doc.servers:
        assert s.handshake.performed is False and s.handshake.ok is None    # config never becomes a live handshake
    assert doc.tests == [] and doc.runtime_validation_performed is False
    assert not any(c.claim_status == ClaimStatus.RUNTIME_SUPPORTED for c in doc.claims)


def test_ambiguous_verified_is_not_promoted():
    data = json.load(open(LEGACY))
    data["servers"][0]["tools"][0]["verified"] = True
    doc = import_legacy_dict(data)
    t = doc.servers[0].tools[0]
    assert "NOT promoted" in t.provenance["verified_import"]
    assert any("verified=true had no matching test" in l for l in doc.import_history["limitations"])
    data["tests"] = [{"id": "p", "name": "n", "server": doc.servers[0].name, "tool": t.name, "result": "PASS", "expected": "PASS"}]
    doc2 = import_legacy_dict(data)
    assert doc2.tests[0].control_outcome.value == "INCONCLUSIVE"     # legacy PASS without an observed effect
    assert "runtime-supported by a matching legacy test result" in doc2.servers[0].tools[0].provenance["verified_import"]


def test_unknown_version_is_not_guessed():
    data = json.load(open(LEGACY))
    data["version"] = "1.7"
    with pytest.raises(ValueError):
        import_legacy_dict(data)
