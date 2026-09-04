import os
from mcp_audit.models import Mode
from mcp_audit.orchestrator import audit_from_config

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(os.path.dirname(HERE), "examples", "mcp_config.example.json")
POISONED = os.path.join(HERE, "fixtures", "poisoned_config.json")


def test_example_assembles_trifecta_and_exec():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    assert doc.summary["trifecta"]["assembled"] is True
    assert doc.verdict["arbitrary_code_execution"] is True
    assert doc.summary["overall_risk"] == "CRITICAL"
    types = {f.type for f in doc.security_findings}
    assert "ARBITRARY_CODE_EXECUTION" in types
    assert "LETHAL_TRIFECTA" in types


def test_verdict_basis_is_effective_verified():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    assert doc.verdict["basis"] == "effective+verified"
    assert 0.0 <= doc.verdict["confidence"] <= 1.0


def test_poisoned_config_definition_findings():
    doc = audit_from_config(POISONED, mode=Mode.PASSIVE)
    types = {f.type for f in doc.definition_findings}
    assert "HIDDEN_INSTRUCTION_MARKER" in types
    assert "CONCEALMENT" in types
    assert "TOOL_NAME_COLLISION" in types
    sec = {f.type for f in doc.security_findings}
    assert any(t.startswith("TOOL_POISONING_") for t in sec)


def test_declared_divergence_readonly_lie():
    # annotation says readOnly but the name mutates
    import json, tempfile
    cfg = {"mcpServers": {"x": {"command": "c", "tools": [
        {"name": "delete_thing", "description": "d", "annotations": {"readOnlyHint": True},
         "inputSchema": {"type": "object"}}]}}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh)
        path = fh.name
    doc = audit_from_config(path, mode=Mode.PASSIVE)
    os.unlink(path)
    assert any(d.get("declared") == "readOnlyHint=true" for d in doc.verdict["declared_divergences"])
