import json
import os
import tempfile
from mcp_audit.models import Mode
from mcp_audit.orchestrator import audit_from_config
from mcp_audit.reporting import emit_json, emit_markdown, save_baseline, load_baseline, diff_baseline

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(os.path.dirname(HERE), "examples", "mcp_config.example.json")


def test_emit_json_roundtrips_and_has_schema():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    data = json.loads(emit_json(doc))
    assert data["schema"] == "audit"
    assert "definition_analysis" in data
    assert "downstream" in data
    assert data["downstream"]["P2_matrix"]


def test_emit_markdown_smoke():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    md = emit_markdown(doc)
    assert "# MCP audit report" in md
    assert "Lethal trifecta" in md


def test_env_values_never_emitted():
    import json as _json, tempfile as _tf
    cfg = {"mcpServers": {"x": {"command": "c", "env": {"SECRET_TOKEN": "supersecret"},
                                "tools": [{"name": "t", "inputSchema": {"type": "object"}}]}}}
    with _tf.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        _json.dump(cfg, fh); path = fh.name
    doc = audit_from_config(path, mode=Mode.PASSIVE)
    os.unlink(path)
    blob = emit_json(doc)
    assert "supersecret" not in blob
    assert "SECRET_TOKEN" in blob  # the key is kept, the value is not


def test_drift_clean_then_rug_pull():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        bl_path = fh.name
    save_baseline(doc, bl_path)
    old = load_baseline(bl_path)

    # unchanged -> clean
    doc2 = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    assert diff_baseline(old, doc2)["clean"] is True

    # change a description -> rug pull
    cfg = json.load(open(EXAMPLE))
    cfg["mcpServers"]["filesystem"]["tools"][0]["description"] = "changed"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh); changed = fh.name
    doc3 = audit_from_config(changed, mode=Mode.PASSIVE)
    d = diff_baseline(old, doc3)
    os.unlink(bl_path); os.unlink(changed)
    assert d["rug_pull"] is True
    assert d["changed_definitions"][0]["key"] == "filesystem/read_file"


def test_new_server_triggers_full_reaudit_alert():
    doc = audit_from_config(EXAMPLE, mode=Mode.PASSIVE)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        bl_path = fh.name
    save_baseline(doc, bl_path)
    old = load_baseline(bl_path)
    cfg = json.load(open(EXAMPLE))
    cfg["mcpServers"]["evil"] = {"command": "c", "tools": [{"name": "z", "inputSchema": {"type": "object"}}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh); newp = fh.name
    doc2 = audit_from_config(newp, mode=Mode.PASSIVE)
    d = diff_baseline(old, doc2)
    os.unlink(bl_path); os.unlink(newp)
    assert "evil" in d["added_servers"]
    assert any("NEW_SERVER" in a for a in d["alerts"])
