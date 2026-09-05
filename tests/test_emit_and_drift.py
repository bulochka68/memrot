"""Emission (JSON/Markdown/JSONL/ObSec) and baseline comparison (criteria 14, 16)."""
import json
import os
from mcp_audit.orchestrator import audit_from_config
from mcp_audit.reporting import (emit_json, emit_markdown, emit_jsonl, build_obsec_export, save_baseline, load_baseline,
                                 diff_baseline, esc)
from mcp_audit.validation import validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(os.path.dirname(HERE), "examples", "mcp_config.example.json")


def test_json_validates_and_markdown_comes_from_same_model():
    doc = audit_from_config(EXAMPLE)
    data = json.loads(emit_json(doc))
    assert data["schema"] == "agent-security-audit" and data["schema_version"] == "2.0"
    assert validate_document(data) == []
    md = emit_markdown(doc)
    for heading in ("## 1.", "## 3.", "## 5.", "## 6.", "## 10."):
        assert heading in md
    assert data["verdict"]["assessment_state"] in md
    assert "Покрытие неполное" in md
    lines = emit_jsonl(doc).splitlines()
    assert json.loads(lines[0])["record"] == "run"
    assert {json.loads(l)["record"] for l in lines} >= {"evidence", "claim", "control_result"}


def test_env_values_never_emitted(write_json):
    cfg = {"mcpServers": {"x": {"command": "c", "env": {"SECRET_TOKEN": "supersecret"},
                                "tools": [{"name": "t", "inputSchema": {"type": "object"}}]}}}
    doc = audit_from_config(write_json("c.json", cfg))
    blob = emit_json(doc) + emit_markdown(doc)
    assert "supersecret" not in blob
    assert "SECRET_TOKEN" in blob


def test_untrusted_fragments_are_escaped():
    assert "<script>" not in esc("<script>alert(1)</script>")
    assert "[x](http://e)" not in esc("[x](http://e)")


def test_obsec_export_is_idempotent_with_stable_ids():
    doc = audit_from_config(EXAMPLE)
    a = build_obsec_export(doc)
    b = build_obsec_export(doc)
    assert [f["stable_id"] for f in a["findings"]] == [f["stable_id"] for f in b["findings"]]
    assert a["verdict"]["gate_code"] == "GATE_INCOMPLETE"
    assert a["exporter"]["status"] == "ok"
    bad = build_obsec_export(doc, {a["findings"][0]["stable_id"]: {"state": "accepted"}}) if a["findings"] else None
    if bad:
        assert bad["exporter"]["status"] == "error"


def test_drift_clean_then_definition_change_is_not_a_rug_pull(tmp_path):
    doc = audit_from_config(EXAMPLE)
    bl = str(tmp_path / "bl.json")
    save_baseline(doc, bl)
    old = load_baseline(bl)
    assert old["approval_state"] == "unknown"
    assert diff_baseline(old, audit_from_config(EXAMPLE))["clean"] is True
    cfg = json.load(open(EXAMPLE))
    cfg["mcpServers"]["filesystem"]["tools"][0]["description"] = "changed"
    changed = str(tmp_path / "changed.json")
    json.dump(cfg, open(changed, "w"))
    d = diff_baseline(old, audit_from_config(changed))
    assert d["clean"] is False and "rug_pull" not in d
    ch = [c for c in d["changes"] if c["kind"] == "definition_changed"][0]
    assert ch["key"] == "filesystem/read_file" and ch["approval_state"] == "unknown"
    assert "not established" in ch["interpretation"]
    approved = diff_baseline(old, audit_from_config(changed), {"filesystem/read_file": {"state": "approved", "hash": ch["new"]}})
    assert approved["approval_state"] == "approved"


def test_new_server_and_incompatible_snapshot(tmp_path):
    doc = audit_from_config(EXAMPLE)
    bl = str(tmp_path / "bl.json")
    save_baseline(doc, bl)
    old = load_baseline(bl)
    cfg = json.load(open(EXAMPLE))
    cfg["mcpServers"]["evil"] = {"command": "c", "tools": [{"name": "z", "inputSchema": {"type": "object"}}]}
    p = str(tmp_path / "new.json")
    json.dump(cfg, open(p, "w"))
    d = diff_baseline(old, audit_from_config(p))
    assert any(c["kind"] == "added" and c["key"] == "server:evil" for c in d["changes"])
    other = dict(old)
    other["target"] = {"id": "another-target", "build_ref": None, "environment": None}
    d2 = diff_baseline(other, audit_from_config(EXAMPLE))
    assert d2["compatibility"]["comparable"] is False and d2["clean"] is None
    assert d2["changes"][0]["kind"] == "comparison_inconclusive"


def test_policy_change_between_compatible_snapshots_is_policy_drift(stand_doc, tmp_path):
    from mcp_audit.reporting import build_baseline
    old = build_baseline(stand_doc)
    old["policy_digest"] = "sha256:other"
    d = diff_baseline(old, stand_doc)
    kinds = {c["kind"] for c in d["changes"]}
    assert "policy_changed" in kinds
    assert d["approval_state"] in ("unknown", "pending")
