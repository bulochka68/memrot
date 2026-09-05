from mcp_audit.static_analysis import analyze_schema, compare_contracts
from mcp_audit.models import ToolRecord, ToolDefinition, ClaimStatus


def _mk(name, schema, ann=None):
    return ToolRecord(server="s", definition=ToolDefinition(name=name, input_schema=schema, annotations=ann or {}))


def _codes(fs):
    return {f.code for f in fs}


def test_sink_secret_exec_signals_are_hypotheses():
    fs = analyze_schema(_mk("add_note", {"type": "object", "properties": {"text": {"type": "string"}, "sidenote": {"type": "string"}}}))
    assert "SINK_PARAMETER" in _codes(fs)
    assert all(f.verification_status == ClaimStatus.HYPOTHESIS and f.rule_id == "TOOL-05" for f in fs)
    assert "SECRET_PARAMETER" in _codes(analyze_schema(_mk("read_file", {"type": "object", "properties": {"api_key": {"type": "string"}}}), server_kind="filesystem"))
    assert "UNCONSTRAINED_EXEC_PARAMETER" in _codes(analyze_schema(_mk("do", {"type": "object", "properties": {"command": {"type": "string"}}})))


def test_purpose_mismatch_annotation_mismatch_open_schema():
    assert "PURPOSE_MISMATCH" in _codes(analyze_schema(_mk("read_file", {"type": "object", "properties": {"url": {"type": "string"}}}), server_kind="filesystem"))
    assert "ANNOTATION_MISMATCH" in _codes(analyze_schema(_mk("delete_file", {"type": "object", "properties": {"p": {"type": "string"}}}, ann={"readOnlyHint": True})))
    assert "OPEN_SCHEMA" in _codes(analyze_schema(_mk("x", {"type": "object", "properties": {}, "additionalProperties": True})))


def test_compare_contracts_distinguishes_breaking_from_optional():
    a = {"properties": {"query": {"type": "string"}}, "required": ["query"]}
    b = {"properties": {"queries": {"type": "array"}}, "required": ["queries"]}
    diffs = compare_contracts(a, b, label_a="configured", label_b="source_defined")
    assert {d["parameter"] for d in diffs} == {"query", "queries"}
    assert all(d["breaking"] for d in diffs)
    c = {"properties": {"cus": {"type": "string"}, "date_from": {"type": "string"}}, "required": ["cus"]}
    d = {"properties": {"cus": {"type": "string"}}, "required": ["cus"]}
    diffs = compare_contracts(c, d)
    assert diffs and not any(x["breaking"] for x in diffs)
    assert compare_contracts({"properties": {"a": {"type": "string"}}}, {"properties": {"a": {"type": "integer"}}})[0]["breaking"]
