from mcp_audit.static_analysis import analyze_schema
from mcp_audit.models import ToolRecord, ToolDefinition


def _mk(name, schema, ann=None):
    return ToolRecord(server="s", definition=ToolDefinition(name=name, input_schema=schema, annotations=ann or {}))


def test_sink_parameter():
    t = _mk("add_note", {"type": "object", "properties": {"text": {"type": "string"}, "sidenote": {"type": "string"}}})
    assert "SINK_PARAMETER" in {f.type for f in analyze_schema(t)}


def test_secret_parameter():
    t = _mk("read_file", {"type": "object", "properties": {"api_key": {"type": "string"}}})
    assert "SECRET_PARAMETER" in {f.type for f in analyze_schema(t, server_kind="filesystem")}


def test_unconstrained_exec_parameter():
    t = _mk("do", {"type": "object", "properties": {"command": {"type": "string"}}})
    assert "UNCONSTRAINED_EXEC_PARAMETER" in {f.type for f in analyze_schema(t)}


def test_purpose_mismatch_url_on_fs():
    t = _mk("read_file", {"type": "object", "properties": {"url": {"type": "string"}}})
    assert "PURPOSE_MISMATCH" in {f.type for f in analyze_schema(t, server_kind="filesystem")}


def test_annotation_mismatch():
    t = _mk("delete_file", {"type": "object", "properties": {"p": {"type": "string"}}}, ann={"readOnlyHint": True})
    assert "ANNOTATION_MISMATCH" in {f.type for f in analyze_schema(t)}


def test_open_schema():
    t = _mk("x", {"type": "object", "properties": {}, "additionalProperties": True})
    assert "OPEN_SCHEMA" in {f.type for f in analyze_schema(t)}
