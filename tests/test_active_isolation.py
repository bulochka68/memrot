import pytest
from mcp_audit.active import IsolationGuard, SandboxViolation, kind_cases, schema_agrees, classify_error, decide
from mcp_audit.active.fixtures import ControlCase
from mcp_audit.models import ServerRecord, ToolRecord, ToolDefinition, ExecutionStatus, ErrorClass, ControlOutcome
from mcp_audit.discovery.introspector import MCPError


def test_guard_refuses_without_declaration(monkeypatch):
    with pytest.raises(SandboxViolation):
        IsolationGuard(sandbox=False).ensure_sandbox()
    monkeypatch.delenv("MCP_AUDIT_SANDBOX", raising=False)
    with pytest.raises(SandboxViolation):
        IsolationGuard(sandbox=True).ensure_sandbox()
    monkeypatch.setenv("MCP_AUDIT_SANDBOX", "1")
    IsolationGuard(sandbox=True).ensure_sandbox()


def test_declaration_is_not_proof_and_destructive_off_by_default():
    g = IsolationGuard(sandbox=True)
    assert g.allow_destructive is False
    assert "not proof" in g.declaration()["note"]
    ev = IsolationGuard.technical_evidence({})
    assert ev["attested"] is False
    ev2 = IsolationGuard.technical_evidence({"data": "synthetic", "network": "none", "permissions": "low", "attested_by": "fixture"})
    assert ev2["attested"] is True


def test_kind_cases_only_with_agreeing_schema():
    s = ServerRecord(name="fs", kind="filesystem")
    s.tools = [ToolRecord(server="fs", definition=ToolDefinition(name="write_file", input_schema={"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]})),
               ToolRecord(server="fs", definition=ToolDefinition(name="read_file", input_schema={"type": "object", "properties": {"path": {"type": "string"}}}))]
    s.effective_access = {"policy_expected": {"paths_allowed": ["/workspace/**"]}, "inferred": {}}
    cases = kind_cases(s, {"canary": "CANARY-x", "sinkhole": "http://sink.invalid"})
    ids = {c.id for c in cases}
    assert "FS-TRAVERSAL" in ids and all(c.effect_check["kind"] != "none" for c in cases if c.expected == "denied" and c.id.startswith("FS"))
    assert schema_agrees(s.tools[0], {"path": "x", "content": "y"}) == []
    assert schema_agrees(s.tools[0], {"filepath": "x"})
    assert schema_agrees(None, {"path": "x"})


def test_error_classification_and_outcome_semantics():
    assert classify_error(MCPError("invalid params", code=-32602), None) == ErrorClass.SCHEMA_ERROR
    assert classify_error(MCPError("method not found", code=-32601), None) == ErrorClass.UNKNOWN_TOOL
    assert classify_error(TimeoutError("t"), None) == ErrorClass.TIMEOUT
    assert classify_error(None, {"isError": True, "content": [{"type": "text", "text": "permission denied"}]}) == ErrorClass.AUTHORIZATION_REFUSAL
    denied = ControlCase("c", "c", "s", "t", {}, "denied")
    assert decide(denied, ExecutionStatus.TIMEOUT, ErrorClass.TIMEOUT, {"kind": "none", "observed": None})[0] == ControlOutcome.INCONCLUSIVE
    assert decide(denied, ExecutionStatus.COMPLETED, ErrorClass.NONE, {"kind": "none", "observed": None})[0] == ControlOutcome.INCONCLUSIVE
    assert decide(denied, ExecutionStatus.COMPLETED, ErrorClass.NONE, {"kind": "file_absent", "observed": False, "forbidden_effect": True})[0] == ControlOutcome.FAIL
    assert decide(denied, ExecutionStatus.COMPLETED, ErrorClass.AUTHORIZATION_REFUSAL, {"kind": "file_absent", "observed": True})[0] == ControlOutcome.PASS
    allowed = ControlCase("c", "c", "s", "t", {}, "allowed")
    assert decide(allowed, ExecutionStatus.COMPLETED, ErrorClass.AUTHORIZATION_REFUSAL, {"kind": "none", "observed": None})[0] == ControlOutcome.FAIL
    assert decide(allowed, ExecutionStatus.COMPLETED, ErrorClass.NONE, {"kind": "file_exists", "observed": True})[0] == ControlOutcome.PASS
