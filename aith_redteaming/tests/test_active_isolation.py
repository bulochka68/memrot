import os
import pytest
from mcp_audit.active import IsolationGuard, SandboxViolation
from mcp_audit.active.probes import default_probes
from mcp_audit.models import ServerRecord, ToolRecord, ToolDefinition


def test_guard_refuses_without_sandbox_flag():
    with pytest.raises(SandboxViolation):
        IsolationGuard(sandbox=False).ensure_sandbox()


def test_guard_refuses_without_env_marker(monkeypatch):
    monkeypatch.delenv("MCP_AUDIT_SANDBOX", raising=False)
    with pytest.raises(SandboxViolation):
        IsolationGuard(sandbox=True).ensure_sandbox()


def test_guard_allows_in_sandbox(monkeypatch):
    monkeypatch.setenv("MCP_AUDIT_SANDBOX", "1")
    IsolationGuard(sandbox=True).ensure_sandbox()  # no raise


def test_default_probes_include_boundary_for_fs():
    s = ServerRecord(name="fs", kind="filesystem")
    s.tools = [ToolRecord(server="fs", definition=ToolDefinition(name="write_file")),
               ToolRecord(server="fs", definition=ToolDefinition(name="read_file"))]
    s.effective_access = {"paths": {"allowed": ["/workspace/**"]}}
    probes = default_probes(s, "CANARY-x", "http://sink.invalid")
    kinds = {p.id for p in probes}
    assert "FS-TRAVERSAL" in kinds
    assert any(p.kind == "boundary" for p in probes)
