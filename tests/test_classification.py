from mcp_audit.discovery import parse_config
from mcp_audit.classification import classify_tool, resolve_effective_access, score_tool
from mcp_audit.models import Operation, Risk, ToolRecord, ToolDefinition, ServerRecord


def _tool(name, desc=""):
    return ToolRecord(server="s", definition=ToolDefinition(name=name, description=desc))


def test_operation_classification():
    assert classify_tool(_tool("read_file")).classification == Operation.READ
    assert classify_tool(_tool("write_file")).classification == Operation.WRITE
    assert classify_tool(_tool("delete_file")).classification == Operation.DELETE
    assert classify_tool(_tool("execute_command")).classification == Operation.EXEC


def test_delete_is_destructive_and_critical():
    t = classify_tool(_tool("delete_file"))
    score_tool(t)
    assert t.destructive
    assert t.risk == Risk.CRITICAL


def test_exec_is_critical_and_sets_trifecta_legs():
    t = classify_tool(_tool("execute_command"), server_kind="shell")
    score_tool(t)
    assert t.risk == Risk.CRITICAL
    assert t.sensitive_source and t.egress


def test_unknown_mutator_fails_safe_to_write():
    t = classify_tool(_tool("frobnicate"))
    assert t.classification == Operation.WRITE


def test_effective_access_filesystem():
    s = parse_config({"mcpServers": {"fs": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace/my-project"],
        "x_audit": {"kind": "filesystem", "allowed_paths": ["/workspace/my-project/**"], "denied_paths": ["/etc/**"]},
    }}})[0]
    acc = resolve_effective_access(s)
    assert "/workspace/my-project/**" in acc["paths"]["allowed"]
    assert any("/etc" in d for d in acc["paths"]["denied"])
    assert "/root/**" in acc["paths"]["denied"]  # always-deny added


def test_effective_access_postgres_defaults_to_full_dml():
    s = ServerRecord(name="pg", kind="postgres")
    acc = resolve_effective_access(s)
    assert "DELETE" in acc["operations"]
    assert acc["ddl"] is False


def test_fs_no_allowed_paths_is_unbounded():
    s = ServerRecord(name="fs", kind="filesystem")
    acc = resolve_effective_access(s)
    assert acc["unbounded"] is True
