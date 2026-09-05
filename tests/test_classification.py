from mcp_audit.discovery import parse_config
from mcp_audit.classification import classify_tool, resolve_effective_access, score_tool, CONVENTIONAL_DENIALS
from mcp_audit.models import Operation, Severity, ToolRecord, ToolDefinition, ServerRecord, KnowledgeState


def _tool(name, desc=""):
    return ToolRecord(server="s", definition=ToolDefinition(name=name, description=desc))


def test_primary_class_and_v2_operations():
    assert classify_tool(_tool("read_file")).classification == Operation.READ
    w = classify_tool(_tool("write_file"))
    assert w.classification == Operation.WRITE and set(w.operations) >= {"CREATE"}
    d = classify_tool(_tool("delete_file"))
    assert d.classification == Operation.DELETE and d.operations == ["DELETE"]
    e = classify_tool(_tool("execute_command"))
    assert e.classification == Operation.EXEC and "EXECUTE" in e.operations and "TRANSMIT" in e.operations
    assert e.classification_basis == "definition" and e.knowledge_state == KnowledgeState.ASSUMED


def test_unknown_class_is_unknown_not_assumed_write():
    t = classify_tool(_tool("frobnicate"))
    assert t.classification == Operation.UNKNOWN
    assert t.knowledge_state == KnowledgeState.UNKNOWN
    assert score_tool(t).capability_risk == Severity.MEDIUM   # potential damage is not lowered by assumption


def test_capability_risk_is_not_a_finding_severity():
    t = classify_tool(_tool("delete_file"))
    score_tool(t)
    assert t.destructive and t.capability_risk == Severity.CRITICAL
    assert "potential damage" in t.provenance["capability_risk"]


def test_effective_access_separates_expected_inferred_observed():
    s = parse_config({"mcpServers": {"fs": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace/my-project"],
        "x_audit": {"kind": "filesystem", "allowed_paths": ["/workspace/my-project/**"], "denied_paths": ["/etc/**"]},
    }}})[0]
    acc = resolve_effective_access(s)
    assert acc["policy_expected"]["paths_allowed"] == ["/workspace/my-project/**"]
    assert acc["policy_expected"]["paths_denied"] == ["/etc/**"]
    assert acc["inferred"]["conventional_denials"]["paths"] == CONVENTIONAL_DENIALS
    assert "not an ACL" in acc["inferred"]["conventional_denials"]["note"]
    assert acc["enforcement"] == "unknown"
    assert acc["observed"]["items"] == []
    assert "/root/**" not in acc["policy_expected"].get("paths_denied", [])   # convention is never presented as the author's policy


def test_unknown_permissions_stay_unknown():
    s = ServerRecord(name="pg", kind="postgres")
    acc = resolve_effective_access(s)
    assert acc["inferred"]["ddl"] is None
    assert "assumed" in acc["inferred"]["operations_note"]
    g = ServerRecord(name="g", kind="generic")
    assert resolve_effective_access(g)["inferred"]["network_access"] is None


def test_fs_without_root_is_unknown_scope():
    s = ServerRecord(name="fs", kind="filesystem")
    acc = resolve_effective_access(s)
    assert acc["inferred"]["unbounded"] is True
    assert acc["inferred"]["knowledge_state"] == "unknown"
