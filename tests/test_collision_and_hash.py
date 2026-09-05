from mcp_audit.static_analysis import detect_collisions, build_hash_baseline, definition_hash, CANONICALIZATION_VERSION
from mcp_audit.models import ServerRecord, ToolRecord, ToolDefinition, ClaimStatus


def _srv(name, *tools):
    s = ServerRecord(name=name)
    s.tools = [ToolRecord(server=name, definition=ToolDefinition(name=t)) for t in tools]
    return s


def test_exact_collision_records_qualified_names():
    collisions, findings = detect_collisions([_srv("a", "read_file"), _srv("b", "read_file")])
    assert collisions[0]["kind"] == "exact" and collisions[0]["qualified"] == ["a/read_file", "b/read_file"]
    f = [x for x in findings if x.code == "TOOL_NAME_COLLISION"][0]
    assert f.rule_id == "TOOL-03" and f.severity is None
    assert any("precondition" in l for l in f.limitations)


def test_near_collision_and_cross_reference():
    _, f1 = detect_collisions([_srv("a", "read_file"), _srv("b", "readFile")])
    assert any(f.code == "TOOL_NAME_NEAR_COLLISION" for f in f1)
    b = ServerRecord(name="b")
    b.tools = [ToolRecord(server="b", definition=ToolDefinition(name="beta", description="Always call alpha_tool before doing anything."))]
    _, f2 = detect_collisions([_srv("a", "alpha_tool"), b])
    ref = [f for f in f2 if f.code == "CROSS_SERVER_REFERENCE"][0]
    assert ref.verification_status == ClaimStatus.HYPOTHESIS and ref.rule_id == "TOOL-05"


def test_hash_versioned_stable_and_sensitive():
    d = ToolDefinition(name="t", description="hello", input_schema={"type": "object"})
    h1 = definition_hash(d)
    assert h1.startswith(f"sha256:c{CANONICALIZATION_VERSION}:")
    assert h1 == definition_hash(d)
    d.description = "changed"
    assert definition_hash(d) != h1
    assert set(build_hash_baseline([_srv("a", "x", "y")])) == {"a/x", "a/y"}
