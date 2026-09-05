import json
from mcp_audit.discovery import parse_config
from mcp_audit.discovery.config_parser import infer_kind, _strip_json_comments, looks_like_mcp_config


def test_parse_mcpservers_shape_records_field_sources():
    servers = parse_config({"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w"]},
    }})
    assert len(servers) == 1
    s = servers[0]
    assert s.name == "fs" and s.kind == "filesystem" and s.transport == "stdio"
    assert s.field_sources["kind"] == "inferred"
    assert s.field_sources["command"] == "config"


def test_config_tools_never_fabricate_a_handshake():
    s = parse_config({"mcpServers": {"x": {"command": "c", "tools": [{"name": "t", "inputSchema": {"type": "object"}}]}}})[0]
    assert s.handshake.performed is False
    assert s.handshake.ok is None
    assert s.handshake.source == "config"
    assert s.inventory_sources["configured"]["count"] == 1


def test_parse_vscode_servers_and_http():
    servers = parse_config({"servers": {"api": {"url": "https://x/mcp"}}})
    assert servers[0].transport == "http"


def test_parse_list_and_bare():
    a = parse_config([{"name": "s", "command": "c"}])
    b = parse_config({"s": {"command": "c"}})
    assert a[0].name == "s" and b[0].name == "s"


def test_disabled_skipped_and_native_flag():
    assert parse_config({"mcpServers": {"x": {"command": "c", "disabled": True}}}) == []
    n = parse_config({"mcpServers": {"native": {"command": "internal", "x_audit": {"native": True}}}})[0]
    assert n.is_mcp is False


def test_infer_kind():
    assert infer_kind("db", "npx", ["server-postgres"], None) == "postgres"
    assert infer_kind("sh", "mcp-server-commands", [], None) == "shell"
    assert infer_kind("weird", "thing", [], None) == "generic"


def test_jsonc_comments_and_detection():
    txt = '{ // c\n "mcpServers": { "s": {"command": "c",} } /* x */ }'
    data = json.loads(_strip_json_comments(txt))
    assert data["mcpServers"]["s"]["command"] == "c"
    assert looks_like_mcp_config(data)
    assert not looks_like_mcp_config({"schema_version": "2.0", "adapters": []})
