from mcp_audit.discovery import parse_config
from mcp_audit.discovery.config_parser import infer_kind, _strip_json_comments


def test_parse_mcpservers_shape():
    servers = parse_config({"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w"]},
    }})
    assert len(servers) == 1
    assert servers[0].name == "fs"
    assert servers[0].kind == "filesystem"
    assert servers[0].transport == "stdio"


def test_parse_vscode_servers_and_http():
    servers = parse_config({"servers": {"api": {"url": "https://x/mcp"}}})
    assert servers[0].transport == "http"
    assert servers[0].kind in ("fetch", "generic")


def test_parse_list_and_bare():
    a = parse_config([{"name": "s", "command": "c"}])
    b = parse_config({"s": {"command": "c"}})
    assert a[0].name == "s" and b[0].name == "s"


def test_disabled_skipped():
    servers = parse_config({"mcpServers": {"x": {"command": "c", "disabled": True}}})
    assert servers == []


def test_infer_kind():
    assert infer_kind("db", "npx", ["server-postgres"], None) == "postgres"
    assert infer_kind("sh", "mcp-server-commands", [], None) == "shell"
    assert infer_kind("weird", "thing", [], None) == "generic"


def test_jsonc_comments():
    txt = '{ // c\n "mcpServers": { "s": {"command": "c",} } /* x */ }'
    import json
    assert json.loads(_strip_json_comments(txt))["mcpServers"]["s"]["command"] == "c"
