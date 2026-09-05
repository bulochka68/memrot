"""End-to-end active probing against the bundled mock stdio MCP server."""
import os
import shutil
import pytest

from mcp_audit.discovery import parse_config
from mcp_audit.discovery.introspector import introspect_server
from mcp_audit.orchestrator import Orchestrator
from mcp_audit.active import IsolationGuard
from mcp_audit.models import Mode, TestResult

HERE = os.path.dirname(os.path.abspath(__file__))
MOCK = os.path.join(HERE, "mock_mcp_server.py")


@pytest.fixture()
def mock_config(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("MOCK_ROOT", str(root))
    monkeypatch.setenv("MCP_AUDIT_SANDBOX", "1")
    servers = parse_config({"mcpServers": {"filesystem": {
        "command": "python3", "args": [MOCK], "env": {"MOCK_ROOT": str(root)},
        "x_audit": {"kind": "filesystem", "allowed_paths": [str(root) + "/**"]},
    }}})
    return servers, str(root)


def test_live_discovery(mock_config):
    servers, _ = mock_config
    introspect_server(servers[0], timeout=15)
    assert servers[0].handshake.ok
    assert {t.name for t in servers[0].tools} == {"read_file", "write_file"}
    assert servers[0].handshake.instructions


def test_active_probes_verify_boundaries(mock_config):
    servers, _ = mock_config
    orch = Orchestrator(Mode.ACTIVE)
    doc = orch.discover(servers, live=True, timeout=15)
    orch.run(doc, guard=IsolationGuard(sandbox=True), timeout=15)
    by_id = {t.id: t for t in doc.tests}
    assert by_id["FS-WRITE-INSIDE"].result == TestResult.PASS
    assert by_id["FS-TRAVERSAL"].result == TestResult.BLOCKED
    assert by_id["FS-TRAVERSAL"].boundary_holds
    assert by_id["FS-READ-SECRET"].result == TestResult.BLOCKED
    # tools got verified
    verified = {t.name: t.verified for t in doc.servers[0].tools}
    assert verified["write_file"] is True
    assert verified["read_file"] is True
