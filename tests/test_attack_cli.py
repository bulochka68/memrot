import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_attack.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_ROOT = os.path.join(ROOT, "mcp_attack", "catalog", "prompts")
BENIGN = os.path.join(CATALOG_ROOT, "benign_control")
MEM02 = os.path.join(CATALOG_ROOT, "mem02_global_policy_poisoning")


class _EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        last_message = body["messages"][-1]["content"]
        reply = {"choices": [{"message": {"role": "assistant", "content": f"echo: {last_message}"}}]}
        payload = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


def test_list_catalog_prints_inventory(capsys):
    rc = main(["list-catalog", "--catalog", MEM02])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mem02-explicit-rule" in out
    assert "MEM-02" in out


def test_list_catalog_filters_by_rule_id(capsys):
    rc = main(["list-catalog", "--catalog", MEM02, "--rule-id", "AUTH-02"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mem02-explicit-rule" not in out


def test_validate_catalog_all_shipped_folders_clean(capsys):
    rc = main(["validate-catalog", CATALOG_ROOT])
    assert rc == 0


def test_run_end_to_end_against_in_process_http_target(http_server, monkeypatch, tmp_path, write_json):
    port = http_server.server_address[1]
    monkeypatch.setenv("MCP_ATTACK_CRED_CUS_TEST", "sk-test-cli")
    config_path = write_json("cli_run.config.json", {
        "schema_version": "1.0",
        "target": {"kind": "openai_compat",
                  "binding": {"base_url": f"http://127.0.0.1:{port}", "model": "test-model", "timeout": 5.0}},
        "channels": [{"role": "attacker", "principal": {"principal_id": "1001", "credential_ref": "CUS_TEST"}}],
        "catalog_paths": [BENIGN],
    })
    out_dir = str(tmp_path / "out")
    rc = main(["run", "--config", config_path, "--out", out_dir])
    assert rc == 0
    assert os.path.isfile(os.path.join(out_dir, "run.json"))
    assert os.path.isfile(os.path.join(out_dir, "run.md"))
    assert os.path.isfile(os.path.join(out_dir, "trace.jsonl"))
    with open(os.path.join(out_dir, "run.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    assert len(report["results"]) == 3   # 3 benign_control variants
    assert all(r["verdict"] == "CLEAN" for r in report["results"])


def test_run_missing_config_field_is_a_clean_error(write_json):
    config_path = write_json("bad.config.json", {"schema_version": "1.0", "channels": []})
    assert main(["run", "--config", config_path]) == 4
