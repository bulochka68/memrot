"""Exercises the real urllib-based adapter against a stdlib HTTP server --
no Docker, no third-party HTTP library."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from memrot.adapters.openai_compat import OpenAICompatAdapter
from memrot.models import Principal


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 -- silence test server logging
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_response(401)
            self.end_headers()
            return
        last_message = body["messages"][-1]["content"]
        if "TRIGGER_500" in last_message:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"simulated server error")
            return
        reply = {"choices": [{"message": {"role": "assistant", "content": f"echo: {last_message}"}}]}
        payload = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


def test_send_round_trip_over_real_http(http_server, monkeypatch):
    port = http_server.server_address[1]
    monkeypatch.setenv("MEMROT_CRED_TESTKEY", "sk-test-123")
    adapter = OpenAICompatAdapter(base_url=f"http://127.0.0.1:{port}", model="test-model", timeout=5.0)
    principal = Principal(principal_id="1001", credential_ref="TESTKEY")
    session_id = adapter.new_session(principal)
    assert adapter.send(principal, session_id, "hello canary") == "echo: hello canary"


def test_missing_credential_raises_before_any_network_call(http_server):
    port = http_server.server_address[1]
    adapter = OpenAICompatAdapter(base_url=f"http://127.0.0.1:{port}", model="test-model")
    principal = Principal(principal_id="9999", credential_ref="DEFINITELY_MISSING_CRED")
    with pytest.raises(RuntimeError, match="missing credential"):
        adapter.send(principal, "s1", "hi")


def test_http_error_is_wrapped_as_runtime_error(http_server, monkeypatch):
    port = http_server.server_address[1]
    monkeypatch.setenv("MEMROT_CRED_TESTKEY2", "sk-test-456")
    adapter = OpenAICompatAdapter(base_url=f"http://127.0.0.1:{port}", model="test-model", timeout=5.0)
    principal = Principal(principal_id="1002", credential_ref="TESTKEY2")
    with pytest.raises(RuntimeError, match="HTTP 500"):
        adapter.send(principal, "s1", "please TRIGGER_500 now")


def test_capabilities_are_black_box_only():
    adapter = OpenAICompatAdapter(base_url="http://example.invalid/v1", model="m")
    caps = adapter.capabilities()
    assert caps.access_profile == "black_box"
    assert not caps.supports_inspect_memory
    assert not caps.supports_ground_truth
