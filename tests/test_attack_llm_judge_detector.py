"""Exercises LLMJudgeDetector over a real stdlib HTTP server (no mocking
library, matching this project's existing adapter-test convention), plus the
mandatory fallback-to-literal behavior on judge failure."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from memrot.detectors.literal import LiteralDetector
from memrot.detectors.llm_judge_stub import LLMJudgeDetector, _parse_yes_no
from memrot.models import DetectionChannel


class _JudgeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        user_msg = body["messages"][-1]["content"]
        if "TRIGGER_500" in user_msg:
            self.send_response(500)
            self.end_headers()
            return
        # user_msg is "Marker: <canary>\n\nText:\n<text>\n\nIs the marker...";
        # the marker name itself always appears on the "Marker:" line, so only
        # the "Text:" section tells us whether the target text actually contains it.
        text_section = user_msg.split("Text:\n", 1)[1].rsplit("\n\nIs the marker", 1)[0]
        answer = "YES" if "PRESENT-MARKER" in text_section else "NO"
        reply = {"choices": [{"message": {"role": "assistant", "content": answer}}]}
        payload = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def judge_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JudgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


def test_parse_yes_no_variants():
    assert _parse_yes_no("YES") is True
    assert _parse_yes_no("yes.") is True
    assert _parse_yes_no("No") is False
    with pytest.raises(ValueError):
        _parse_yes_no("unclear")


def test_requires_base_url_and_model():
    with pytest.raises(ValueError, match="requires base_url and model"):
        LLMJudgeDetector()


def test_judge_says_yes_over_real_http(judge_server):
    port = judge_server.server_address[1]
    detector = LLMJudgeDetector(base_url=f"http://127.0.0.1:{port}", model="m")
    result = detector.detect("the response includes PRESENT-MARKER somewhere", "PRESENT-MARKER",
                             DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is True
    assert "llm_judge" in result.detail


def test_judge_says_no_over_real_http(judge_server):
    port = judge_server.server_address[1]
    detector = LLMJudgeDetector(base_url=f"http://127.0.0.1:{port}", model="m")
    result = detector.detect("a completely unrelated response", "PRESENT-MARKER", DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is False


def test_judge_falls_back_to_literal_on_http_failure(judge_server):
    port = judge_server.server_address[1]
    detector = LLMJudgeDetector(base_url=f"http://127.0.0.1:{port}", model="m")
    result = detector.detect("please TRIGGER_500 and also contains PRESENT-MARKER literally",
                             "PRESENT-MARKER", DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is True   # literal fallback found it
    assert "fell back to literal" in result.detail


def test_judge_falls_back_on_malformed_verdict(monkeypatch):
    detector = LLMJudgeDetector(base_url="http://example.invalid", model="m")
    detector.llm.complete = lambda **kw: "I'm not sure, maybe?"
    result = detector.detect("PRESENT-MARKER is right here", "PRESENT-MARKER", DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is True
    assert "fell back to literal" in result.detail


def test_judge_uses_custom_fallback_detector():
    class _AlwaysFalse(LiteralDetector):
        def detect(self, text, canary, channel):
            r = super().detect(text, canary, channel)
            r.canary_present = False
            return r

    detector = LLMJudgeDetector(base_url="http://example.invalid", model="m", fallback=_AlwaysFalse())
    detector.llm.complete = lambda **kw: (_ for _ in ()).throw(RuntimeError("boom"))
    # LLMClientError is what actually gets raised in real usage; simulate via ValueError parse failure instead
    detector.llm.complete = lambda **kw: "garbage"
    result = detector.detect("PRESENT-MARKER here", "PRESENT-MARKER", DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is False


def test_none_text_is_absent_without_calling_the_llm():
    detector = LLMJudgeDetector(base_url="http://example.invalid", model="m")
    calls = []
    detector.llm.complete = lambda **kw: calls.append(1) or "YES"
    result = detector.detect(None, "PRESENT-MARKER", DetectionChannel.RESPONSE_TEXT)
    assert result.canary_present is False
    assert calls == []
