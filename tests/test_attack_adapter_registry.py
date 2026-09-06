from mcp_attack.adapters.mcp_client import MCPClientAdapter
from mcp_attack.adapters.openai_compat import HTTPGenericAdapter, OpenAICompatAdapter
from mcp_attack.adapters.registry import build_adapter
from mcp_attack.config import TargetBinding


def test_build_adapter_constructs_openai_compat():
    adapter = build_adapter(TargetBinding(kind="openai_compat",
                                          binding={"base_url": "http://example.invalid/v1", "model": "m"}))
    assert isinstance(adapter, OpenAICompatAdapter)
    assert adapter.kind == "openai_compat"


def test_build_adapter_constructs_http_generic():
    adapter = build_adapter(TargetBinding(
        kind="http_generic",
        binding={"base_url": "http://example.invalid", "model": "m"},
        options={"response_path": "reply.text", "messages_field": "turns", "session_in_body": True,
                 "chat_path": "/v1/ask"},
    ))
    assert isinstance(adapter, HTTPGenericAdapter)
    assert adapter.kind == "http_generic"
    assert adapter.response_path == "reply.text"
    assert adapter.chat_path == "/v1/ask"


def test_build_adapter_constructs_mcp_client_without_connecting():
    adapter = build_adapter(TargetBinding(kind="mcp_client",
                                          binding={"base_url": "http://example.invalid/mcp"}))
    assert isinstance(adapter, MCPClientAdapter)
    assert adapter.kind == "mcp_client"
    assert adapter.capabilities().access_profile == "grey_box"
    assert adapter.capabilities().supports_tool_staging is False


def test_http_generic_extracts_custom_response_path():
    adapter = HTTPGenericAdapter(base_url="http://example.invalid", response_path="data.0.text")
    assert adapter._extract_content({"data": [{"text": "hello"}]}) == "hello"
