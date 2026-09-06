"""Grey-box adapter for an MCP server (streamable-HTTP or stdio).

Minimal JSON-RPC 2.0 client copied in spirit from ``mcp_audit.discovery.introspector``
but **not imported** from it -- this package must stay independent of ``mcp_audit``.
Handshake is lazy (constructor never requires a live server) so JSON config can
instantiate the adapter without a running process.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

from ..models import Principal
from .base import AdapterCapabilities, TargetAdapter
from .openai_compat import credential_for

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-attack", "version": "1.0.0"}
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class _StdioTransport:
    def __init__(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None) -> None:
        exe = shutil.which(command) or command
        merged = dict(os.environ)
        merged.update(env or {})
        self.proc = subprocess.Popen(
            [exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=merged, cwd=cwd, text=True, encoding="utf-8", bufsize=1,
        )
        self._q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._q.put(None)

    def send(self, msg: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("timed out waiting for MCP server response")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


class _HttpTransport:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 20.0) -> None:
        self.url = url
        self.headers = dict(headers or {})
        self.session_id: Optional[str] = None
        self._timeout = timeout
        self._pending: "queue.Queue[Dict[str, Any]]" = queue.Queue()

    def send(self, msg: Dict[str, Any]) -> None:
        body = json.dumps(msg).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                ctype = resp.headers.get("Content-Type", "")
                raw = resp.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code} from {self.url}") from exc
        if not raw.strip():
            return
        if "text/event-stream" in ctype:
            for evt in _parse_sse(raw):
                self._pending.put(evt)
        else:
            self._pending.put(json.loads(raw))

    def recv(self, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            return self._pending.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("timed out waiting for MCP server response")

    def close(self) -> None:
        return None


def _parse_sse(raw: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    data_lines: List[str] = []
    for line in raw.splitlines() + [""]:
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
        elif line == "":
            if data_lines:
                try:
                    out.append(json.loads("\n".join(data_lines)))
                except json.JSONDecodeError:
                    pass
                data_lines = []
    return out


class MCPClientAdapter(TargetAdapter):
    kind = "mcp_client"
    adapter_version = "1.0.0"

    def __init__(self, *, base_url: Optional[str] = None, command: Optional[str] = None,
                 args: Optional[List[str]] = None, timeout: float = 20.0,
                 chat_tool: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None,
                 env: Optional[Dict[str, str]] = None) -> None:
        if not base_url and not command:
            raise ValueError("mcp_client adapter requires base_url (streamable-HTTP) or command (stdio)")
        self.base_url = (base_url or "").rstrip("/")
        self.command = command
        self.args = list(args or [])
        self.timeout = timeout
        self.chat_tool = chat_tool
        self.extra_headers = dict(extra_headers or {})
        self.env = dict(env or {})
        self._transport: Any = None
        self._rpc_id = 0
        self._tools: List[Dict[str, Any]] = []
        self._connected = False

    def _ensure_connected(self, principal: Optional[Principal] = None) -> None:
        if self._connected:
            return
        headers = dict(self.extra_headers)
        if principal is not None:
            try:
                headers["Authorization"] = f"Bearer {credential_for(principal)}"
            except RuntimeError:
                pass
        if self.command:
            self._transport = _StdioTransport(self.command, self.args, env=self.env)
        else:
            self._transport = _HttpTransport(self.base_url, headers=headers, timeout=self.timeout)
        self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self._notify("notifications/initialized")
        listed = self._request("tools/list", {}) or {}
        self._tools = list(listed.get("tools") or [])
        self._connected = True

    def _next_id(self) -> int:
        self._rpc_id += 1
        return self._rpc_id

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        rid = self._next_id()
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._transport.send(msg)
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timeout waiting for {method}")
            resp = self._transport.recv(remaining)
            if resp is None:
                raise RuntimeError(f"MCP server closed during {method}")
            if resp.get("id") != rid:
                continue
            if "error" in resp:
                err = resp["error"] or {}
                raise RuntimeError(str(err.get("message", "rpc error")))
            return resp.get("result")

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._transport.send(msg)

    def _pick_chat_tool(self) -> str:
        if self.chat_tool:
            return self.chat_tool
        preferred = ("chat", "ask", "message", "complete", "talk", "agent")
        names = [t.get("name", "") for t in self._tools]
        for needle in preferred:
            for name in names:
                if needle in name.lower():
                    return name
        if names:
            return names[0]
        raise RuntimeError("mcp_client: server advertised no tools to call")

    def new_session(self, principal: Principal) -> str:
        return f"s-{uuid.uuid4().hex[:12]}"

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        self._ensure_connected(principal)
        tool = self._pick_chat_tool()
        result = self._request("tools/call", {
            "name": tool,
            "arguments": {"message": message, "session_id": session_id},
        })
        if isinstance(result, dict):
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and "text" in first:
                    return str(first["text"])
            if "text" in result:
                return str(result["text"])
            return json.dumps(result, ensure_ascii=False)
        return "" if result is None else str(result)

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            access_profile="grey_box",
            supports_tool_staging=False,
            notes=["MCP handshake is lazy; tool staging is not available unless the server exposes it"],
        )
