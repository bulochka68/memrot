"""MCP introspector: performs the handshake and enumerates tools/resources/prompts.

Stdlib-only JSON-RPC 2.0 client for two transports:
  * stdio          - spawns the server, newline-delimited JSON on stdin/stdout
  * http / sse     - Streamable HTTP (POST JSON-RPC, JSON or SSE response)

Only ``initialize``, ``notifications/initialized``, ``tools/list``,
``resources/list`` and ``prompts/list`` are used in discovery.  ``tools/call``
is exposed for the controlled-validation layer only.

Execution rules (TZ §14):
  * offline mode never reaches this module - the orchestrator only calls it in
    ``live_inventory`` / ``controlled_validation`` modes;
  * a spawned stdio server receives a *minimal* environment (an allow-list plus
    the env explicitly given in the config), not the auditor's full environment;
  * a live inventory is "not without impact": stdio spawns a process and a
    network handshake reveals itself; the handshake records identity, time and
    completeness so the snapshot context is comparable later.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from ..models import ServerRecord, ToolDefinition, ToolRecord, Handshake

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-audit", "version": "2.0.0"}

# Minimal environment handed to spawned stdio servers.
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT",
                 "SystemRoot", "COMSPEC", "PATHEXT", "USERPROFILE", "TERM", "PYTHONIOENCODING")
MAX_PAGES = 100
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def minimal_env(explicit: Optional[Dict[str, str]] = None, extra_allow: Optional[List[str]] = None) -> Dict[str, str]:
    env: Dict[str, str] = {}
    allow = set(ENV_ALLOWLIST) | set(extra_allow or [])
    for k in allow:
        if k in os.environ:
            env[k] = os.environ[k]
    env.update(explicit or {})
    return env


class MCPError(RuntimeError):
    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class _StdioTransport:
    def __init__(self, command: str, args: List[str], env: Dict[str, str], cwd: Optional[str] = None,
                 env_allow: Optional[List[str]] = None):
        exe = shutil.which(command) or command
        self.proc = subprocess.Popen(
            [exe, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=minimal_env(env, env_allow),
            cwd=cwd,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._stderr: List[str] = []
        self._bytes = 0
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._err_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._err_reader.start()

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._bytes += len(line)
            if self._bytes > MAX_RESPONSE_BYTES:
                self._stderr.append("[audit] response size limit exceeded; stopping reader")
                break
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                self._stderr.append(f"[non-json stdout] {line[:200]}")
        self._q.put(None)

    def _pump_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip())
            if len(self._stderr) > 200:
                del self._stderr[:-200]

    def send(self, msg: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float) -> Optional[Dict[str, Any]]:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("timed out waiting for MCP server response")

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr[-20:])

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
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = dict(headers or {})
        self.session_id: Optional[str] = None
        self._pending: "queue.Queue[Dict[str, Any]]" = queue.Queue()

    _timeout = 20.0

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
                raw = resp.read(MAX_RESPONSE_BYTES + 1).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise MCPError(f"HTTP {e.code} from {self.url}", code=e.code)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MCPError("response size limit exceeded")
        if not raw.strip():
            return  # notification accepted (202)
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

    stderr_tail = ""

    def close(self) -> None:
        pass


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


class Introspector:
    """A minimal MCP client.  Use as a context manager."""

    def __init__(self, server: ServerRecord, timeout: float = 20.0, cwd: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None, env_allow: Optional[List[str]] = None,
                 max_operations: int = 500):
        self.server = server
        self.timeout = timeout
        self.cwd = cwd
        self.headers = headers
        self.env_allow = env_allow
        self.max_operations = max_operations
        self._ops = 0
        self._id = 0
        self._transport: Any = None
        self.initialize_result: Dict[str, Any] = {}
        self.pagination_notes: List[str] = []

    def __enter__(self) -> "Introspector":
        s = self.server
        if s.transport == "stdio":
            if not s.command:
                raise MCPError("stdio server without a command")
            self._transport = _StdioTransport(s.command, s.args, s.env, cwd=self.cwd, env_allow=self.env_allow)
        else:
            if not s.url:
                raise MCPError(f"{s.transport} server without a url")
            headers = {k[len("header:"):]: v for k, v in s.env.items() if k.lower().startswith("header:")}
            headers.update(self.headers or {})
            self._transport = _HttpTransport(s.url, headers)
            self._transport._timeout = self.timeout
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._transport:
            self._transport.close()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._ops += 1
        if self._ops > self.max_operations:
            raise MCPError("operation budget exceeded")
        self._id += 1
        rid = self._id
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
                raise MCPError(f"server closed the connection during {method}; stderr: {self._transport.stderr_tail}")
            if resp.get("id") != rid:
                continue
            if "error" in resp:
                err = resp["error"] or {}
                raise MCPError(str(err.get("message", "rpc error")), err.get("code"), err.get("data"))
            return resp.get("result")

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._transport.send(msg)

    def initialize(self) -> Dict[str, Any]:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self.initialize_result = result or {}
        self.notify("notifications/initialized")
        return self.initialize_result

    def _list_all(self, method: str, key: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        seen_names: Dict[str, int] = {}
        for page in range(MAX_PAGES):
            params = {"cursor": cursor} if cursor else None
            res = self.request(method, params) or {}
            batch = res.get(key) or []
            for it in batch:
                n = it.get("name") or it.get("uri")
                if n in seen_names:
                    self.pagination_notes.append(f"{method}: '{n}' repeated across pages (catalog changed during traversal?)")
                seen_names[n] = seen_names.get(n, 0) + 1
            items.extend(batch)
            cursor = res.get("nextCursor")
            if not cursor:
                break
        else:
            self.pagination_notes.append(f"{method}: pagination stopped after {MAX_PAGES} pages; listing may be partial")
        return items

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._list_all("tools/list", "tools")

    def list_resources(self) -> List[Dict[str, Any]]:
        return self._list_all("resources/list", "resources")

    def list_prompts(self) -> List[Dict[str, Any]]:
        return self._list_all("prompts/list", "prompts")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """CONTROLLED VALIDATION ONLY.  Callers must go through the isolation guard."""
        return self.request("tools/call", {"name": name, "arguments": arguments}) or {}


def introspect_server(server: ServerRecord, timeout: float = 20.0, cwd: Optional[str] = None,
                      identity: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                      env_allow: Optional[List[str]] = None) -> ServerRecord:
    """Run the live handshake and fill declared capabilities, tools, resources, prompts.

    The result is the catalogue *advertised to this identity at this moment*;
    absence of a tool here does not prove its absence for another role.
    """
    started = time.time()
    try:
        with Introspector(server, timeout=timeout, cwd=cwd, headers=headers, env_allow=env_allow) as client:
            init = client.initialize()
            caps = init.get("capabilities") or {}
            server.declared_capabilities = {
                "tools": "tools" in caps,
                "resources": "resources" in caps,
                "prompts": "prompts" in caps,
                "logging": "logging" in caps,
                "raw": caps,
            }
            hs = Handshake(
                performed=True, ok=True,
                protocol_version=init.get("protocolVersion"),
                server_info=init.get("serverInfo") or {},
                instructions=init.get("instructions"),
                source="live", captured_at=started, identity=identity, completeness="complete",
            )
            tools: List[Dict[str, Any]] = []
            partial = False
            if "tools" in caps or not caps:
                try:
                    tools = client.list_tools()
                except MCPError as e:
                    hs.error = f"tools/list: {e}"
                    partial = True
            server.tools = [ToolRecord(server=server.name, definition=ToolDefinition.from_mcp(t)) for t in tools]
            if "resources" in caps:
                try:
                    server.resources = client.list_resources()
                except MCPError as e:
                    hs.notes.append(f"resources/list failed: {e}")
                    partial = True
            if "prompts" in caps:
                try:
                    server.prompts = client.list_prompts()
                except MCPError as e:
                    hs.notes.append(f"prompts/list failed: {e}")
                    partial = True
            hs.notes.extend(client.pagination_notes)
            if partial or client.pagination_notes:
                hs.completeness = "partial"
            server.handshake = hs
            server.inventory_sources["live_advertised"] = {
                "count": len(server.tools), "identity": identity, "captured_at": started,
                "completeness": hs.completeness, "protocol_version": hs.protocol_version,
            }
    except (MCPError, TimeoutError, OSError, ValueError) as e:
        server.handshake = Handshake(performed=True, ok=False, error=f"{type(e).__name__}: {e}", source="live",
                                     captured_at=started, identity=identity, completeness="unavailable")
        server.inventory_sources["live_advertised"] = {"count": None, "completeness": "unavailable",
                                                       "error": f"{type(e).__name__}: {e}"}
    return server


def apply_snapshot(server: ServerRecord, snap: Dict[str, Any]) -> ServerRecord:
    """Fill a server from an offline snapshot of an earlier handshake (not a live one)."""
    server.tools = [ToolRecord(server=server.name, definition=ToolDefinition.from_mcp(t)) for t in snap.get("tools", [])]
    server.resources = list(snap.get("resources", []))
    server.prompts = list(snap.get("prompts", []))
    if snap.get("capabilities"):
        server.declared_capabilities = dict(snap["capabilities"])
    else:
        server.declared_capabilities = {"tools": bool(server.tools), "resources": bool(server.resources),
                                        "prompts": bool(server.prompts)}
    captured_at = snap.get("captured_at")
    stale = "unknown"
    if isinstance(captured_at, (int, float)):
        stale = "stale" if time.time() - captured_at > 30 * 86400 else "complete"
    server.handshake = Handshake(performed=False, ok=None, source="snapshot", instructions=snap.get("instructions"),
                                 server_info=snap.get("server_info") or {}, captured_at=captured_at,
                                 identity=snap.get("identity"), completeness=stale,
                                 notes=[f"inventory replayed from snapshot ({snap.get('origin', 'snapshot file')})"])
    server.inventory_sources["snapshot"] = {"count": len(server.tools), "captured_at": captured_at,
                                            "identity": snap.get("identity"), "completeness": stale}
    return server
