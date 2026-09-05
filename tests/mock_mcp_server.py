#!/usr/bin/env python3
"""A tiny stdio MCP server used to test discovery and active probing.

Implements initialize, tools/list and tools/call for a filesystem-like tool
set with a *real* path boundary so boundary probes have something to verify.
"""
import json
import os
import sys

ROOT = os.environ.get("MOCK_ROOT", "/workspace/my-project")

TOOLS = [
    {"name": "read_file", "description": "Read a file from the project.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write a file in the project.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                     "required": ["path", "content"]}},
]


def _inside(path: str) -> bool:
    rp = os.path.realpath(path)
    return rp == os.path.realpath(ROOT) or rp.startswith(os.path.realpath(ROOT) + os.sep)


def handle(msg):
    m = msg.get("method")
    if m == "initialize":
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock", "version": "0"},
                "instructions": "Mock server for audit tests."}
    if m == "tools/list":
        return {"tools": TOOLS}
    if m == "tools/call":
        p = msg.get("params", {})
        name = p.get("name")
        args = p.get("arguments", {})
        path = args.get("path", "")
        if path.endswith("slow.txt"):
            import time
            time.sleep(4)
        if not _inside(path):
            return {"content": [{"type": "text", "text": "denied: path outside root"}], "isError": True}
        if name == "write_file":
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(args.get("content", ""))
            return {"content": [{"type": "text", "text": "ok"}]}
        if name not in ("write_file", "read_file"):
            return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}
        if name == "read_file":
            try:
                with open(path) as fh:
                    return {"content": [{"type": "text", "text": fh.read()}]}
            except OSError as e:
                return {"content": [{"type": "text", "text": str(e)}], "isError": True}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if "id" not in msg:  # notification
            continue
        result = handle(msg)
        resp = {"jsonrpc": "2.0", "id": msg["id"]}
        if result is None:
            resp["error"] = {"code": -32601, "message": "method not found"}
        else:
            resp["result"] = result
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
