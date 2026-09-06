#!/usr/bin/env python3
"""Снимок MCP-инвентаря стенда DVAA для аудитора (stdlib-only).

Зачем нужен: MCP-агенты DVAA отвечают только на ``tools/list`` и ``tools/call``;
метода ``initialize`` у них нет, поэтому штатный live-хендшейк аудитора
(``--mode live-inventory``) обрывается на первом же запросе и даёт
``handshake: unavailable``, 0 инструментов. Скрипт делает то, что аудитору
сделать нечем: сам вызывает ``tools/list`` и сохраняет результат как
*снимок* — с временем съёма и идентичностью, под которой он снят.

Пишет два файла:
  * ``<out>/dvaa.config.json``          — клиентский MCP-конфиг (url + x_audit);
  * ``<out>/dvaa.tools.snapshot.json``  — снимок ``tools/list`` по каждому серверу.

Манифест привязывает их к адаптеру ``mcp_inventory`` как ``path`` + ``snapshot``
при ``live: false``: конфиг остаётся конфигом, снимок — снимком, и ни то ни
другое не выдаётся за успешный хендшейк (INV-02).

  python3 scripts/capture_dvaa_inventory.py --base-url http://localhost -o examples
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

# MCP-агенты стенда: порт -> имя сервера в инвентаре и ожидаемая политика (x_audit).
MCP_AGENTS = {
    7010: {"name": "toolbot", "kind": "shell",
           "x_audit": {"kind": "shell", "network_access": True,
                       "note": "read_file/write_file/execute/fetch_url над песочницей стенда"}},
    7011: {"name": "databot", "kind": "postgres",
           "x_audit": {"kind": "postgres", "operations": ["SELECT"], "ddl": False,
                       "note": "имитация SQL-бэкенда; ответы синтетические"}},
    7012: {"name": "pluginbot", "kind": "generic",
           "x_audit": {"kind": "generic", "network_access": True,
                       "note": "принимает регистрацию инструментов из внешнего реестра"}},
    7013: {"name": "proxybot", "kind": "generic",
           "x_audit": {"kind": "generic", "network_access": True,
                       "note": "проксирует вызовы к апстриму; разрешение инструмента по имени"}},
}


def rpc(url: str, method: str, params: dict | None = None, timeout: float = 10.0) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("DVAA_URL", "http://localhost"),
                    help="базовый адрес стенда без порта (по умолчанию http://localhost)")
    ap.add_argument("--port-offset", type=int, default=int(os.environ.get("HOST_PORT_OFFSET", "0")),
                    help="смещение портов, если стенд запущен с HOST_PORT_OFFSET")
    ap.add_argument("-o", "--out-dir", default="examples", help="каталог для двух выходных файлов")
    ap.add_argument("--identity", default="anonymous (стенд не требует аутентификации)",
                    help="под какой идентичностью снят инвентарь — попадает в снимок")
    args = ap.parse_args()

    captured_at = time.time()
    config: dict = {"mcpServers": {}}
    snapshot: dict = {}
    failures = 0

    for port, meta in MCP_AGENTS.items():
        host_port = port + args.port_offset
        url = f"{args.base_url}:{host_port}/"
        entry = {"url": url, "transport": "http", "x_audit": dict(meta["x_audit"])}
        try:
            res = rpc(url, "tools/list")
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
            print(f"[!] {meta['name']} ({url}): {type(e).__name__}: {e}")
            failures += 1
            config["mcpServers"][meta["name"]] = entry
            continue

        if "error" in res:
            print(f"[!] {meta['name']}: tools/list -> {res['error']}")
            failures += 1
            config["mcpServers"][meta["name"]] = entry
            continue

        tools = (res.get("result") or {}).get("tools") or []
        entry["tools"] = tools
        config["mcpServers"][meta["name"]] = entry
        snapshot[meta["name"]] = {
            "tools": tools,
            "capabilities": {"tools": True, "resources": False, "prompts": False},
            "captured_at": captured_at,
            "identity": args.identity,
            "origin": f"tools/list на {url} (без initialize: метод не реализован стендом)",
        }
        print(f"[ok] {meta['name']:10} {len(tools)} инструмент(ов) с {url}")

    os.makedirs(args.out_dir, exist_ok=True)
    cfg_path = os.path.join(args.out_dir, "dvaa.config.json")
    snap_path = os.path.join(args.out_dir, "dvaa.tools.snapshot.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    with open(snap_path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"\nконфиг:  {cfg_path}\nснимок:  {snap_path}")
    if failures:
        print(f"\n{failures} сервер(ов) не ответили: снимок неполный, INV-02 увидит это как partial")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
