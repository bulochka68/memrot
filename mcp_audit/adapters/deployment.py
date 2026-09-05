"""Deployment adapter: network rules, service rights and storage configuration.

Reads a docker-compose file (PyYAML) or a JSON snapshot
``{"services": {name: {"image", "ports", "environment", "command", "depends_on"}}}``.
It records *bind / publication* facts; it never assumes that a published port
is reachable from the internet - reachability is confirmed per zone (TZ §5.3,
INFRA-02).  Environment *values* are never stored, only key names.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Dict, List, Optional

from ..models import AuditDocument, Method, SourceType
from ..evidence import EvidenceStore
from .base import Adapter, AdapterResult
from .registry import register

STORAGE_IMAGES = {"redis": "redis", "mongo": "mongodb", "postgres": "postgres", "mysql": "mysql",
                  "elasticsearch": "elasticsearch", "qdrant": "vector", "weaviate": "vector", "milvus": "vector",
                  "chroma": "vector", "pgvector": "postgres"}


def _parse_port(p: Any) -> Dict[str, Any]:
    if isinstance(p, dict):
        return {"host_ip": p.get("host_ip"), "published": str(p.get("published")), "target": str(p.get("target")),
                "protocol": p.get("protocol", "tcp")}
    s = str(p)
    proto = "tcp"
    if "/" in s:
        s, proto = s.split("/", 1)
    parts = s.split(":")
    if len(parts) == 3:
        return {"host_ip": parts[0], "published": parts[1], "target": parts[2], "protocol": proto}
    if len(parts) == 2:
        return {"host_ip": None, "published": parts[0], "target": parts[1], "protocol": proto}
    return {"host_ip": None, "published": None, "target": parts[0], "protocol": proto}


def _env_keys(env: Any) -> List[str]:
    if isinstance(env, dict):
        return sorted(str(k) for k in env)
    if isinstance(env, list):
        return sorted(str(e).split("=", 1)[0] for e in env)
    return []


def _storage_auth(kind: Optional[str], env_keys: List[str], command: Any) -> Dict[str, Any]:
    cmd = " ".join(command) if isinstance(command, list) else str(command or "")
    if kind == "redis":
        if "--requirepass" in cmd or any(k in ("REDIS_PASSWORD", "REDIS_ARGS", "REDIS_REQUIREPASS") for k in env_keys):
            return {"auth": True, "basis": "requirepass / password env present"}
        return {"auth": None, "basis": "authentication not shown in this configuration"}
    if kind == "mongodb":
        if any(k in ("MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD") for k in env_keys) or "--auth" in cmd:
            return {"auth": True, "basis": "root credentials / --auth present"}
        return {"auth": None, "basis": "authentication not shown in this configuration"}
    if kind in ("postgres", "mysql"):
        if any(k in ("POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD") for k in env_keys):
            return {"auth": True, "basis": "password env present"}
        return {"auth": None, "basis": "authentication not shown in this configuration"}
    return {"auth": None, "basis": "not a known storage image"}


@register
class DeploymentAdapter(Adapter):
    kind = "deployment"
    adapter_version = "2.0.0"
    supported = ["compose_services", "published_ports", "env_key_names", "storage_auth_hints", "depends_on"]
    unsupported = {
        "reachability": "a published port is not assumed reachable from any zone; reachability needs a zone-specific observation",
        "runtime_rights": "database privileges of running services are not queried",
        "env_values": "environment values are never read into the report",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        path = self.binding.path("path")
        if not path or not os.path.isfile(path):
            return AdapterResult(self.status("unavailable", [f"deployment snapshot not found: {path}"]))
        try:
            data = self._read_json(path)
        except RuntimeError as e:
            return AdapterResult(self.status("unavailable", [str(e)]))
        services = (data or {}).get("services") or {}
        with open(path, "rb") as fh:
            dg = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        out: Dict[str, Any] = {"source": os.path.relpath(path), "services": {}, "volumes": sorted((data or {}).get("volumes") or {})}
        count = 0
        for name, svc in services.items():
            svc = svc or {}
            image = str(svc.get("image") or "")
            kind = None
            for key, k in STORAGE_IMAGES.items():
                if key in image or key in name:
                    kind = k
                    break
            ports = [_parse_port(p) for p in (svc.get("ports") or [])]
            env_keys = _env_keys(svc.get("environment"))
            rec = {
                "image": image or None, "build": bool(svc.get("build")), "storage_kind": kind,
                "published_ports": ports,
                "host_published": [p for p in ports if p["published"]],
                "loopback_only": all(p.get("host_ip") in ("127.0.0.1", "::1", "localhost") for p in ports if p["published"]) if ports else None,
                "env_keys": env_keys,
                "depends_on": sorted((svc.get("depends_on") or {}).keys()) if isinstance(svc.get("depends_on"), dict) else list(svc.get("depends_on") or []),
                "storage_auth": _storage_auth(kind, env_keys, svc.get("command")) if kind else None,
                "networks": sorted(svc.get("networks") or []) if isinstance(svc.get("networks"), (list, dict)) else [],
            }
            ev = store.add(SourceType.DEPLOYMENT_SNAPSHOT, Method.PARSING,
                           {"path": os.path.relpath(path), "service": name}, digest=dg, adapter=self.kind,
                           adapter_version=self.adapter_version,
                           summary=f"service {name}: image={image or 'build'}, published={[p['published'] for p in ports if p['published']]}",
                           limitations=["bind/publication only; reachability per network zone not established"])
            rec["evidence_ref"] = ev.evidence_id
            out["services"][name] = rec
            count += 1
        doc.deployment = out
        return AdapterResult(self.status("available" if services else "partial",
                                         [] if services else ["no services found"], evidence_count=count))
