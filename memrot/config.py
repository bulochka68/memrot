"""Run configuration: target binding + channels + catalog + detector + generator.

Credentials are never embedded here -- only a ``credential_ref`` per
principal, resolved at adapter-call time from ``MEMROT_CRED_<ref>``
(mirrors ``mcp_audit``'s ``MCP_AUDIT_CRED_<NAME>`` convention). JSON is the
primary format; YAML is accepted when PyYAML is installed, same optional-dep
pattern as ``mcp_audit.manifest``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Channel, ChannelRole, Principal

CONFIG_SCHEMA_VERSION = "1.0"


@dataclass
class TargetBinding:
    kind: str
    binding: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectorBinding:
    kind: str = "literal"
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratorBinding:
    kind: str = "static_catalog"
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunConfig:
    target: TargetBinding
    channels: List[Channel]
    schema_version: str = CONFIG_SCHEMA_VERSION
    access_profile: str = "black_box"
    detector: DetectorBinding = field(default_factory=DetectorBinding)
    catalog_paths: List[str] = field(default_factory=list)
    generator: GeneratorBinding = field(default_factory=GeneratorBinding)
    reset_between_variants: bool = False
    audit_path: Optional[str] = None
    audit_mode: str = "filter"
    reporting: Dict[str, Any] = field(default_factory=lambda: {"formats": ["json", "markdown"]})
    base_dir: str = "."

    def channels_by_role(self, role: str) -> List[Channel]:
        return [c for c in self.channels if c.role.value == role]

    def resolve_catalog_paths(self) -> List[str]:
        out = []
        for p in self.catalog_paths:
            out.append(p if os.path.isabs(p) else os.path.normpath(os.path.join(self.base_dir, p)))
        return out


def _check_no_secrets(obj: Any, where: str = "config") -> None:
    """Same rule as mcp_audit.manifest._check_no_secrets: configs carry
    credential *references*, never raw secrets."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("password", "secret", "token", "api_key", "apikey", "client_secret", "authorization") \
                    and isinstance(v, str) and v:
                raise ValueError(f"{where}: secret-like field {k!r} must not be embedded; use a credential_ref instead")
            _check_no_secrets(v, where)
    elif isinstance(obj, list):
        for v in obj:
            _check_no_secrets(v, where)


def _load_any(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for YAML configs; use JSON instead") from exc
        return yaml.safe_load(text)
    return json.loads(text)


def _parse_channel(d: Dict[str, Any]) -> Channel:
    p = d.get("principal") or {}
    principal = Principal(
        principal_id=str(p["principal_id"]),
        credential_ref=p.get("credential_ref"),
        label=p.get("label", ""),
        metadata=dict(p.get("metadata") or {}),
    )
    return Channel(role=ChannelRole(d["role"]), principal=principal, channel_id=d.get("channel_id", ""))


def load_config(path: str) -> RunConfig:
    data = _load_any(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: config must be a mapping")
    _check_no_secrets(data, where=path)

    schema_version = str(data.get("schema_version") or CONFIG_SCHEMA_VERSION)
    if schema_version != CONFIG_SCHEMA_VERSION:
        raise ValueError(f"{path}: unsupported config schema_version {schema_version!r} (expected {CONFIG_SCHEMA_VERSION})")

    target_d = data.get("target")
    if not target_d or "kind" not in target_d:
        raise ValueError(f"{path}: target.kind is required")
    target = TargetBinding(kind=target_d["kind"], binding=dict(target_d.get("binding") or {}),
                           options=dict(target_d.get("options") or {}))

    channels_d = data.get("channels") or []
    if not channels_d:
        raise ValueError(f"{path}: at least one channel is required")
    channels = [_parse_channel(c) for c in channels_d]

    det_d = data.get("detector") or {}
    detector = DetectorBinding(kind=det_d.get("kind", "literal"), options=dict(det_d.get("options") or {}))

    gen_d = data.get("generator") or {}
    generator = GeneratorBinding(kind=gen_d.get("kind", "static_catalog"), options=dict(gen_d.get("options") or {}))

    base_dir = os.path.dirname(os.path.abspath(path))
    return RunConfig(
        target=target, channels=channels, schema_version=schema_version,
        access_profile=data.get("access_profile", "black_box"),
        detector=detector, catalog_paths=list(data.get("catalog_paths") or []),
        generator=generator, reset_between_variants=bool(data.get("reset_between_variants", False)),
        audit_path=data.get("audit_path"), audit_mode=data.get("audit_mode", "filter"),
        reporting=dict(data.get("reporting") or {"formats": ["json", "markdown"]}),
        base_dir=base_dir,
    )
