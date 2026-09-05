"""Target manifest v2 (TZ §5.1-5.2) and profile loading.

A manifest describes the target identity, the inspection profile, the bound
adapters and the reporting policy.  Secrets are never part of it: adapters
receive *credential binding names* resolved from the environment.

A plain MCP client config is still accepted: it is wrapped into a manifest
with one ``mcp_inventory`` adapter, so the v1 command line keeps working.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import AccessProfile, RunMode, coerce_mode
from .adapters import AdapterBinding
from .discovery.config_parser import looks_like_mcp_config, _strip_json_comments

MANIFEST_SCHEMA_VERSION = "2.0"


@dataclass
class Manifest:
    schema_version: str = MANIFEST_SCHEMA_VERSION
    target: Dict[str, Any] = field(default_factory=dict)
    access_profile: AccessProfile = AccessProfile.GREY_BOX
    mode: RunMode = RunMode.OFFLINE
    required_controls: List[str] = field(default_factory=list)
    profile_ref: Optional[str] = None
    business_policy_ref: Optional[str] = None
    inventory_manifest_ref: Optional[str] = None
    adapters: List[AdapterBinding] = field(default_factory=list)
    reporting: Dict[str, Any] = field(default_factory=dict)
    reproducibility: Dict[str, Any] = field(default_factory=dict)
    fixtures: Dict[str, Any] = field(default_factory=dict)
    base_dir: str = "."
    path: Optional[str] = None
    legacy_wrapped: bool = False
    extensions: Dict[str, Any] = field(default_factory=dict)

    def adapter(self, adapter_id: str) -> Optional[AdapterBinding]:
        for a in self.adapters:
            if a.adapter_id == adapter_id:
                return a
        return None

    def kinds(self) -> List[str]:
        return sorted({a.kind for a in self.adapters})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "target": self.target,
            "inspection": {"access_profile": self.access_profile.value, "mode": self.mode.value,
                           "required_controls": self.required_controls, "profile_ref": self.profile_ref,
                           "business_policy_ref": self.business_policy_ref,
                           "inventory_manifest_ref": self.inventory_manifest_ref},
            "adapters": [{"id": a.adapter_id, "kind": a.kind, "binding": a.binding, "options": a.options} for a in self.adapters],
            "reporting": self.reporting, "reproducibility": self.reproducibility,
            "legacy_wrapped": self.legacy_wrapped, "path": self.path,
        }


def _load_any(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as e:
            raise RuntimeError("PyYAML is required for YAML manifests; use JSON instead") from e
        return yaml.safe_load(text)
    return json.loads(_strip_json_comments(text))


def _check_no_secrets(obj: Any, where: str = "manifest") -> None:
    """Manifests carry references, not secrets (TZ §5.1)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("password", "secret", "token", "api_key", "apikey", "client_secret", "authorization") and isinstance(v, str) and v:
                raise ValueError(f"{where}: secret-like field {k!r} must not be embedded; use a credential binding name")
            _check_no_secrets(v, where)
    elif isinstance(obj, list):
        for v in obj:
            _check_no_secrets(v, where)


def wrap_legacy_config(config_path: str, *, mode: Any = RunMode.OFFLINE, snapshot: Optional[str] = None,
                       context_root: Optional[str] = None, extra_adapters: Optional[List[AdapterBinding]] = None,
                       target_id: Optional[str] = None, access_profile: Any = AccessProfile.GREY_BOX,
                       profile_ref: Optional[str] = None) -> Manifest:
    base = os.path.dirname(os.path.abspath(config_path))
    binding: Dict[str, Any] = {"path": os.path.abspath(config_path)}
    if snapshot:
        binding["snapshot"] = os.path.abspath(snapshot)
    if context_root:
        binding["context_root"] = os.path.abspath(context_root)
    m = Manifest(
        target={"id": target_id or "legacy-mcp-config",
                "build_ref": None, "environment": "unknown",
                "note": "legacy MCP config wrapped into a v2 manifest; target identity/build not declared (pass target_id to set one)"},
        access_profile=AccessProfile(access_profile) if not isinstance(access_profile, AccessProfile) else access_profile,
        mode=coerce_mode(mode),
        adapters=[AdapterBinding(adapter_id="mcp-config", kind="mcp_inventory", binding=binding, base_dir=base)]
                 + list(extra_adapters or []),
        base_dir=base, path=os.path.abspath(config_path), legacy_wrapped=True, profile_ref=profile_ref,
    )
    return m


def load_manifest(path: str, *, mode_override: Optional[Any] = None) -> Manifest:
    data = _load_any(path)
    base = os.path.dirname(os.path.abspath(path))
    if looks_like_mcp_config(data) and "adapters" not in (data if isinstance(data, dict) else {}):
        return wrap_legacy_config(path, mode=mode_override or RunMode.OFFLINE)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: manifest must be a mapping")
    _check_no_secrets(data)
    insp = data.get("inspection") or {}
    adapters: List[AdapterBinding] = []
    for a in data.get("adapters") or []:
        adapters.append(AdapterBinding(adapter_id=a["id"], kind=a["kind"], binding=dict(a.get("binding") or {}),
                                       options=dict(a.get("options") or {}), base_dir=base))
    known = {"schema_version", "target", "inspection", "adapters", "reporting", "reproducibility", "fixtures"}
    m = Manifest(
        schema_version=str(data.get("schema_version") or MANIFEST_SCHEMA_VERSION),
        target=dict(data.get("target") or {}),
        access_profile=AccessProfile(insp.get("access_profile", "grey_box")),
        mode=coerce_mode(mode_override or insp.get("mode", "offline")),
        required_controls=list(insp.get("required_controls") or data.get("required_controls") or []),
        profile_ref=insp.get("profile_ref") or data.get("profile_ref"),
        business_policy_ref=insp.get("business_policy_ref"),
        inventory_manifest_ref=insp.get("inventory_manifest_ref"),
        adapters=adapters, reporting=dict(data.get("reporting") or {}),
        reproducibility=dict(data.get("reproducibility") or {}), fixtures=dict(data.get("fixtures") or {}),
        base_dir=base, path=os.path.abspath(path),
        extensions={k: v for k, v in data.items() if k not in known and k not in ("required_controls", "profile_ref")},
    )
    if m.schema_version != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"{path}: unsupported manifest schema_version {m.schema_version!r} (expected {MANIFEST_SCHEMA_VERSION}); "
                         "unknown versions are not guessed")
    return m


def load_profile(ref: Optional[str], base_dir: str = ".") -> Dict[str, Any]:
    """Load a system profile (JSON/YAML).  Profiles hold system-specific names; rules stay generic."""
    if not ref:
        return {}
    path = ref if os.path.isabs(ref) else os.path.join(base_dir, ref)
    if not os.path.isfile(path):
        # allow bare profile ids resolved from the bundled profiles/ directory
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for cand in (os.path.join(here, "profiles", ref), os.path.join(here, "profiles", ref + ".json")):
            if os.path.isfile(cand):
                path = cand
                break
        else:
            raise FileNotFoundError(f"profile not found: {ref}")
    data = _load_any(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: profile must be a mapping")
    data.setdefault("profile_id", os.path.splitext(os.path.basename(path))[0])
    data["_path"] = os.path.abspath(path)
    return data
