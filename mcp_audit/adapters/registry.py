"""Adapter registry: kind -> adapter class.

Adapters bundled with the package register themselves with :func:`register` on
import.  A stand that needs a source the package does not read (systemd units,
Helm charts, a bespoke policy service) adds one **without patching the package**
(portability P2-6):

* ``python -m mcp_audit audit … --adapter-plugin my_pkg.systemd:SystemdAdapter``;
* ``"adapter_plugins": ["my_pkg.systemd:SystemdAdapter"]`` in the manifest;
* an entry point in the installing distribution::

      [project.entry-points."mcp_audit.adapters"]
      systemd = "my_pkg.systemd:SystemdAdapter"

A plugin that cannot be imported is reported, never ignored: an adapter that is
not there must show up as an unavailable source, not as an empty finding list.
"""
from __future__ import annotations

import importlib
from typing import Dict, List, Optional, Tuple, Type

from .base import Adapter, AdapterBinding

ENTRY_POINT_GROUP = "mcp_audit.adapters"

_REGISTRY: Dict[str, Type[Adapter]] = {}
_LOADED_PLUGINS: Dict[str, str] = {}          # spec -> kind
_ENTRY_POINTS_LOADED = False


def register(cls: Type[Adapter]) -> Type[Adapter]:
    _REGISTRY[cls.kind] = cls
    return cls


def get_adapter(kind: str) -> Type[Adapter]:
    if kind not in _REGISTRY:
        raise KeyError(f"unknown adapter kind {kind!r}; known: {sorted(_REGISTRY)}")
    return _REGISTRY[kind]


def known_kinds() -> list:
    return sorted(_REGISTRY)


def build(binding: AdapterBinding) -> Adapter:
    return get_adapter(binding.kind)(binding)


def load_plugin(spec: str) -> str:
    """Import ``module:Class`` (or ``module``) and register the adapter(s) it defines.

    Returns the kind that became available.  Raises ``ValueError`` with the reason
    when the plugin cannot be imported or is not an adapter.
    """
    spec = str(spec).strip()
    if spec in _LOADED_PLUGINS:
        return _LOADED_PLUGINS[spec]
    module_name, _, attr = spec.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:                     # ImportError and anything the module raises on import
        raise ValueError(f"adapter plugin {spec!r}: {type(exc).__name__}: {exc}") from exc
    if not attr:
        kinds = sorted(k for k, cls in _REGISTRY.items() if getattr(cls, "__module__", "").startswith(module_name))
        if not kinds:
            raise ValueError(f"adapter plugin {spec!r}: the module registered no adapter; "
                             "decorate the class with @register or use 'module:Class'")
        _LOADED_PLUGINS[spec] = ",".join(kinds)
        return _LOADED_PLUGINS[spec]
    cls = getattr(module, attr, None)
    if cls is None:
        raise ValueError(f"adapter plugin {spec!r}: {attr!r} not found in {module_name}")
    if not (isinstance(cls, type) and issubclass(cls, Adapter)):
        raise ValueError(f"adapter plugin {spec!r}: {attr!r} is not a subclass of mcp_audit.adapters.base.Adapter")
    if not getattr(cls, "kind", None) or cls.kind == Adapter.kind:
        raise ValueError(f"adapter plugin {spec!r}: the class must declare a non-abstract 'kind'")
    register(cls)
    _LOADED_PLUGINS[spec] = cls.kind
    return cls.kind


def load_plugins(specs) -> Tuple[List[str], List[str]]:
    """Load several plugins; returns ``(kinds, problems)`` instead of raising."""
    kinds: List[str] = []
    problems: List[str] = []
    for spec in specs or []:
        try:
            kinds.append(load_plugin(spec))
        except ValueError as exc:
            problems.append(str(exc))
    return kinds, problems


def load_entry_point_plugins(group: str = ENTRY_POINT_GROUP, force: bool = False) -> Tuple[List[str], List[str]]:
    """Register adapters published by installed distributions under ``group``."""
    global _ENTRY_POINTS_LOADED
    if _ENTRY_POINTS_LOADED and not force:
        return [], []
    _ENTRY_POINTS_LOADED = True
    kinds: List[str] = []
    problems: List[str] = []
    try:
        from importlib.metadata import entry_points
        try:
            found = list(entry_points(group=group))
        except TypeError:                         # Python < 3.10 API
            found = list((entry_points() or {}).get(group, []))
    except Exception as exc:                      # pragma: no cover - metadata backend problem
        return [], [f"entry point group {group!r} could not be read: {type(exc).__name__}: {exc}"]
    for ep in found:
        try:
            kinds.append(load_plugin(ep.value))
        except ValueError as exc:
            problems.append(f"entry point {getattr(ep, 'name', '?')}: {exc}")
    return kinds, problems
