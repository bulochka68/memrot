"""Adapter registry: kind -> adapter class."""
from __future__ import annotations

from typing import Dict, Type

from .base import Adapter, AdapterBinding

_REGISTRY: Dict[str, Type[Adapter]] = {}


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
