"""Build a TargetAdapter from a config-declared TargetBinding.

``CallableAdapter`` is deliberately not registered here: it needs live Python
callables, which a JSON config cannot express. Build it directly in code
(e.g. for tests) instead.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .base import TargetAdapter
from .genai_invest import GenAIInvestAdapter
from .openai_compat import OpenAICompatAdapter

if TYPE_CHECKING:
    from ..config import TargetBinding

_REGISTRY = {
    "openai_compat": OpenAICompatAdapter,
    "genai_invest": GenAIInvestAdapter,
}


def build_adapter(target: "TargetBinding") -> TargetAdapter:
    cls = _REGISTRY.get(target.kind)
    if cls is None:
        raise ValueError(f"unknown target.kind {target.kind!r}; known kinds: {sorted(_REGISTRY)}")
    kwargs = dict(target.binding)
    kwargs.update(target.options)
    return cls(**kwargs)
