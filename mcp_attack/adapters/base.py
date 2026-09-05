"""Target adapter contract.

The core engine (``runner/engine.py``) knows nothing about any specific
target: it only calls these methods.  A new system needs one adapter of
~40-100 lines; the attack catalogue, detectors and verdict logic are reused
unchanged.  This is the same "universal core, thin adapter" split garak
("generators") and promptfoo ("providers") use.

Only ``new_session`` and ``send`` are required.  Everything else has a
no-op / unsupported default so an adapter can start minimal and grow.
``capabilities()`` lets the runner degrade gracefully (``NOT_EVALUATED``,
never a crash) when a catalog variant asks for more than the bound adapter
can give -- mirroring ``mcp_audit``'s NOT_EVALUATED/NOT_APPLICABLE philosophy
for missing sources.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, List, Optional

from ..models import Principal


@dataclass
class AdapterCapabilities:
    access_profile: str = "black_box"        # black_box | grey_box | white_box -- ceiling this instance can serve
    supports_consolidate: bool = False
    supports_inspect_memory: bool = False
    supports_ground_truth: bool = False
    supports_reset: bool = False
    notes: List[str] = field(default_factory=list)


class TargetAdapter(abc.ABC):
    kind: str = "abstract"
    adapter_version: str = "0.1.0"

    @abc.abstractmethod
    def new_session(self, principal: Principal) -> str:
        """Start a fresh conversation as ``principal``; return an opaque session id."""
        raise NotImplementedError

    @abc.abstractmethod
    def send(self, principal: Principal, session_id: str, message: str) -> str:
        """Send one turn; return the assistant's response text."""
        raise NotImplementedError

    def consolidate(self, principal: Principal, session_id: str) -> None:
        """Force the target to write memory now.  No-op default: systems that
        consolidate automatically need not override this."""
        return None

    def inspect_memory(self, principal: Principal) -> Optional[str]:
        """Direct, white-box read of the principal's memory state as text.
        Returns ``None`` when this channel is not available (black-box)."""
        return None

    def ground_truth_check(self, marker: str, **kwargs: Any) -> Optional[bool]:
        """An objective, out-of-band signal independent of what the model
        *said* -- e.g. a backend access log grep. Returns ``None`` when this
        channel is not available."""
        return None

    def reset(self) -> bool:
        """Clear all target state between full runs. Returns False when
        unsupported (the mandatory per-variant baseline phase is then the
        cross-run contamination safety net)."""
        return False

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(access_profile="black_box")
