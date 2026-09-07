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
    supports_tool_staging: bool = False
    supports_document_ingestion: bool = False
    supported_tool_vectors: List[str] = field(default_factory=list)
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

    def stage_tool_response(self, tool_name: str, content: str, *, vector: str = "web_search",
                            persist: bool = False) -> None:
        """Make the target's matching tool call(s) return ``content`` instead
        of the real result. Default (``persist=False``): one-shot, consumed
        by the first matching call then reverts to real behavior -- this is
        the realistic condition for a tool that can issue several concurrent
        sub-queries per turn (e.g. a multi-query web search): only one of
        them gets poisoned, diluted among genuine results, exactly like a
        not-yet-top-ranked real page would be. ``persist=True`` instead keeps
        returning ``content`` for every matching call until
        :meth:`unstage_tool_response` is called -- simulates the poisoned
        source being the dominant/only hit (e.g. a well-indexed or
        SEO-ranked page), isolating the payload's own potency from that
        dilution effect. Models indirect prompt injection delivered via a
        tool result (e.g. a poisoned web-search snippet) rather than a
        direct chat turn. ``vector`` is a semantic label of the delivery
        channel (``web_search`` / ``email`` / ``document`` / ``calendar`` /
        ``crm`` / ``custom``); the adapter decides which of its tools should
        return ``content``. No-op default: an adapter that can't stage a
        tool result should not silently do nothing and claim success --
        pair this with ``AdapterCapabilities.supports_tool_staging = False``
        so the runner reports ``NOT_EVALUATED`` instead of a false
        ``CLEAN``."""
        return None

    def unstage_tool_response(self, tool_name: str) -> None:
        """Clear any staged response for ``tool_name`` regardless of how it
        was staged (one-shot or ``persist=True``). The engine calls this
        unconditionally right after the trigger turn of a tool-injection
        flow, so a ``persist=True`` stage never leaks into a later phase
        (consolidate, probe) of the same variant run. No-op default -- safe
        for adapters that already auto-clear (the one-shot default) or that
        don't support staging at all."""
        return None

    def ingest_document(self, principal: Principal, session_id: str, document_text: str) -> str:
        """Feed a document the way the agent would receive an attachment or
        RAG context; return the assistant's reply. No-op default -- pair
        with ``supports_document_ingestion=False`` so the runner reports
        ``NOT_EVALUATED`` instead of a false ``CLEAN``."""
        return ""

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(access_profile="black_box")
