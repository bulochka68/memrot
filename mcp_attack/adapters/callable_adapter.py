"""In-process adapter wrapping plain Python callables.

This is what the test suite uses (no Docker/network needed), and is also the
documented onboarding path for testing a memory library (mem0, LangGraph, a
custom SDK) at the API level without going through HTTP at all.

Deliberately excluded from config-driven construction (``adapters/registry.py``):
it needs live Python callables, which a JSON config cannot express. Build it
directly in code instead.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..models import Principal
from .base import AdapterCapabilities, TargetAdapter

SendFn = Callable[[str, str, str], str]
NewSessionFn = Callable[[str], str]
ConsolidateFn = Callable[[str, str], None]
InspectFn = Callable[[str], Optional[str]]
GroundTruthFn = Callable[..., Optional[bool]]
ResetFn = Callable[[], bool]


class CallableAdapter(TargetAdapter):
    kind = "callable"
    adapter_version = "1.0.0"

    def __init__(self, *, send_fn: SendFn, new_session_fn: Optional[NewSessionFn] = None,
                 consolidate_fn: Optional[ConsolidateFn] = None,
                 inspect_fn: Optional[InspectFn] = None,
                 ground_truth_fn: Optional[GroundTruthFn] = None,
                 reset_fn: Optional[ResetFn] = None,
                 access_profile: str = "black_box") -> None:
        self._send_fn = send_fn
        self._new_session_fn = new_session_fn
        self._consolidate_fn = consolidate_fn
        self._inspect_fn = inspect_fn
        self._ground_truth_fn = ground_truth_fn
        self._reset_fn = reset_fn
        self._access_profile = access_profile
        self._session_counter = 0

    def new_session(self, principal: Principal) -> str:
        if self._new_session_fn is not None:
            return self._new_session_fn(principal.principal_id)
        self._session_counter += 1
        return f"session-{principal.principal_id}-{self._session_counter}"

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        return self._send_fn(principal.principal_id, session_id, message)

    def consolidate(self, principal: Principal, session_id: str) -> None:
        if self._consolidate_fn is not None:
            self._consolidate_fn(principal.principal_id, session_id)

    def inspect_memory(self, principal: Principal) -> Optional[str]:
        if self._inspect_fn is not None:
            return self._inspect_fn(principal.principal_id)
        return None

    def ground_truth_check(self, marker: str, **kwargs: Any) -> Optional[bool]:
        if self._ground_truth_fn is not None:
            return self._ground_truth_fn(marker, **kwargs)
        return None

    def reset(self) -> bool:
        if self._reset_fn is not None:
            return bool(self._reset_fn())
        return False

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            access_profile=self._access_profile,
            supports_consolidate=self._consolidate_fn is not None,
            supports_inspect_memory=self._inspect_fn is not None,
            supports_ground_truth=self._ground_truth_fn is not None,
            supports_reset=self._reset_fn is not None,
        )
