"""In-process fake targets for the mcp_attack test suite -- no Docker/network.

FakeVulnerableMemoryApp blindly promotes whatever was said in a session to
both "global policy" (visible to every principal) and per-principal
"semantic memory" (visible to that principal in later sessions) once
consolidate() is called -- deliberately naive, standing in for a target with
no provenance/authority checks on memory writes.

FakeCleanMemoryApp has the identical interface but consolidate() never
persists anything, standing in for a target that isn't vulnerable to this
class of attack.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp_attack.adapters.callable_adapter import CallableAdapter


class FakeVulnerableMemoryApp:
    def __init__(self) -> None:
        self.global_policy: str = ""
        self.user_semantic: Dict[str, str] = {}
        self.session_messages: Dict[str, List[str]] = {}
        self._counter = 0

    def new_session(self, principal_id: str) -> str:
        self._counter += 1
        sid = f"sess-{principal_id}-{self._counter}"
        self.session_messages[sid] = []
        return sid

    def send(self, principal_id: str, session_id: str, message: str) -> str:
        self.session_messages.setdefault(session_id, []).append(message)
        parts = []
        if self.global_policy:
            parts.append(self.global_policy)
        if principal_id in self.user_semantic:
            parts.append(self.user_semantic[principal_id])
        parts.append(f"(ack: {message[:40]})")
        return " | ".join(parts)

    def consolidate(self, principal_id: str, session_id: str) -> None:
        combined = " ".join(self.session_messages.get(session_id, []))
        if not combined:
            return
        self.global_policy = (self.global_policy + " " + combined).strip()
        self.user_semantic[principal_id] = (self.user_semantic.get(principal_id, "") + " " + combined).strip()

    def inspect_memory(self, principal_id: str) -> str:
        return f"global_policy={self.global_policy!r} user_semantic={self.user_semantic.get(principal_id, '')!r}"

    def ground_truth(self, marker: str, **kwargs: Any) -> bool:
        haystacks = [self.global_policy] + list(self.user_semantic.values())
        return any(marker and marker in h for h in haystacks)

    def reset(self) -> bool:
        self.global_policy = ""
        self.user_semantic = {}
        self.session_messages = {}
        return True


class FakeCleanMemoryApp(FakeVulnerableMemoryApp):
    def consolidate(self, principal_id: str, session_id: str) -> None:
        return None   # never persists: not vulnerable to this class of attack


class RaisingApp:
    """Adapter target whose send() always raises -- exercises the ERROR path."""

    def new_session(self, principal_id: str) -> str:
        return "session-1"

    def send(self, principal_id: str, session_id: str, message: str) -> str:
        raise RuntimeError("simulated transport failure")

    def consolidate(self, principal_id: str, session_id: str) -> None:
        return None


def build_adapter(app, *, access_profile: str = "black_box", with_memory: bool = False,
                  with_ground_truth: bool = False, with_reset: bool = False) -> CallableAdapter:
    kwargs: Dict[str, Any] = dict(
        send_fn=app.send, new_session_fn=app.new_session, consolidate_fn=app.consolidate,
        access_profile=access_profile,
    )
    if with_memory:
        kwargs["inspect_fn"] = app.inspect_memory
    if with_ground_truth:
        kwargs["ground_truth_fn"] = app.ground_truth
    if with_reset:
        kwargs["reset_fn"] = app.reset
    return CallableAdapter(**kwargs)
