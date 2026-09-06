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

    def ingest(self, principal_id: str, session_id: str, document_text: str) -> str:
        self.session_messages.setdefault(session_id, []).append(document_text)
        return f"(ingested {len(document_text)} chars)"


class FakeCleanMemoryApp(FakeVulnerableMemoryApp):
    def consolidate(self, principal_id: str, session_id: str) -> None:
        return None   # never persists: not vulnerable to this class of attack


class FakeToolPoisonableApp:
    """Mirrors the reference stand's two-hop laundering requirement (see
    ``mcp_attack.adapters.inprocess_stand``'s docstring): staged tool content
    is never auto-persisted -- it only reaches memory if the model's own
    visible reply repeats it (simulated here: ``send()`` echoes the staged
    snippet back only when the message looks like a search request), and
    only global-scope memory is shared across every principal (mirrors
    ``AgentPolicyMemory``'s ``scope=global``, no ``user_id``)."""

    def __init__(self) -> None:
        self.staged: Dict[str, str] = {}
        self.global_policy: str = ""
        self.session_messages: Dict[str, List[str]] = {}
        self.session_launder: Dict[str, str] = {}   # session_id -> the assistant's own visible reply
        self._counter = 0

    def new_session(self, principal_id: str) -> str:
        self._counter += 1
        sid = f"sess-{principal_id}-{self._counter}"
        self.session_messages[sid] = []
        return sid

    def stage_tool_response(self, tool_name: str, content: str) -> None:
        self.staged[tool_name] = content

    def send(self, principal_id: str, session_id: str, message: str) -> str:
        self.session_messages.setdefault(session_id, []).append(message)
        if "search" in message.lower() and self.staged.get("duckduckgo_search"):
            snippet = self.staged.pop("duckduckgo_search")
            reply = f"Here's what I found: {snippet}"
            self.session_launder[session_id] = reply
            return reply
        parts = [self.global_policy] if self.global_policy else []
        parts.append(f"(ack: {message[:40]})")
        return " | ".join(parts)

    def consolidate(self, principal_id: str, session_id: str) -> None:
        laundered = self.session_launder.get(session_id, "")
        if laundered:
            self.global_policy = (self.global_policy + " " + laundered).strip()

    def inspect_memory(self, principal_id: str) -> str:
        return f"global_policy={self.global_policy!r}"

    def reset(self) -> bool:
        self.staged = {}
        self.global_policy = ""
        self.session_messages = {}
        self.session_launder = {}
        return True


class FakeToolCleanApp(FakeToolPoisonableApp):
    """Same laundering mechanics, but consolidate() never persists -- stands
    in for a target whose summarizer discards tool-sourced content even
    after it was echoed into a visible reply (e.g. it strips quoted/attributed
    text before extraction)."""

    def consolidate(self, principal_id: str, session_id: str) -> None:
        return None


class RaisingApp:
    """Adapter target whose send() always raises -- exercises the ERROR path."""

    def new_session(self, principal_id: str) -> str:
        return "session-1"

    def send(self, principal_id: str, session_id: str, message: str) -> str:
        raise RuntimeError("simulated transport failure")

    def consolidate(self, principal_id: str, session_id: str) -> None:
        return None


def build_adapter(app, *, access_profile: str = "black_box", with_memory: bool = False,
                  with_ground_truth: bool = False, with_reset: bool = False,
                  with_tool_staging: bool = False, with_ingest: bool = False,
                  supported_tool_vectors: Optional[List[str]] = None) -> CallableAdapter:
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
    if with_tool_staging:
        kwargs["stage_tool_fn"] = app.stage_tool_response
    if with_ingest:
        kwargs["ingest_fn"] = app.ingest
    if supported_tool_vectors is not None:
        kwargs["supported_tool_vectors"] = supported_tool_vectors
    return CallableAdapter(**kwargs)
