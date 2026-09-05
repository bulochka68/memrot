"""Isolation guard for the active plane.

Passive audits (near prod) must never reach this layer.  The guard is a
hard gate: unless ``sandbox=True`` is passed explicitly *and* the
``MCP_AUDIT_SANDBOX`` environment marker is set, every probe is refused.
It also carries the canary token and sinkhole address that probes use so
that a successful exfil probe leaks only a marked, worthless value into a
black hole.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import List


class SandboxViolation(RuntimeError):
    """Raised when the active plane is asked to run outside a sandbox."""


@dataclass
class IsolationGuard:
    sandbox: bool = False
    env_marker: str = "MCP_AUDIT_SANDBOX"
    sinkhole: str = "http://sinkhole.invalid.local"
    canary_token: str = field(default_factory=lambda: "CANARY-" + secrets.token_hex(8))
    allow_destructive: bool = True
    _log: List[str] = field(default_factory=list)

    def ensure_sandbox(self) -> None:
        if not self.sandbox:
            raise SandboxViolation(
                "Active verification refused: not in sandbox mode. "
                "Layer 4 executes tools/call and must run only in the isolated P0 stand."
            )
        if os.environ.get(self.env_marker) not in ("1", "true", "yes"):
            raise SandboxViolation(
                f"Active verification refused: {self.env_marker} is not set. "
                "Set it inside the isolated stand to acknowledge sandbox execution."
            )

    def canary_path(self, tmp: str) -> str:
        return os.path.join(tmp, f"{self.canary_token}.txt")

    def note(self, msg: str) -> None:
        self._log.append(msg)

    @property
    def log(self) -> List[str]:
        return list(self._log)
