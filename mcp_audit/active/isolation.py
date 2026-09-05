"""Isolation guard for controlled validation.

The guard separates two things that v1 conflated (TZ §2, §14):

* **declaration** - ``sandbox=True`` plus the ``MCP_AUDIT_SANDBOX`` marker say
  that the operator *intends* to run inside an isolated fixture.  Without the
  declaration nothing is executed.
* **technical evidence** - facts about the execution environment (container
  marker, restricted environment, fixture attestation of data/network/permission
  isolation).  Only the fixture can attest isolation of a *remote* target; the
  auditor's local container never substitutes for it.

``allow_destructive`` defaults to False; destructive cases are skipped unless
the operator opts in explicitly.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class SandboxViolation(RuntimeError):
    """Raised when controlled validation is requested without the sandbox declaration."""


@dataclass
class IsolationGuard:
    sandbox: bool = False
    env_marker: str = "MCP_AUDIT_SANDBOX"
    sinkhole: str = "http://sinkhole.invalid.local"
    canary_token: str = field(default_factory=lambda: "CANARY-" + secrets.token_hex(8))
    allow_destructive: bool = False
    max_cases: int = 200
    max_seconds: float = 600.0
    _log: List[str] = field(default_factory=list)

    def ensure_sandbox(self) -> None:
        if not self.sandbox:
            raise SandboxViolation(
                "Controlled validation refused: sandbox not declared. "
                "This layer executes tools/call and must run only in an isolated fixture.")
        if os.environ.get(self.env_marker) not in ("1", "true", "yes"):
            raise SandboxViolation(
                f"Controlled validation refused: {self.env_marker} is not set. "
                "Set it inside the isolated fixture to acknowledge sandbox execution.")

    def declaration(self) -> Dict[str, Any]:
        return {"sandbox_flag": self.sandbox, "env_marker": self.env_marker,
                "env_marker_set": os.environ.get(self.env_marker) in ("1", "true", "yes"),
                "allow_destructive": self.allow_destructive,
                "note": "declaration of intent; not proof of OS, network or remote-target isolation"}

    @staticmethod
    def technical_evidence(fixture_isolation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Collect local technical facts and the fixture's attestation (if any)."""
        fx = dict(fixture_isolation or {})
        return {
            "container_marker": os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"),
            "restricted_env": True,   # spawned servers get the allow-list env (introspector.minimal_env)
            "fixture_attestation": {k: fx.get(k) for k in ("data", "network", "permissions", "attested_by", "evidence_ref")},
            "attested": bool(fx.get("attested_by")) and all(fx.get(k) for k in ("data", "network", "permissions")),
            "note": "local facts do not prove isolation of a remote target; the fixture attestation is the only basis for that",
        }

    def canary_path(self, tmp: str) -> str:
        return os.path.join(tmp, f"{self.canary_token}.txt")

    def note(self, msg: str) -> None:
        self._log.append(msg)

    @property
    def log(self) -> List[str]:
        return list(self._log)
