"""Layer 4 - Active Verification (behavioral plane).  SANDBOX ONLY.

This layer really calls ``tools/call``: it reads, writes, deletes and runs
commands.  It must only execute inside the isolated stand (pipeline phase P0).
The IsolationGuard refuses to run unless it is explicitly told it is in a
sandbox, and it forces egress to a sinkhole and secrets to canaries.
"""
from .isolation import IsolationGuard, SandboxViolation
from .probes import default_probes, Probe
from .runner import run_active_verification

__all__ = ["IsolationGuard", "SandboxViolation", "default_probes", "Probe", "run_active_verification"]
