"""Layer 4 - Controlled validation (behavioural plane).  ISOLATED FIXTURE ONLY.

Executes *registered* control cases through ``tools/call`` with agreed
schemas, separates execution status from control outcome, observes effects
independently of response text where possible, and records the isolation
declaration apart from technical isolation evidence.
"""
from .isolation import IsolationGuard, SandboxViolation
from .fixtures import ControlCase, cases_from_fixtures, kind_cases, schema_agrees
from .probes import default_probes, Probe
from .runner import run_controlled_validation, run_active_verification, classify_error, decide, observe_effect

__all__ = ["IsolationGuard", "SandboxViolation", "ControlCase", "cases_from_fixtures", "kind_cases", "schema_agrees",
           "default_probes", "Probe", "run_controlled_validation", "run_active_verification", "classify_error",
           "decide", "observe_effect"]
