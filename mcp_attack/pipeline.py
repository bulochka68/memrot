"""Single API for the audit → attack happy path.

CLI ``quickstart`` and the demo notebook both call :func:`audit_then_attack`
so there is one source of truth. This module never imports ``mcp_audit``.
"""
from __future__ import annotations

import os
from typing import List, Optional, Sequence

from .adapters.base import TargetAdapter
from .adapters.registry import build_adapter
from .audit_plan import select_variants_by_audit
from .catalog.generator import StaticCatalogGenerator
from .config import TargetBinding
from .detectors import build_detector
from .detectors.base import Detector
from .models import Channel, RunReport, default_run_id
from .mutation.domain import audit_looks_like_invest_stand
from .mutation.llm_client import LLMClient
from .reporting.aggregate import aggregate
from .runner.adaptive import run_adaptive
from .runner.engine import run_matrix
from .tracer import JSONLTracer

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
GENERIC_CATALOG = os.path.join(_PACKAGE_DIR, "catalog", "prompts", "generic")
ALL_CATALOG = os.path.join(_PACKAGE_DIR, "catalog", "prompts")
PLACEHOLDER_CREDENTIAL = "placeholder-unauthenticated"


def resolve_pool(pool: str, audit_json_path: Optional[str] = None) -> List[str]:
    """``neutral`` = generic prompts; ``all`` = generic + domain overlays;
    ``auto`` (quickstart default) = ``all`` when the audit JSON is this
    repo's invest stand, otherwise ``neutral`` (mempalace / unknown)."""
    chosen = pool
    if pool in ("", "auto"):
        chosen = "all" if (audit_json_path and audit_looks_like_invest_stand(audit_json_path)) else "neutral"
    if chosen in ("", "neutral"):
        return [GENERIC_CATALOG]
    if chosen == "all":
        return [ALL_CATALOG]
    return [pool]


def ensure_placeholder_credentials(channels: Sequence[Channel]) -> List[str]:
    """If a channel's credential env var is unset, plant a harmless
    placeholder rather than failing before the run. The adapter may still
    get 401s; that surfaces as ERROR, not a crash."""
    notes: List[str] = []
    for channel in channels:
        ref = channel.principal.credential_ref or channel.principal.principal_id
        env_name = f"MCP_ATTACK_CRED_{ref}"
        if not os.environ.get(env_name):
            os.environ[env_name] = PLACEHOLDER_CREDENTIAL
            notes.append(
                f"used placeholder-credential for {env_name}; responses may be 401/anonymous"
            )
    return notes


def audit_then_attack(audit_json_path: Optional[str], target: TargetBinding, channels: List[Channel], *,
                      pool: str = "neutral", top_n: Optional[int] = None,
                      detector: Optional[Detector] = None, tracer: Optional[JSONLTracer] = None,
                      adaptive: bool = False, attacker_llm: Optional[LLMClient] = None,
                      adapter: Optional[TargetAdapter] = None,
                      reset_between_variants: bool = False,
                      adaptive_max_rounds: int = 3,
                      min_severity: Optional[str] = None) -> RunReport:
    """Load the chosen pool → optional ranked audit prioritization →
    ``run_matrix`` (or ``run_adaptive``) → ``RunReport``."""
    resolved = resolve_pool(pool, audit_json_path)
    variants = StaticCatalogGenerator(resolved).generate()
    limitations: List[str] = []
    limitations.extend(ensure_placeholder_credentials(channels))
    if pool in ("", "auto"):
        if resolved == [ALL_CATALOG]:
            limitations.append("pool=auto: audit profile looks like the invest stand; loaded generic + domain overlay")
        else:
            limitations.append("pool=auto: using the generic catalog (no invest-stand overlay)")
    if audit_json_path:
        variants, audit_limitations = select_variants_by_audit(
            variants, audit_json_path, mode="ranked", min_severity=min_severity, top_n=top_n,
        )
        limitations.extend(audit_limitations)
    elif top_n is not None:
        variants = variants[: max(0, int(top_n))]

    bound = adapter if adapter is not None else build_adapter(target)
    det = detector if detector is not None else build_detector("literal", {})
    own_tracer = tracer is None
    tr = tracer if tracer is not None else JSONLTracer()
    try:
        if adaptive:
            if attacker_llm is None:
                raise ValueError("adaptive mode requires attacker_llm")
            results = []
            run_id = default_run_id()
            for seed in variants:
                results.extend(run_adaptive(
                    seed, channels, bound, det, tr, run_id,
                    attacker_llm=attacker_llm, max_rounds=adaptive_max_rounds,
                ))
            report = RunReport(run_id=run_id, target_id=bound.kind, results=results,
                               channels=list(channels), limitations=limitations, trace_path=tr.path)
            aggregate(report)
        else:
            report = run_matrix(variants, channels, bound, det, tr,
                                reset_between_variants=reset_between_variants)
            report.limitations = limitations + report.limitations
    finally:
        if own_tracer:
            tr.close()
    return report
