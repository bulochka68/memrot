"""Coverage metrics (TZ §13.1).

No single "security percentage".  Each metric keeps numerator, denominator,
the source of the denominator, the method, unknowns and the gaps.  A zero or
unknown denominator yields "не определено", never 100 %.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (AuditDocument, ControlOutcome, CoverageMetric, ExecutionStatus, MEMORY_STAGES, StageObservation)


def build_coverage(doc: AuditDocument, required: List[str]) -> List[CoverageMetric]:
    out: List[CoverageMetric] = []

    # inventory completeness against a reference list (profile or policy)
    ref = (doc.profile.get("reference_inventory") or doc.policy.get("authorized_tools") or {})
    if ref:
        total = sum(len(v) for v in ref.values())
        matched = 0
        gaps = []
        for srv, names in ref.items():
            s = doc.server(srv)
            have = {t.name for t in s.tools} if s else set()
            matched += len(set(names) & have)
            gaps += [f"{srv}/{n}" for n in names if n not in have]
        out.append(CoverageMetric("inventory_completeness", matched, total, "reference inventory (profile/policy)",
                                  "name matching per server", gaps=gaps, limitation="the reference list may itself be partial"))
    else:
        out.append(CoverageMetric("inventory_completeness", None, None, "no reference inventory", "n/a",
                                  limitation="no reference list; overall completeness unknown"))

    # component coverage
    comps = [c for c in doc.components]
    evaluated = {c for r in doc.control_results for c in r.component_refs if r.counts_for_coverage}
    for f in doc.findings:
        evaluated |= set(f.component_refs)
    out.append(CoverageMetric("component_coverage", len([c for c in comps if c.component_id in evaluated]), len(comps) or None,
                              "components of manifest/profile/inventory", "component referenced by a PASS/FAIL control or a finding",
                              gaps=[c.component_id for c in comps if c.component_id not in evaluated],
                              limitation="does not show the depth of evaluation per component"))

    # mandatory controls
    results = {r.rule_id: r for r in doc.control_results}
    req = [r for r in required if r in results]
    na = [r for r in req if results[r].control_outcome == ControlOutcome.NOT_APPLICABLE and results[r].applicability.value == "not_applicable"]
    denom = [r for r in req if r not in na]
    num = [r for r in denom if results[r].counts_for_coverage]
    out.append(CoverageMetric("mandatory_control_coverage", len(num), len(denom) or None, "required controls minus justified not-applicable",
                              "PASS + FAIL / all", unknown=len([r for r in denom if results[r].control_outcome != ControlOutcome.NOT_APPLICABLE and not results[r].counts_for_coverage]),
                              gaps=[f"{r}:{results[r].control_outcome.value}" for r in denom if not results[r].counts_for_coverage],
                              limitation="INCONCLUSIVE, NOT_EVALUATED and unknown applicability stay in the denominator"))
    static_num = [r for r in num if results[r].method and results[r].method.value in ("static_analysis", "policy_inspection", "parsing")]
    runtime_num = [r for r in num if results[r].method and results[r].method.value in ("observation", "controlled_validation")]
    out.append(CoverageMetric("mandatory_control_coverage_static", len(static_num), len(denom) or None, "same as above", "static methods only",
                              limitation="static support shows code/config facts, not runtime behaviour"))
    out.append(CoverageMetric("mandatory_control_coverage_runtime", len(runtime_num), len(denom) or None, "same as above", "observation / fixtures only",
                              limitation="runtime support is bound to the observed principal, build and environment"))

    # identity coverage: evaluated access relations vs expected policy relations
    rules = doc.policy.get("access_rules") or []
    trans = doc.source_facts.get("auth_transitions") or []
    if rules:
        verified = [t for t in trans if t.get("status") in ("static_supported", "contradicted")]

        def _res(x: str) -> str:
            return (x or "").split("(")[0].strip().lower()

        covered = [r for r in rules if any(_res(t.get("resource")) == _res(r.get("resource")) and
                                           (t.get("operation", "").upper() == r.get("operation", "").upper()) for t in verified)]
        out.append(CoverageMetric("identity_coverage", len(covered), len(rules), "expected access relations in policy",
                                  "policy relations with at least one verified transition (operation + resource)",
                                  gaps=[f"{r.get('subject')}:{r.get('operation')}:{r.get('resource')}" for r in rules if r not in covered],
                                  limitation="not replaced by the number of tokens used; a verified transition is a static fact"))
    else:
        out.append(CoverageMetric("identity_coverage", None, None, "policy has no access_rules", "n/a", limitation="expected relations unknown"))

    # memory coverage per stage
    cases = doc.memory_cases
    for stage in MEMORY_STAGES:
        applicable = [c for c in cases if c.get("stages", {}).get(stage) != StageObservation.NOT_EVALUATED.value]
        observed = [c for c in applicable if c.get("stages", {}).get(stage) in (StageObservation.OBSERVED.value, StageObservation.NOT_OBSERVED.value)]
        out.append(CoverageMetric(f"memory_stage_{stage}", len(observed) if cases else None, len(applicable) or None if cases else None,
                                  "applicable memory cases", "stage observed or not_observed with coverage", 
                                  unknown=len([c for c in applicable if c.get("stages", {}).get(stage) == StageObservation.UNKNOWN.value]),
                                  limitation="stages are never merged into one verified"))

    # boundary coverage
    bnds = [b.boundary_id for b in doc.boundaries]
    ev_b = {b for r in doc.control_results for b in r.evaluated_boundary_refs} | {b for t in doc.tests for b in t.evaluated_boundary_refs}
    out.append(CoverageMetric("boundary_coverage", len([b for b in bnds if b in ev_b]), len(bnds) or None, "boundaries of the accepted model",
                              "boundary reached by a PASS/FAIL evaluation", gaps=[b for b in bnds if b not in ev_b],
                              limitation="an unreached backend is not counted as evaluated"))

    # execution quality
    tests = doc.tests
    out.append(CoverageMetric("execution_quality", len([t for t in tests if t.execution_status == ExecutionStatus.COMPLETED]),
                              len(tests) or None, "control cases", "validly completed cases",
                              details={"errors": len([t for t in tests if t.execution_status == ExecutionStatus.ERROR]),
                                       "timeouts": len([t for t in tests if t.execution_status == ExecutionStatus.TIMEOUT]),
                                       "skipped": len([t for t in tests if t.execution_status == ExecutionStatus.SKIPPED])},
                              limitation="errors are not excluded to make the report look complete"))

    # observation quality
    tq = doc.meta.get("trace_quality") or {}
    cov = doc.meta.get("memory_coverage") or {}
    if tq or cov:
        out.append(CoverageMetric("observation_quality", tq.get("events", 0) - tq.get("events_missing_required_fields", 0) if tq else None,
                                  tq.get("events") if tq else None, "trace events", "events with required fields",
                                  details={"unlinked_parent_refs": tq.get("unlinked_parent_refs"), "coverage": cov},
                                  limitation="absence of an event is evidence only with sufficient coverage"))
    else:
        out.append(CoverageMetric("observation_quality", None, None, "no trace", "n/a", limitation="no runtime observation available"))
    doc.coverage = out
    return out
