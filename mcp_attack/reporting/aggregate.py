"""Attack-Success-Rate aggregation.

Denominator policy: only CONFIRMED and CLEAN count toward a GroupMetric's
``total`` (they are the two outcomes where the technique was actually
attempted and its effect could be observed). INVALID (stale contamination),
ERROR (adapter/transport failure) and NOT_EVALUATED (access profile not met)
are excluded from every ratio -- but never hidden: they are always visible
via ``counts_by_verdict``. A group with zero attempts displays "n/a (0/0)",
never a fabricated 0% or 100%.
"""
from __future__ import annotations

from typing import Dict, List

from ..models import GroupMetric, RunReport, Verdict

AXES = ("framing", "payload", "layer", "propagation")
_COUNTED = (Verdict.CONFIRMED, Verdict.CLEAN)


def _bump(groups: Dict[str, GroupMetric], key: str, confirmed: bool) -> None:
    g = groups.setdefault(key, GroupMetric(key=key))
    g.total += 1
    if confirmed:
        g.confirmed += 1


def aggregate(report: RunReport) -> RunReport:
    counts: Dict[str, int] = {}
    overall = GroupMetric(key="overall")
    by_rule: Dict[str, GroupMetric] = {}
    by_axis: Dict[str, Dict[str, GroupMetric]] = {axis: {} for axis in AXES}

    for r in report.results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
        if r.verdict not in _COUNTED:
            continue
        confirmed = r.verdict == Verdict.CONFIRMED
        overall.total += 1
        if confirmed:
            overall.confirmed += 1
        for rule_id in r.rule_ids or ["(untagged)"]:
            _bump(by_rule, rule_id, confirmed)
        for axis in AXES:
            value = getattr(r, axis, "") or "(unset)"
            _bump(by_axis[axis], value, confirmed)

    report.counts_by_verdict = counts
    report.overall_asr = overall
    report.asr_by_rule_id = by_rule
    report.asr_by_axis = by_axis
    return report
