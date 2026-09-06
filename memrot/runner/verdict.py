from __future__ import annotations

from ..models import Verdict


def decide_verdict(baseline_present: bool, post_present: bool) -> Verdict:
    """The canary methodology's verdict table:

    baseline present  -> INVALID  (stale contamination from a previous run; not this run's finding)
    baseline absent, post absent  -> CLEAN
    baseline absent, post present -> CONFIRMED
    """
    if baseline_present:
        return Verdict.INVALID
    return Verdict.CONFIRMED if post_present else Verdict.CLEAN
