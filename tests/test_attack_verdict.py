import pytest

from mcp_attack.models import Verdict
from mcp_attack.runner.verdict import decide_verdict


@pytest.mark.parametrize("baseline,post,expected", [
    (False, False, Verdict.CLEAN),
    (False, True, Verdict.CONFIRMED),
    (True, False, Verdict.INVALID),
    (True, True, Verdict.INVALID),
])
def test_decide_verdict_truth_table(baseline, post, expected):
    assert decide_verdict(baseline, post) == expected
