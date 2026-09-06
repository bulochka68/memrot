import pytest

from memrot.models import Verdict
from memrot.runner.verdict import decide_verdict


@pytest.mark.parametrize("baseline,post,expected", [
    (False, False, Verdict.CLEAN),
    (False, True, Verdict.CONFIRMED),
    (True, False, Verdict.INVALID),
    (True, True, Verdict.INVALID),
])
def test_decide_verdict_truth_table(baseline, post, expected):
    assert decide_verdict(baseline, post) == expected
