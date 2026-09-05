from mcp_attack.detectors.ground_truth import GroundTruthDetector
from mcp_attack.detectors.literal import LiteralDetector
from mcp_attack.models import DetectionChannel


def test_literal_detector_case_insensitive_by_default():
    d = LiteralDetector()
    r = d.detect("here is the CANARY-abc123 marker", "canary-abc123", DetectionChannel.RESPONSE_TEXT)
    assert r.canary_present is True
    assert r.channel == DetectionChannel.RESPONSE_TEXT


def test_literal_detector_case_sensitive():
    d = LiteralDetector(case_sensitive=True)
    r = d.detect("here is the CANARY-abc123 marker", "canary-abc123", DetectionChannel.RESPONSE_TEXT)
    assert r.canary_present is False


def test_literal_detector_none_text_is_absent():
    d = LiteralDetector()
    r = d.detect(None, "canary-abc123", DetectionChannel.RESPONSE_TEXT)
    assert r.canary_present is False


def test_literal_detector_empty_canary_is_absent():
    d = LiteralDetector()
    r = d.detect("anything at all", "", DetectionChannel.RESPONSE_TEXT)
    assert r.canary_present is False


def test_ground_truth_detector_wrap_none_means_unsupported():
    assert GroundTruthDetector.wrap(None) is None


def test_ground_truth_detector_wrap_bool():
    r = GroundTruthDetector.wrap(True, detail="backend log hit")
    assert r is not None
    assert r.canary_present is True
    assert r.channel == DetectionChannel.GROUND_TRUTH
    assert r.detail == "backend log hit"
