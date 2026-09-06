from memrot.models import (Channel, ChannelRole, GroupMetric, Principal, Verdict, path_state_for, plain)


def test_group_metric_zero_denominator_is_not_a_percentage():
    m = GroupMetric(key="MEM-02")
    assert m.ratio is None
    assert m.display == "n/a (0/0)"


def test_group_metric_ratio_and_display():
    m = GroupMetric(key="MEM-02", confirmed=1, total=4)
    assert m.ratio == 0.25
    assert m.display == "1/4 (25.0%)"


def test_channel_id_defaults_to_role_and_principal():
    c = Channel(role=ChannelRole.ATTACKER, principal=Principal(principal_id="1001"))
    assert c.channel_id == "attacker:1001"


def test_channel_to_dict_round_trips_plain_values():
    c = Channel(role=ChannelRole.VICTIM, principal=Principal(principal_id="1002", credential_ref="CUS_1002"))
    d = c.to_dict()
    assert d["role"] == "victim"
    assert d["principal"]["credential_ref"] == "CUS_1002"


def test_verdict_values_are_plain_strings_via_plain():
    assert plain(Verdict.CONFIRMED) == "CONFIRMED"


def test_path_state_for_matches_audit_ladder():
    assert path_state_for(Verdict.CONFIRMED, "cross-user") == "control_violation_observed"
    assert path_state_for(Verdict.CONFIRMED, "single-turn") == "runtime_path_observed"
    assert path_state_for(Verdict.CLEAN, "cross-user") == "static_path_supported"
    assert path_state_for(Verdict.ERROR) == "unknown"
    assert path_state_for(Verdict.NOT_EVALUATED) == "unknown"
    assert path_state_for(Verdict.INVALID) == "unknown"
