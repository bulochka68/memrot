import os

import pytest

from mcp_attack.adapters.openai_compat import credential_for
from mcp_attack.config import _check_no_secrets, load_config
from mcp_attack.models import ChannelRole, Principal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _base_config(**overrides):
    cfg = {
        "schema_version": "1.0",
        "target": {"kind": "openai_compat", "binding": {"base_url": "http://x/v1", "model": "m"}},
        "channels": [
            {"role": "attacker", "principal": {"principal_id": "1001", "credential_ref": "CUS_1001"}},
            {"role": "victim", "principal": {"principal_id": "1002", "credential_ref": "CUS_1002"}},
        ],
        "catalog_paths": ["mcp_attack/catalog/prompts/domain/invest_bank/benign_control"],
    }
    cfg.update(overrides)
    return cfg


def test_load_config_parses_channels_and_target(write_json):
    path = write_json("cfg.json", _base_config())
    config = load_config(path)
    assert config.target.kind == "openai_compat"
    assert len(config.channels) == 2
    assert config.channels[0].role == ChannelRole.ATTACKER
    assert config.channels[0].principal.principal_id == "1001"


def test_load_config_rejects_unknown_schema_version(write_json):
    path = write_json("cfg.json", _base_config(schema_version="99.0"))
    with pytest.raises(ValueError):
        load_config(path)


def test_load_config_requires_at_least_one_channel(write_json):
    path = write_json("cfg.json", _base_config(channels=[]))
    with pytest.raises(ValueError):
        load_config(path)


def test_check_no_secrets_rejects_embedded_api_key():
    with pytest.raises(ValueError):
        _check_no_secrets({"target": {"binding": {"api_key": "sk-genai-abc"}}})


def test_check_no_secrets_allows_credential_ref():
    _check_no_secrets({"principal": {"credential_ref": "CUS_1001"}})   # must not raise


def test_credential_for_resolves_from_env(monkeypatch):
    monkeypatch.setenv("MCP_ATTACK_CRED_CUS_1001", "sk-genai-test")
    p = Principal(principal_id="1001", credential_ref="CUS_1001")
    assert credential_for(p) == "sk-genai-test"


def test_credential_for_missing_env_raises(monkeypatch):
    monkeypatch.delenv("MCP_ATTACK_CRED_CUS_9999", raising=False)
    p = Principal(principal_id="9999", credential_ref="CUS_9999")
    with pytest.raises(RuntimeError):
        credential_for(p)


def test_shipped_example_config_resolves_existing_catalog_directories():
    """Regression test: catalog_paths resolve relative to the config file's
    own directory (examples/), not the process cwd -- caught a real bug on
    the first live run where paths pointed at examples/mcp_attack/... ."""
    path = os.path.join(ROOT, "examples", "genai_invest_stand.attack.config.json")
    config = load_config(path)
    for resolved in config.resolve_catalog_paths():
        assert os.path.isdir(resolved), resolved
