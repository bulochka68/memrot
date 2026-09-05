import json
import os
from mcp_audit.cli import main

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXAMPLE = os.path.join(ROOT, "examples", "mcp_config.example.json")
STAND = os.path.join(ROOT, "examples", "genai_invest_stand.manifest.json")


def test_exit_codes_distinguish_incomplete_from_findings(tmp_path, capsys):
    out = str(tmp_path / "a.json")
    assert main(["audit", EXAMPLE, "--json", out, "--gate"]) == 2
    assert main(["audit", STAND, "--json", str(tmp_path / "s.json"), "--md", str(tmp_path / "s.md"), "--obsec", str(tmp_path / "o.json"), "--gate"]) == 1
    assert main(["audit", EXAMPLE, "--json", out]) == 0
    assert main(["validate", out]) == 0
    assert main(["audit", str(tmp_path / "missing.json")]) == 4
    err = capsys.readouterr().err
    assert '"exit_code"' in err


def test_baseline_drift_and_rules(tmp_path, capsys):
    bl = str(tmp_path / "bl.json")
    assert main(["baseline", EXAMPLE, "-o", bl]) == 0
    assert main(["drift", EXAMPLE, "--baseline", bl, "--fail-on-drift"]) == 0
    cfg = json.load(open(EXAMPLE))
    cfg["mcpServers"]["filesystem"]["tools"][0]["description"] = "changed"
    p = str(tmp_path / "c.json")
    json.dump(cfg, open(p, "w"))
    assert main(["drift", p, "--baseline", bl, "--fail-on-drift"]) == 3
    assert main(["rules"]) == 0
    assert "MEM-02" in capsys.readouterr().out


def test_migrate_cli(tmp_path):
    legacy = os.path.join(HERE, "fixtures", "legacy", "audit.output.v1.1.json")
    out = str(tmp_path / "m.json")
    assert main(["migrate", legacy, "-o", out]) == 0
    assert json.load(open(out))["schema_version"] == "2.0"
