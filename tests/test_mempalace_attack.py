"""Attack-side acceptance stand: the red-team harness wired to a foreign system.

The audit half of the stand is already ported to MemPalace
(https://github.com/MemPalace/mempalace, commit d9f0590) by data alone
(``tests/test_mempalace_profile.py``). This test covers the *attack* half of
the same port: a run config (``examples/mempalace.attack.config.json``) that
points ``mcp_client`` at the shared HTTP hub, and a domain overlay
(``memrot/catalog/prompts/domain/mempalace/``) whose variants attack
exactly the controls that audit flagged FAIL on that build — MEM-01, MEM-03,
MEM-07, AUTH-01 and EGRESS-01.

Everything here is offline: it reads the committed config, catalog and audit
snapshot, so it needs neither the clone, the network, nor a live hub. Only
``memrot`` is imported — never ``mcp_audit`` — matching the package
boundary the audit → attack bridge relies on (plain JSON + shared string tags).
"""
import json
import os

from memrot.catalog.loader import load_catalog
from memrot.catalog.schema import validate_catalog_file
from memrot.config import load_config
from memrot.audit_plan import select_variants_by_audit
from memrot.models import DOMAIN_VALUES

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG = os.path.join(ROOT, "examples", "mempalace.attack.config.json")
AUDIT = os.path.join(ROOT, "examples", "mempalace.audit.json")
OVERLAY = os.path.join(ROOT, "memrot", "catalog", "prompts", "domain", "mempalace")

# The controls that MemPalace's audit reports FAIL on the recorded build
# (see tests/test_mempalace_profile.py). The overlay must attack these.
AUDIT_FAIL_RULES = {"MEM-01", "MEM-03", "MEM-07", "MEM-09", "AUTH-01", "AUTH-02", "AUTH-04", "EGRESS-01"}


def test_mempalace_is_a_declared_attack_domain():
    # the attack-side analog of the audit lexicon extension: one additive enum entry
    assert "mempalace" in DOMAIN_VALUES


def test_attack_config_wires_mcp_client_to_the_hub():
    cfg = load_config(CONFIG)
    assert cfg.target.kind == "mcp_client"                       # grey-box MCP-over-HTTP hub
    assert cfg.target.binding["base_url"].endswith(":8765/mcp")  # deploy/docker-compose.server.yml
    assert cfg.access_profile == "grey_box"
    roles = {c.role.value for c in cfg.channels}
    assert {"attacker", "victim", "benign_control"} <= roles
    # a shared static bearer with self-asserted identity: one credential_ref, many principal_ids
    refs = {c.principal.credential_ref for c in cfg.channels}
    assert refs == {"MEMPALACE_TEAM_TOKEN"}
    assert len({c.principal.principal_id for c in cfg.channels}) == len(cfg.channels)
    # every catalog path the config names actually exists
    for path in cfg.resolve_catalog_paths():
        assert os.path.exists(path), path
    # audit-driven by construction
    assert cfg.audit_mode == "ranked"
    assert cfg.audit_path and os.path.exists(os.path.join(ROOT, cfg.audit_path))


def test_overlay_validates_strict_taxonomy():
    files = []
    for base, _dirs, names in os.walk(OVERLAY):
        files.extend(os.path.join(base, n) for n in names if n.endswith(".json"))
    assert files, "no catalog files found under the mempalace overlay"
    for path in files:
        errors = validate_catalog_file(path, require_taxonomy=True)
        assert errors == [], f"{path}: {errors}"


def test_overlay_is_mempalace_domain_and_attacks_audited_controls():
    variants = load_catalog([OVERLAY])
    assert len(variants) >= 10
    tagged = [v for v in variants if v.rule_ids]           # everything but the benign controls
    assert tagged
    # each non-benign variant attacks a control the audit actually flagged on this build
    for v in tagged:
        assert set(v.rule_ids) & AUDIT_FAIL_RULES, f"{v.id} attacks {v.rule_ids}, none of which audit flagged"
    covered = set().union(*(set(v.rule_ids) for v in tagged))
    # the overlay covers the headline MemPalace findings
    assert {"MEM-01", "MEM-03", "MEM-07", "AUTH-01", "EGRESS-01"} <= covered


def test_audit_driven_ranking_prioritizes_findings_over_benign():
    """The whole point of the wiring: the committed MemPalace audit snapshot
    reorders the catalog so variants matching its FAIL controls come first and
    the benign controls sink to the bottom. Ranked mode never drops a variant."""
    cfg = load_config(CONFIG)
    variants = load_catalog(cfg.resolve_catalog_paths())
    ordered, _limitations = select_variants_by_audit(variants, AUDIT, mode="ranked")
    assert len(ordered) == len(variants)                    # ranked reorders, never filters

    benign_ids = {"mp-benign-recent-drawers", "mp-benign-search-topic", "mp-benign-status"}
    positions = {v.id: i for i, v in enumerate(ordered)}
    worst_attack = max(i for v, i in positions.items()
                       for _ in [0] if v not in benign_ids and _variant_rule_ids(variants, v))
    best_benign = min(positions[b] for b in benign_ids if b in positions)
    assert worst_attack < best_benign, "a benign control outranked an audit-matched attack"

    # a top-slice is entirely audit-relevant (matches a FAIL control by rule_id or bridged category)
    top = ordered[:6]
    assert all(v.owasp_amg_category or (set(v.rule_ids) & AUDIT_FAIL_RULES) for v in top)


def _variant_rule_ids(variants, vid):
    for v in variants:
        if v.id == vid:
            return v.rule_ids
    return []
