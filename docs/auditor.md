# Agent security audit subsystem (pipeline phase P1) — v2.0

Implementation of [`docs/audit_subsystem_architecture.md`](audit_subsystem_architecture.md)
(document v2.0). The package keeps its historical name `mcp_audit`, but the object
of the audit is the **life cycle of an agentic system**: inventory and
capabilities, definitions and context, identity and authorization, memory,
observed behaviour and infrastructure. MCP is one supported interface among
REST, native functions, background jobs, memory stores and traces.

The auditor lives in the same repository as the stand it audits: `mcp_audit/`,
`profiles/`, `schemas/`, `examples/`, `docs/` and `tests/` sit next to `app/`,
`mcp-invest/`, `invest-server/` and `docker-compose.yml`. Every command below is
run from the repository root, so profile paths such as `app/api_server.py`
resolve directly and no `..` is needed.

## What an audit answers

1. Which components, data, tools and background operations are available to the system?
2. Who may read, change and publish that data?
3. Where can untrusted content gain extra authority, including a transition into shared memory or policy?
4. Which part of every conclusion is supported by configuration, code, access policy or an execution observation?
5. Which boundaries were evaluated, which were not, and what closes the gap?

Every statement is a **claim** with its own `source_type`, `method`,
`claim_status` (hypothesis / static_supported / runtime_supported /
contradicted / inconclusive), `evidence_refs`, `scope`, qualitative
`confidence` and `limitations`. There is no tool-wide `verified` flag, no fixed
confidence number and no single "security percentage".

## Versions

| Item | Value | Defined in |
|---|---|---|
| Report schema | `agent-security-audit` 2.0 | `mcp_audit.AUDIT_SCHEMA_VERSION`, `schemas/agent-security-audit-2.0.schema.json` |
| Engine | 2.0.0 | `mcp_audit.__version__` |
| Ruleset | 2.0.0 (28 rules: MEM-01…10, AUTH-01…06, INFRA-01…03, TOOL-01…05, EGRESS-01…02, INV-01…02) | `python -m mcp_audit rules`, `docs/rules_catalog.md` |
| Legacy readers | audit 1.0 / 1.1 | `python -m mcp_audit migrate`, `docs/migration_v1_to_v2.md` |

## Modes and access profiles

| Mode | Does | May conclude |
|---|---|---|
| `offline` (default) | parses configs, sources, policies and snapshots; spawns nothing, connects nowhere | static facts, assumptions, mismatches |
| `live-inventory` | performs the MCP handshake (stdio servers get a minimal environment) | the catalogue advertised to *this* identity at *this* moment |
| `trace-review` | reads execution / memory events | only what the events show, with their coverage |
| `controlled-validation` | runs **registered** control cases on an isolated fixture | a concrete invariant inside the fixture |
| `baseline-comparison` | compares compatible snapshots | classified changes with an approval state |

`--access-profile black_box | grey_box | white_box` is an independent axis
describing which sources are available. Legacy `passive` / `active` / `drift`
names are accepted as aliases.

## Usage

```bash
# the stand in this checkout: sources + compose are read live, nothing is started
python -m mcp_audit audit examples/genai_invest_stand.local.manifest.json \
  --json .audit/stand.json --md .audit/stand.md --gate

# a plain MCP client config is wrapped into a manifest automatically (offline)
python -m mcp_audit audit examples/mcp_config.example.json --json audit.json --md report.md

# full v2 manifest: inventory + source facts + expected policy + deployment snapshot
python -m mcp_audit audit examples/genai_invest_stand.manifest.json --json stand.json --md stand.md --obsec obsec.json

# gate: exit 1 on confirmed findings, 2 on incomplete assessment, 0 only when complete and clean
python -m mcp_audit audit examples/genai_invest_stand.manifest.json --json stand.json --gate

# live inventory of an MCP config (spawns/contacts servers), context files, a system profile
python -m mcp_audit audit config.json --mode live-inventory --context-root . --profile profiles/my_system.json

# controlled validation: registered cases only, inside the isolated fixture
MCP_AUDIT_SANDBOX=1 python -m mcp_audit audit config.json --mode controlled-validation --sandbox --fixtures fixtures.json

# baselines and drift (approval state comes from a registry, never from the auditor)
python -m mcp_audit baseline config.json -o baseline.json
python -m mcp_audit drift config.json --baseline baseline.json --approvals approvals.json --fail-on-drift

# check a profile before the first audit: structure, locators, regexes, rule refs, references
python -m mcp_audit lint-profile profiles/mempalace.json --root /path/to/checkout \
  --sources mcp_inventory,policy_snapshot,deployment

# extract portable source facts for a profile, validate a report, migrate a legacy one
python -m mcp_audit source-snapshot --root /path/to/checkout --profile profiles/genai_invest_stand.json --commit <sha> -o facts.json
python -m mcp_audit validate stand.json
python -m mcp_audit migrate old_v1.json -o new_v2.json
python -m mcp_audit rules --markdown > docs/rules_catalog.md
```

Exit codes: `0` completed without violations in scope, `1` confirmed findings,
`2` partial / undetermined assessment (an unknown mandatory control is never an
allow), `3` drift, `4` audit error. Incompleteness and violations have different
machine codes.

`lint-profile` uses the same scale on the profile itself: `0` clean, `1`
problems found, `4` the profile could not be read. It checks five things — the
profile schema, that every `path` exists and every `symbol` resolves in the
source tree, that every regular expression compiles, that every `rule_refs`
entry names a rule in the catalogue, and that `component` / `from` / `to` /
`writer_principal` / `boundary` point at declared entities — and then prints
**which rules the profile opens at all**, so the gap map is visible before the
first audit instead of after reading a wall of `not_evaluated`. Warnings (an
unknown section, a reference that may be a principal declared elsewhere) are
printed but do not change the exit code unless `--strict` is given. Without
`--root` the locator checks are skipped and the report says so.

```
$ python -m mcp_audit lint-profile profiles/mempalace.json --root ../mempalace
profiles/mempalace.json: 1 problem(s)

  flows[F-mine-derivation].symbol  '_build_metadata' not found in mempalace/miner.py

planned rules with this profile: 18/28   (assumed sources: source_snapshot)
  missing: EGRESS-02 INFRA-03 (control_fixtures), INFRA-02 (deployment), INV-01 INV-02 (mcp_inventory),
           TOOL-01 (mcp_inventory+baseline), MEM-08 (memory_event_snapshot),
           EGRESS-01 INFRA-01 MEM-10 (policy_snapshot)
```

(That is a real run: the symbol was renamed to `_build_drawer_metadata` upstream,
and without the linter it would have surfaced as one `unknown` flow in the report,
indistinguishable from "the code does not do this".)

An adapter that lives outside the package is registered with
`--adapter-plugin module:Class` (repeatable), with `"adapter_plugins"` in the
manifest, or through the `mcp_audit.adapters` entry-point group; a plugin that
fails to load is reported in `limitations`, never silently dropped.

Python API:

```python
from mcp_audit.orchestrator import audit_from_manifest, audit_from_config
from mcp_audit.reporting import emit_json, emit_markdown, build_obsec_export

doc = audit_from_manifest("examples/genai_invest_stand.manifest.json")
print(doc.verdict["assessment_state"], doc.verdict["security_conclusion"])
for r in doc.control_results:
    print(r.rule_id, r.applicability.value, r.execution_status.value, r.control_outcome.value)
open("stand.json", "w").write(emit_json(doc))
```

## Inputs

A **manifest** (JSON, or YAML when PyYAML is present) declares the target
identity, inspection profile and bound adapters; secrets are never embedded
(credentials come through `MCP_AUDIT_CRED_<NAME>` environment bindings). A
**profile** holds the names of a concrete system (components, memory stores,
flows to verify in source, authorization transitions, token validation,
routing) so that the rules stay generic. Formats of all adapter inputs are in
[`docs/adapters_and_formats.md`](adapters_and_formats.md); porting the audit to
another stand is described in
[`docs/porting_to_a_new_stand.md`](porting_to_a_new_stand.md).

| Adapter | Source |
|---|---|
| `mcp_inventory` | MCP client config (configured catalogue), snapshot, live handshake, agent context files |
| `source_snapshot` | source tree (tool declarations by the profile's extraction strategy — decorator, registry dict, list literal or JSON file — plus regex-verified profile flows) or a pre-extracted facts file |
| `policy_snapshot` | expected access & memory policy |
| `memory_event_snapshot` | normalized memory records and events (W / R / C / B) |
| `trace` | JSONL execution events with causality and coverage |
| `deployment` | compose / JSON snapshot (published ports, env key names, storage auth hints) |
| `control_fixtures` | registered control cases and the fixture's isolation attestation |

A missing adapter shows up in the plan, in coverage and as `NOT_EVALUATED` on the
affected controls. It never becomes an empty finding list with a green verdict.

## Output

`agent-security-audit` v2.0 JSON: `meta`, `target`, `adapters`, `plan`,
`inventory` (servers with `inventory_sources`, reconciliation), `components`,
`principals`, `capabilities`, `memory_stores`, `boundaries`, `edges`,
`definition_analysis`, `evidence`, `claims`, `control_results`, `findings`,
`tests`, `memory_cases`, `coverage`, `trifecta`, `summary`, `verdict`,
`downstream`, `drift`, `import_history`, `limitations`. The Markdown report,
JSONL stream and ObSec export are generated from the same document; untrusted
fragments are escaped and secrets are redacted before they reach the evidence store.

The verdict has two independent axes: `assessment_state`
(complete_for_scope / partial / not_assessed) and `security_conclusion`
(findings_present / no_violations_observed / undetermined). `LETHAL_TRIFECTA`
is an indicator with a path state (capability_combination /
static_path_supported / runtime_path_observed / control_violation_observed /
unknown), not a proof of a leak.

## Worked example: the investment stand

`examples/genai_invest_stand.manifest.json` audits the deliberately vulnerable
stand of the `bulochka68-with-stand` branch (commit `912edfb1`) **offline from
snapshots**: the client-side MCP config (9 tools, as captured for the v1.1
example), source facts extracted from the stand sources (14 MCP declarations +
the native `duckduckgo_search(queries: List[str])`), an expected policy and a
secrets-free deployment snapshot. The report
(`examples/genai_invest_stand.report.md`) is `partial + findings_present`:
user-session processing publishes shared policy (MEM-02, static_supported),
scope decided by LLM output (MEM-03), policy presented as rules in the system
message (MEM-04), lost provenance (MEM-05), no approval before publication
(MEM-06), resource authorization missing per hop in the default mode (AUTH-02),
client parameters weaken checks (AUTH-03), JWT audience/issuer checks disabled
(AUTH-04), unbounded service delegation (AUTH-05), excessive store rights
(INFRA-01), storage ports published on the host (INFRA-02), tool results reach
policy (TOOL-04), the `query` vs `queries` contract mismatch (TOOL-02), an
uncontrolled search egress (EGRESS-01) and the 9-vs-14 inventory mismatch
(INV-01, a hypothesis until explained). No runtime validation was performed and
no claim is `runtime_supported`.

A second profile, `profiles/rest_native_agent.json`, runs the same rules on a
REST/native agent with pgvector memory and no MCP.

## Tests

```bash
pip install pytest
python -m pytest -q
```

The suite covers the acceptance criteria of the specification (mapping in the
architecture document, §14): config-only reports stay partial with no runtime
claims; inventory and contract mismatches are separate hypotheses; stale
schemas, unknown tools and timeouts are INCONCLUSIVE; one allowed write is not
full project access; collisions are judged with the router; background memory
jobs appear as components; allowed sharing is not a violation; W/R/C/B stages
are independent; AUTH and MEM outcomes are independent; policy drift carries an
approval state; a missing adapter never yields a green verdict; one defect is
one stable finding; legacy imports do not invent verification; a second
topology works through adapters; untrusted content cannot change auditor
settings; closure follows the remediation criterion on a new build, not a
vanished source; a pending job blocks a clean revocation result; mass blocking
of allowed operations is a functional failure.

## Scope

The audit is **diagnosis, not defense**. Static support shows a code or
configuration defect, not an observed effect on the running model; runtime
support is bound to the observed principal, build and fixture. Controlled
validation runs only inside an isolated fixture, on registered cases, and the
sandbox flag is a declaration of intent rather than proof of isolation.
