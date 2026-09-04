# MCP agent audit subsystem (pipeline phase P1)

Implementation of the audit-subsystem architecture in
[`docs/audit_subsystem_architecture.md`](docs/audit_subsystem_architecture.md).

The audit produces **three linked answers**, not just a tool list:

1. **What the agent can actually do** — effective, not declared, rights.
2. **What is hidden inside the tool definitions** — descriptions and schemas are
   the tool-poisoning channel, invisible in a capability table.
3. **Whether the lethal trifecta is assembled** — sensitive access × untrusted
   input × outbound channel → an overall verdict.

It closes the original blind spot: definition-plane inspection is a
first-class layer here, not an afterthought.

## Two founding principles

**Three audit planes**

| Plane | Question | Layer |
|---|---|---|
| Capability | What can the agent do? | discovery + classification (1, 3) |
| Definition | What do the definitions themselves say? | static analysis (2) |
| Behavioral | What happens when we actually try? | active probes, sandbox only (4) |

**Three trust levels per fact** — every fact carries a provenance:
`declared` (server self-report, never trusted for the verdict), `effective`
(derived from config/permissions), `verified` (confirmed by an active probe).
The verdict is built from `effective + verified` only.

## Component layers

| Layer | Module | Role |
|---|---|---|
| 1 Discovery | `mcp_audit/discovery/` | config parser, live MCP introspector (stdio + HTTP/SSE), agent-context parser |
| 2 Static analysis | `mcp_audit/static_analysis/` | description linter, schema analyzer, collision detector, definition hasher, optional `mcp-scan` bridge |
| 3 Classification & risk | `mcp_audit/classification/` | READ/WRITE/EXEC/DELETE, LOW..CRITICAL, effective-access resolver |
| 4 Active verification | `mcp_audit/active/` | probe runner, boundary tester, isolation guard — **sandbox only** |
| 5 Trifecta / correlation | `mcp_audit/correlation/` | trifecta assessor, cross-server reasoner, verdict builder |
| 6 Findings & reporting | `mcp_audit/reporting/` | JSON emitter, baseline store, drift (P8), downstream feeders |
| Orchestrator | `mcp_audit/orchestrator.py` | single data model = the `audit` JSON, drives the layers per mode |

## Run modes

| Mode | Layers | Where | When |
|---|---|---|---|
| `passive` | 1, 2, 3, 5, 6 | anywhere, incl. near prod | regularly; touches nothing |
| `active` | + 4 probes | isolated stand (P0) only | when building the stand, before campaigns |
| `drift` | 1, 2 + hash compare | CI / on config change | on any MCP-config change |

The active layer really calls `tools/call` (it reads, writes, deletes, runs
commands), so the `IsolationGuard` refuses to run unless both `--sandbox` is
passed **and** `MCP_AUDIT_SANDBOX=1` is set inside the isolated stand.

## Usage

```bash
# passive audit -> JSON + Markdown report
python -m mcp_audit audit examples/mcp_config.example.json --json audit.json --md report.md

# also run Invariant Labs mcp-scan if it is installed
python -m mcp_audit audit config.json --live --mcp-scan

# active verification (ONLY inside the isolated P0 stand)
MCP_AUDIT_SANDBOX=1 python -m mcp_audit audit config.json --mode active --sandbox --live

# drift / rug-pull detection (P8)
python -m mcp_audit baseline config.json -o baseline.json
python -m mcp_audit drift config.json --baseline baseline.json --fail-on-drift

# gate CI on risk
python -m mcp_audit audit config.json --json audit.json --fail-on-risk   # exit 2 on CRITICAL
```

Python API:

```python
from mcp_audit.models import Mode
from mcp_audit.orchestrator import audit_from_config
from mcp_audit.reporting import emit_json

doc = audit_from_config("config.json", mode=Mode.PASSIVE)
print(doc.summary["overall_risk"], doc.verdict["lethal_trifecta"])
open("audit.json", "w").write(emit_json(doc))
```

## Config formats

The parser accepts the common MCP client shapes: `mcpServers` (Claude
Desktop / Cursor), `servers` (VS Code, JSONC with comments), a bare mapping,
or a list. Two non-standard, audit-only extensions are honored:

- `x_audit`: explicit effective-access overrides — `allowed_paths`,
  `denied_paths`, `operations`, `ddl`, `network_access`, `kind`.
- `tools`: an offline tools snapshot so a passive audit can run without
  spawning the server. A live handshake (`--live`) or a `--snapshot` file are
  the alternatives.

Secret **values** in `env` are never emitted — only the key names are kept.

## Output: the `audit` JSON (schema v1.1)

Extends the original `audit v1.0` with the `definition_analysis` section
(descriptions/schemas/hashes/collisions/`mcp-scan`) that closed the blind
spot. Top-level keys: `servers`, `agent_context`, `definition_analysis`,
`effective_capabilities`, `tests`, `security_findings`, `summary`, `verdict`,
`downstream` (P2 matrix rows, P3 corpus cases, P8 baseline keys), `drift`.

Component → JSON field mapping is in the architecture doc, section 7.

## What the definition plane catches

- Hidden / invisible Unicode and ASCII smuggled via the Unicode TAG block
  (`AML.T0068`), including keywords split by zero-width characters.
- Pseudo system/role markers (`<IMPORTANT>`, `SYSTEM:`), instruction
  overrides, concealment ("do not tell the user").
- Cross-tool steering and cross-server references (shadowing indicators).
- Duplicate / look-alike tool names across servers (shadowing precondition).
- Sink parameters (free-form fields a poisoned description routes data into),
  secret-shaped parameters, unconstrained exec parameters, schema/purpose
  mismatch, sensitive default paths, annotation lies (`readOnlyHint` on a
  mutating tool).
- Authorization steering / IDOR: a parameter description that tells the model
  to pass an arbitrary or user-named identifier into an access-scoping field
  (broken access control delegated to the LLM).

Detection is **bilingual (English + Russian)**: injection/override/concealment/
steering patterns, operation verbs, and sensitive-data markers all have Russian
variants. The homoglyph check is word-level, so Cyrillic prose with Latin
technical tokens (ISIN, tickers, product names) is not a false positive — only a
single token that mixes scripts is flagged.

A worked example against a real, deliberately vulnerable stand
(`examples/genai_invest_stand.config.json`, an HTTP MCP investment server plus a
web-search tool) is in `examples/genai_invest_stand.report.md`: it assembles the
lethal trifecta and catches the IDOR in the `cus` parameter.

## Tests

```bash
pip install pytest
python -m pytest -q
```

58 tests cover config parsing, the definition linter (incl. Unicode smuggling
and Russian-language injection/steering/IDOR), the schema analyzer,
classification and effective access, collisions and hashing, the
trifecta/verdict, JSON/Markdown emission, drift (clean, rug pull, new server),
the isolation guard, and a full live active-probe run against a bundled mock
stdio MCP server (`tests/mock_mcp_server.py`).

## Scope

The audit is **diagnosis, not defense**: it shows the composition of risk, it
does not remove it. The active plane runs only in the isolated stand. This is
an architectural/hardening tool for your own MCP configuration.
