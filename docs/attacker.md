# Agent attack harness (`mcp_attack`)

Implementation of the red-team half of the audit → attack loop. The package is
standalone: it never imports `mcp_audit`. Alignment with the auditor is by
plain string tags (`rule_ids`, `owasp_amg_category`, `technique_category`) and
JSON reports.

## What the harness answers

1. Does an untrusted instruction persist into memory and surface later (same user, other user, or other session)?
2. Does tool output (search snippet, email, document) get treated as instructions rather than data?
3. Which delivery technique (direct override, obfuscation, many-shot, …) actually lands?
4. When a run is incomplete, was that a miss (`CLEAN`) or a gap (`NOT_EVALUATED` / `ERROR` / `INVALID`)?

Every attempt gets a verdict. The Attack-Success-Rate denominator is never
fabricated: `total==0` displays `n/a (0/0)`.

## Modes and access profiles

| Access profile | What the adapter can see | Typical adapter |
|---|---|---|
| `black_box` | chat in / chat out | `openai_compat`, `http_generic` |
| `grey_box` | chat plus some tool/MCP surface | `mcp_client`, `inprocess_stand` |
| `white_box` | memory inspection and/or ground truth | `callable`, `genai_invest` |

`single-turn` variants have no baseline phase (`INVALID` is structurally
impossible). `cross-user` / `cross-session-same-user` run
baseline → inject → consolidate → probe. `tool_result` and
`document_ingestion` have their own flows.

## Adapters

| `kind` | Box | When to use | Extra channels |
|---|---|---|---|
| `openai_compat` | black | Any OpenAI-compatible `/v1/chat/completions` | none |
| `http_generic` | black | Same, but custom field mapping (`response_path`, `messages_field`, `session_in_body`) | none |
| `mcp_client` | grey | Streamable-HTTP or stdio MCP server; `send` is `tools/call` | none (no tool staging unless the server allows it) |
| `genai_invest` | white (if Mongo configured) | This repo's investment stand | finalize, optional Mongo/Redis, docker-log ground truth |
| `callable` | whatever you wire | In-process memory library (mem0, LangGraph, tests) | whatever callables you pass |

Credentials are never in config: set `MCP_ATTACK_CRED_<credential_ref>`.

## Connect a new agent in ~40 lines (white-box)

`CallableAdapter` is the documented onboarding path for a memory library.
JSON config cannot express live Python callables — build the adapter in code:

```python
from mcp_attack.adapters.callable_adapter import CallableAdapter
from mcp_attack.models import Channel, ChannelRole, Principal
from mcp_attack.detectors.literal import LiteralDetector
from mcp_attack.runner import run_matrix
from mcp_attack.tracer import JSONLTracer

store = {}  # stand-in for mem0 / a LangGraph checkpointer

def send(principal_id, session_id, message):
    memory = store.get("global", "")
    return f"{memory} (ack {message[:40]})"

def consolidate(principal_id, session_id):
    store["global"] = store.get("pending", store.get("global", ""))

def inspect(principal_id):
    return store.get("global", "")

def reset():
    store.clear()
    return True

adapter = CallableAdapter(
    send_fn=send, consolidate_fn=consolidate, inspect_fn=inspect, reset_fn=reset,
    access_profile="white_box",
)
```

Black-box, one command, no config file:

```bash
python -m mcp_attack quickstart \
  --url http://localhost:8600/v1 --model my-agent \
  --out .attack --report-html .attack/run.html
```

Audit then attack (ranked by finding severity, trifecta, P3 campaigns; same
`path_state` vocabulary as `mcp_audit` / `redteam/`):

```bash
python -m mcp_audit audit examples/genai_invest_stand.local.manifest.json --json .audit/stand.json
python -m mcp_attack quickstart --url http://localhost:8600/v1 --model my-agent \
  --audit .audit/stand.json --out .attack
```

`--pool auto` (quickstart default) loads `catalog/prompts/domain/invest_bank`
on top of the generic pool when `meta.profile.id` is this repo's invest stand;
a mempalace / unknown profile stays on `generic/`. Each `AttackResult` carries
`path_state` so a run can close the static → runtime loop without importing
`mcp_audit`.

Same function the notebook calls: `mcp_attack.pipeline.audit_then_attack`.

## Taxonomy

Three independent tag sets on every variant:

| Field | Vocabulary | Meaning |
|---|---|---|
| `owasp_amg_category` | 6 OWASP Agent Memory Guard slugs | *what* is being poisoned (memory / tool-output) |
| `technique_category` | delivery/obfuscation slugs in `taxonomy.ATTACK_TECHNIQUE_CATEGORIES` | *how* the payload is delivered |
| `taxonomy` | MITRE ATLAS ids (`AML.T0051`, `AML.T0070`, …) | cross-reference |
| `rule_ids` | `mcp_audit` rule catalogue | optional link to a specific audit |

`python -m mcp_attack validate-catalog mcp_attack/catalog/prompts --strict-taxonomy`
requires AMG on every `memory_poisoning` variant and ATLAS **or**
`technique_category` on every non-benign variant.

| Source | Classes covered |
|---|---|
| Neutral core `catalog/prompts/generic` | 6 AMG categories + 10 technique categories (direct, authority, obfuscation, splitting, many-shot, refusal, roleplay, low-resource language, tool-result, context-ignore) |
| Domain overlay `catalog/prompts/domain/invest_bank` | same AMG set, bank-flavored wording |
| Imported banks (`garak_dan`, `trustairlab_jailbreak`) | `threat_model=llm_jailbreak_susceptibility` (separate ASR axis) |

Path map: [`docs/catalog_paths.md`](catalog_paths.md).

## Do / don't (ASR invariants)

- Do emit a `Verdict` for every attempt, including `ERROR` and `NOT_EVALUATED`.
- Do keep `INVALID` / `ERROR` / `NOT_EVALUATED` out of the ASR ratio; they still appear in `counts_by_verdict`.
- Do return `NOT_EVALUATED` when the adapter cannot stage a tool vector or ingest a document — never a false `CLEAN`.
- Don't import `mcp_audit` from `mcp_attack`.
- Don't embed secrets in config; only `credential_ref` → `MCP_ATTACK_CRED_<ref>`.
- Don't add third-party HTTP/SDK deps on the black-box path (stdlib `urllib` only).

## Moving the pool to a new domain

1. Run the **neutral** core (`--pool neutral` / `catalog/prompts/generic`).
2. Optionally rewrite wording with `domain_adaptation` (LLM) and a `DomainProfile`
   (`generator.options.domain_profile`, or `profile_from_audit(audit.json)`).
3. Keep bank-specific overlays under `catalog/prompts/domain/<name>/` rather than
   mixing them into the generic tree.

Net-new prompts: `LLMSynthesisGenerator` (`kind=llm_synthesis`). Adaptive
retries: `python -m mcp_attack run --adaptive --attacker-base-url … --attacker-model …`.
