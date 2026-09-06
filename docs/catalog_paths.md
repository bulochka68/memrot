# Attack catalog path map

The prompt catalog was split into a **neutral core** and a **domain overlay**.
`discover_catalog_files` is recursive, so pointing at `memrot/catalog/prompts`
still loads everything. Prefer the new paths in configs and notebooks.

| Old path | New path | Domain |
|---|---|---|
| `memrot/catalog/prompts/generic_memory_prompt_injection` | `memrot/catalog/prompts/generic/generic_memory_prompt_injection` | neutral |
| `memrot/catalog/prompts/generic_sensitive_data_leakage` | `memrot/catalog/prompts/generic/generic_sensitive_data_leakage` | neutral |
| `memrot/catalog/prompts/generic_protected_key_tampering` | `memrot/catalog/prompts/generic/generic_protected_key_tampering` | neutral |
| `memrot/catalog/prompts/generic_memory_integrity_violation` | `memrot/catalog/prompts/generic/generic_memory_integrity_violation` | neutral |
| `memrot/catalog/prompts/generic_bulk_injection_anomaly` | `memrot/catalog/prompts/generic/generic_bulk_injection_anomaly` | neutral |
| `memrot/catalog/prompts/generic_tool_output_instruction_injection` | `memrot/catalog/prompts/generic/generic_tool_output_instruction_injection` | neutral |
| `memrot/catalog/prompts/mem02_global_policy_poisoning` | `memrot/catalog/prompts/domain/invest_bank/mem02_global_policy_poisoning` | invest_bank |
| `memrot/catalog/prompts/mem01_03_cross_session_semantic_poisoning` | `memrot/catalog/prompts/domain/invest_bank/mem01_03_cross_session_semantic_poisoning` | invest_bank |
| `memrot/catalog/prompts/auth_tool_direct_bac_injection` | `memrot/catalog/prompts/domain/invest_bank/auth_tool_direct_bac_injection` | invest_bank |
| `memrot/catalog/prompts/framing_diversity` | `memrot/catalog/prompts/domain/invest_bank/framing_diversity` | invest_bank |
| `memrot/catalog/prompts/benign_control` | `memrot/catalog/prompts/domain/invest_bank/benign_control` | invest_bank |
| `memrot/catalog/prompts/tool_output_web_search_poisoning` | `memrot/catalog/prompts/domain/invest_bank/tool_output_web_search_poisoning` | invest_bank |

New neutral pools (no old path):

- `generic/generic_obfuscation_encoding`
- `generic/generic_payload_splitting`
- `generic/generic_many_shot`
- `generic/generic_refusal_suppression`
- `generic/generic_context_ignore`
- `generic/generic_low_resource_language`
- `generic/generic_tool_email_injection`
- `generic/generic_tool_document_injection`
- `generic/generic_tool_websearch_injection`

MemPalace overlay (domain `mempalace`, no old path) — the attack-side port of
the foreign system audited in [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md).
Each variant attacks a control that audit reports FAIL on the recorded build,
and cites the located source fact (tool/symbol) in its `notes`:

| Path | Attacks (rule_ids) | AMG category |
|---|---|---|
| `domain/mempalace/mem_cross_agent_drawer_poisoning` | MEM-03, MEM-01 | memory_prompt_injection / sensitive_data_leakage |
| `domain/mempalace/mem_audience_bypass_recall` | MEM-01, MEM-07 | sensitive_data_leakage |
| `domain/mempalace/auth_identity_spoofing` | AUTH-01, MEM-03 | memory_prompt_injection |
| `domain/mempalace/peer_sync_exfiltration` | EGRESS-01, MEM-01 | sensitive_data_leakage |
| `domain/mempalace/benign_control` | — | — |

The overlay stays out of `--pool auto` (a mempalace audit resolves to the
generic pool, same portability split as the auditor); load it explicitly via
`examples/mempalace.attack.config.json`'s `catalog_paths` or `--pool all`.
