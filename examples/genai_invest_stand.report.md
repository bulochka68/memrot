# MCP audit report (passive mode)

- Overall risk: **HIGH**
- Servers: 2  Tools: 10
- Arbitrary code execution: **False**
- Lethal trifecta: **True**
- Full project access: **False**
- Confidence: 0.6 (basis: effective+verified)
- Reasons: lethal trifecta is assembled

## Tools

| Server | Tool | Class | Risk | Egress | Verified |
|---|---|---|---|---|---|
| mcp-invest | instruments_search | READ | MEDIUM | - |  |
| mcp-invest | portfolio_get_positions_valuation | READ | MEDIUM | - |  |
| mcp-invest | portfolio_presence_get | READ | MEDIUM | - |  |
| mcp-invest | register_tax_get | READ | MEDIUM | - |  |
| mcp-invest | client_operation_history_list | READ | MEDIUM | - |  |
| mcp-invest | client_training_list | READ | MEDIUM | - |  |
| mcp-invest | margin_instruments_list | READ | MEDIUM | - |  |
| mcp-invest | fin_instrument_prices_get | READ | MEDIUM | - |  |
| mcp-invest | ideas_list | READ | MEDIUM | - |  |
| agent-native | duckduckgo_search | READ | MEDIUM | yes |  |

## Security findings

- **[HIGH] MCP-001 LETHAL_TRIFECTA** - Lethal trifecta assembled: sensitive access + untrusted input + external channel all present.

## Definition-plane findings (tool poisoning surface)

- **[HIGH] UNCONSTRAINED_EXEC_PARAMETER** (mcp-invest/instruments_search) - instruments_search.query is a free string with no enum/pattern - arbitrary execution surface
- **[HIGH] UNCONSTRAINED_EXEC_PARAMETER** (agent-native/duckduckgo_search) - duckduckgo_search.query is a free string with no enum/pattern - arbitrary execution surface
- **[MEDIUM] HOMOGLYPH_MIXED_SCRIPT** (mcp-invest/instruments_search) - Latin text in description contains a few Cyrillic/Greek look-alike letters
- **[MEDIUM] HOMOGLYPH_MIXED_SCRIPT** (mcp-invest/portfolio_presence_get) - Latin text in description contains a few Cyrillic/Greek look-alike letters
