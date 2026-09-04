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
- **[HIGH] MCP-002 TOOL_POISONING_AUTHORIZATION_STEERING** (mcp-invest/portfolio_get_positions_valuation) - Parameter description steers the model to pass an arbitrary identifier (IDOR / broken access control) in description: 'значение из поля user_id текущего чата или любое другое'

## Definition-plane findings (tool poisoning surface)

- **[HIGH] AUTHORIZATION_STEERING** (mcp-invest/portfolio_get_positions_valuation) - Parameter description steers the model to pass an arbitrary identifier (IDOR / broken access control) in description: 'значение из поля user_id текущего чата или любое другое'
- **[MEDIUM] MODEL_ADDRESSED_IMPERATIVE** (mcp-invest/instruments_search) - Imperative addressed to the model in description: 'Используй этот тул первым'
