# MCP audit report (passive mode)

- Overall risk: **CRITICAL**
- Servers: 4  Tools: 6
- Arbitrary code execution: **True**
- Lethal trifecta: **True**
- Full project access: **True**
- Confidence: 0.6 (basis: effective+verified)
- Reasons: arbitrary command execution is available; lethal trifecta is assembled; write access to project data

## Tools

| Server | Tool | Class | Risk | Egress | Verified |
|---|---|---|---|---|---|
| filesystem | read_file | READ | HIGH | - |  |
| filesystem | write_file | WRITE | HIGH | - |  |
| filesystem | delete_file | DELETE | CRITICAL | - |  |
| postgres | query | READ | HIGH | - |  |
| shell | execute_command | EXEC | CRITICAL | yes |  |
| fetch | fetch | READ | MEDIUM | yes |  |

## Security findings

- **[CRITICAL] MCP-001 ARBITRARY_CODE_EXECUTION** - One or more tools can execute arbitrary commands: shell/execute_command
- **[CRITICAL] MCP-002 DESTRUCTIVE_OPERATIONS** - Tools can delete/destroy data: filesystem/delete_file
- **[CRITICAL] MCP-004 LETHAL_TRIFECTA** - Lethal trifecta assembled: sensitive access + untrusted input + external channel all present. A single tool holds all three: ['shell/execute_command'].
- **[HIGH] MCP-003 PROJECT_WRITE_ACCESS** - 2 tool(s) can modify data

## Definition-plane findings (tool poisoning surface)

- **[HIGH] UNCONSTRAINED_EXEC_PARAMETER** (postgres/query) - query.sql is a free string with no enum/pattern - arbitrary execution surface
- **[HIGH] UNCONSTRAINED_EXEC_PARAMETER** (shell/execute_command) - execute_command.command is a free string with no enum/pattern - arbitrary execution surface
