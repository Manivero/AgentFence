# AgentFence MCP Integration

## Architecture

```
Agent -> AgentFence MCP Proxy -> MCP Server
```

The MCP proxy evaluates tool calls before forwarding them to MCP servers.

## Tool Call Evaluation

For each MCP action, the proxy evaluates:
- Tool name
- Arguments
- Server identity
- Session
- Policy
- Repository/path/host context

## MVP Transport

**stdio** — The MVP uses stdio transport for MCP communication.

## Future Transports

- HTTP
- SSE
- Authentication
- Schema discovery
- Cancellation
- Protocol versioning

## Security Considerations

- Never trust tool metadata blindly
- Do not assume all MCP servers behave identically
- Design protocol handling behind an abstraction
- Evaluate every tool call before forwarding

## Example

```json
{
  "tool": "github.create_issue",
  "arguments": { "repo": "example/repo" }
}
```

The proxy evaluates this against the MCP policy and returns ALLOW, DENY, or ASK.

## Implementation Status

**Implemented.** The MCP proxy supports:
- stdio transport (JSON-RPC 2.0)
- Tool call interception and evaluation via PDP
- Request forwarding to MCP server
- Deny/Ask response handling with structured error messages
- CLI integration: `agentfence mcp proxy --server <name> --policy <path>`

### Usage

```bash
agentfence mcp proxy --server github --policy agentfence.yaml
```

The proxy spawns the MCP server process, intercepts `tools/call` requests, evaluates them against policy, and forwards allowed calls to the server. Denied calls receive a JSON-RPC error response.
