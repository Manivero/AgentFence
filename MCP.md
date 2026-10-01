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

**Not yet implemented.** The MCP proxy structure is defined but the actual proxy implementation is pending.
