# AgentFence Threat Model

## Threat Categories

### Malicious Agent

**Description:** An AI agent attempts to perform unauthorized actions.

**MVP Mitigation:** Policy evaluation, approval workflow, audit logging.

**Residual Risk:** Agent may attempt to bypass gateways.

### Compromised MCP Server

**Description:** An MCP server returns malicious tool descriptions or arguments.

**MVP Mitigation:** Policy evaluation of tool calls, never trust tool metadata blindly.

**Residual Risk:** MCP server may behave unexpectedly.

### Malicious Tool Description

**Description:** A tool description contains misleading or harmful instructions.

**MVP Mitigation:** Policy evaluation based on actual action, not description.

**Residual Risk:** None — intent is not authoritative.

### Malicious Tool Arguments

**Description:** Tool arguments contain injection attempts or unauthorized targets.

**MVP Mitigation:** Policy evaluation of arguments, secret detection.

**Residual Risk:** Argument parsing may have edge cases.

### Accidental Secret Disclosure

**Description:** An agent accidentally includes secrets in commands or arguments.

**MVP Mitigation:** Secret detection, redaction, fingerprinting.

**Residual Risk:** False positives/negatives in detection.

### Command Injection

**Description:** Shell commands contain chaining, pipes, redirection, or subshells.

**MVP Mitigation:** Command parsing, dangerous pattern detection.

**Residual Risk:** Simplified parser may miss edge cases.

### Path Traversal

**Description:** File paths contain `..` or absolute paths to access unauthorized files.

**MVP Mitigation:** Path pattern matching, deny rules.

**Residual Risk:** Symlink attacks not fully addressed.

### Policy Bypass

**Description:** An agent attempts to bypass policy evaluation.

**MVP Mitigation:** PEP/PDP separation, no bypass paths.

**Residual Risk:** None — architecture prevents bypass.

### Approval Abuse

**Description:** An agent attempts to approve its own actions or replay approvals.

**MVP Mitigation:** Approval service is separate, replay protection, expiry.

**Residual Risk:** None — agent cannot access approval service.

### Stale Approval

**Description:** An approval is reused after expiration.

**MVP Mitigation:** Expiry checking, validation.

**Residual Risk:** None — expired approvals are rejected.

### Log Tampering

**Description:** An attacker modifies audit logs.

**MVP Mitigation:** Hash chain makes tampering evident.

**Residual Risk:** Attacker can delete logs, but cannot modify without detection.

### Compromised Local Agent Process

**Description:** The agent process is compromised.

**MVP Mitigation:** None — cooperative mode.

**Residual Risk:** High — agent can bypass gateways.

### Malicious Child Process

**Description:** A child process performs unauthorized actions.

**MVP Mitigation:** None — not visible to AgentFence.

**Residual Risk:** High — child processes are not controlled.

### Network Exfiltration

**Description:** An agent exfiltrates data through network requests.

**MVP Mitigation:** Network policy evaluation (when implemented).

**Residual Risk:** High — network proxy not yet implemented.

## Threats MVP Can Mitigate

- Unauthorized shell commands
- Unauthorized MCP tool calls
- Unauthorized network requests (when implemented)
- Secret disclosure in controlled paths
- Approval replay
- Expired approval reuse
- Log tampering (detection)

## Threats MVP Can Only Observe

- Direct child process execution
- Uncontrolled network activity
- Filesystem access outside controlled paths

## Threats MVP Cannot Mitigate

- OS-level attacks
- Kernel exploits
- Physical access attacks
- Compromised AgentFence process
- Bypass through unmanaged processes
