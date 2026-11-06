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

**Description:** An agent attempts to approve its own actions, forge an approval,
replay one, or spend it on a different action.

**MVP Mitigation:** Approval service is separate, replay protection, expiry.

**Phase 9 mitigation:** the enforcement point records the request and never
executes on `Ask`; every request carries an action digest that `consume()`
re-derives; consumption is an atomic `Approved -> Consumed` transition inside a
SQLite `BEGIN IMMEDIATE` transaction, so concurrent consumers cannot both spend
it; a pending request can only be decided once.

**Phase 10 mitigation:** the digest now also covers `cwd`, `repository`,
`branch`, `task_id`, `client_ip` and `host` — the fields that can change either
the policy decision (`location` conditions, plugin inputs) or the meaning of the
operation (a relative path). `consume()` re-derives it, so an approval issued in
one directory or from one location cannot be spent elsewhere. Cross-process
consumption is covered by a two-process test.

**Residual Risk:** `agentfence approve` is **not authenticated** — anyone able
to run it in the operator's environment can decide any pending request. The
trust boundary is the terminal itself. A compromised agent process cannot
approve anything, but a compromised terminal can.

### Stale Approval

**Description:** An approval is reused after expiration, or a pending request is
approved long after it was issued.

**MVP Mitigation:** Expiry checking, validation.

**Phase 9 mitigation:** a request expires after `AGENTFENCE_APPROVAL_TTL_MINUTES`
(default 30). An expired request can neither be decided nor consumed.

**Residual Risk:** None within the configured window — an expired approval is
rejected and the action stays blocked.

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

**Mitigation:** Network policy evaluation, HTTPS CONNECT tunnel inspection, rate limiting (shared token bucket), request body hashing, connection pooling.

**Residual Risk:** Medium — HTTPS tunnel content is encrypted and cannot be inspected.

### Local Storage Exposure

| Asset | Threat | Mitigation | Residual risk |
|---|---|---|---|
| Approval store (`approvals.db`) | Another local account reads pending approvals, including command text | Directory restricted to the current account when AgentFence creates it; DB files always restricted | Pre-existing directories are reported, not hardened |
| Audit store (`agentfence.db`) | Audit trail read or tampered with | Same as above; hash chain detects tampering | No encryption at rest |
| Credentials in command text | A credential embedded in a command is written to disk or logs | `agentfence_secrets::redact` masks high-confidence shapes before persistence or display | Pattern-based; unknown shapes are not masked |
| Journal files (`-wal`, `-shm`, `-journal`) | SQLite side files carry the same content as the DB | Restricted to the current account on open | None beyond the DB itself |
| Operator approval authority | Any process that can run `agentfence approve` as the operator can approve | Approvals are digest-bound, single-use, scoped, and expiring | No separate operator authentication; documented trust boundary |
| Direct store modification | Code running as the operator edits the DB | None | AgentFence does not protect against its own OS account |

**Windows-specific:** `icacls /inheritance:r` applied to a directory strips
inherited ACEs from every child object, leaving pre-existing files with an
empty DACL. AgentFence therefore never rewrites a pre-existing directory; it
reports it and restricts only directories it creates.

### Container Escape

| Asset | Threat | Mitigation | Residual risk |
|---|---|---|---|
| Host kernel | Container escape through a kernel vulnerability | Non-root user, `--cap-drop ALL`, `no-new-privileges`, read-only root FS, resource limits, no network | Kernel exploits are not mitigated by container isolation |
| Host container runtime | Mounting the host runtime socket to gain runtime control | Socket mounts rejected during configuration validation | A runtime bug is not mitigated |
| Host filesystem | Reading or modifying host files | Only explicit, validated mounts; default is none | Every declared mount is fully accessible to the container |
| Host network | Exfiltration or lateral movement | `--network none` by default | Any enabled network path is fully accessible |
| Host resources | CPU, memory, or PID exhaustion | `--cpus`, `--memory`, `--memory-swap`, `--pids-limit`, timeout with container kill | Limits are runtime-enforced, not guaranteed against a runtime bug |

## Threats AgentFence Can Mitigate

- Unauthorized shell commands
- Unauthorized MCP tool calls
- Unauthorized network requests
- Secret disclosure in controlled paths
- Approval replay
- Expired approval reuse
- Log tampering (detection)
- Network rate limiting (shared token bucket)
- Plugin sandboxing (fingerprint verification, runtime timeout, worker-thread isolation)
- Native plugin worker concurrency cap (`MAX_PLUGIN_WORKERS`) — bounds thread growth from plugins that never return; does not terminate them
- WASM plugin sandboxing (Wasmtime 48.0.7, fuel-based interruption, real memory/table limits, empty linker with no WASI or host imports, SHA-256 fingerprint verification, 10 MB module size limit)
- Plugin results applied at the PDP (`Pdp::with_plugin_registry`) — plugins can only **tighten** a decision; a plugin `Allow` is abstained
- Case-insensitive shell deny matching — closes case-based deny evasion (Windows executables are case-insensitive)
- Denied operations never reach their backend: MCP denied/ask writes a JSON-RPC error and nothing to the upstream server's stdin; network denied/ask writes `403` and never opens a destination connection; shell denied exits before `Command::status()` (all three are covered by side-effect tests)
- Audit argument hashing is a real SHA-256 digest over the evaluated command, and the audit event's `action_id` is the action that was actually evaluated

## Threats AgentFence Can Only Observe

- Direct child process execution
- Uncontrolled network activity
- Filesystem access outside controlled paths

## Threats AgentFence Cannot Mitigate

- OS-level attacks
- Kernel exploits
- Physical access attacks
- Compromised AgentFence process
- Bypass through unmanaged processes
- HTTPS tunnel content inspection (encrypted)
