# AgentFence Security Model

## Protection Mode

**AgentFence is currently in cooperative mode.**

```
Protection Mode:   COOPERATIVE
Security Boundary: LIMITED
```

Only actions routed through AgentFence are controlled. This is **not** a complete OS security boundary.

## Security Invariants

These rules may never be broken — not temporarily, not for convenience, not for tests.

1. **LLM is never the authorization authority.** Authorization is deterministic policy evaluation. LLMs may explain, summarize, or analyze — never decide ALLOW/DENY.

2. **Intent is not permission.** Task descriptions, prompts, plans, and session context are contextual evidence only.

3. **No self-approval.** The agent under control must never be able to approve its own actions, mutate approval state, forge approvals, replay approvals, or bypass the approval service.

4. **No silent privilege expansion.** Never broaden permissions to make tests pass, to make Hermes work, to make MCP work, to make a package install work, or to make a demo work.

5. **No secrets in logs.** Never write raw passwords, API keys, tokens, cookies, private keys, or credentials to audit, stdout, stderr, telemetry, or debug dumps.

6. **No fabricated capabilities.** Never claim AgentFence protects something it does not protect.

7. **Never weaken a security control to make a test or integration pass.** Fix the test, fix the design, or document the limitation.

8. **Never hide a failing test.** Surface it, diagnose it, fix it, or document it as a known limitation.

9. **Cooperative mode is limited.** Never claim OS-wide, process-wide, or host-wide enforcement that does not exist.

10. **The local repository is the source of truth.** Inspect it before changing it.

## Plugin Security

- **Native plugins** are a separate, trusted mechanism: timeout enforcement and
  worker-thread isolation (cooperative mode — no memory/CPU isolation)
- **WebAssembly plugins** execute as real WebAssembly **components** inside a
  Wasmtime sandbox:
  - Real component-model isolation (not a cooperative timeout wrapper)
  - Fuel-based interruption (a non-terminating guest is stopped within budget)
  - Real memory and table limits (`Store::limiter` + `StoreLimits` on the store)
  - **Empty linker** — no WASI, no host imports, so no filesystem, network,
    environment or process capability can be reached
  - Module fingerprint verification (SHA-256) over the exact bytes executed
  - Module size limit (10 MB) and bounded action size
- Plugin results are sanitized: decision 3 (Allow) → abstain; Deny/Ask preserved
- Plugin results are applied at the PDP: `Pdp::with_plugin_registry` consults the
  registry and can **tighten** a decision (plugin `Deny`/`Ask` overrides a core
  `Allow`) but can never loosen it. `Pdp::new` does not consult plugins, so no
  existing call site changes behaviour.
- Traps, malformed results and fuel exhaustion are explicit execution failures —
  never an Allow
- Plugin failures are logged and ignored (fail-safe)
- **Configuration surface:** `agentfence.yaml` has an optional `plugins:` section.
  Every enforcement entry point (CLI `exec`, `run`, `mcp`, `network`, and the
  Hermes wrapper) builds its PDP through
  `agentfence_policy::plugin_loader::build_pdp`, so configured plugins are
  consulted on every gateway rather than in one of them. See
  `examples/plugins.yaml` and `POLICY.md` "Policy Plugins".
- **Load failures are fatal, not silent:** a configured, enabled plugin that is
  missing, unreadable, or whose fingerprint does not match fails the whole load
  and the process refuses to start enforcement. Starting with a partially loaded
  plugin set would silently drop the restrictions an administrator configured,
  so this fails closed with the plugin id in the error message.
- **Native plugins follow a distinct trust model:** the `native:` section may
  only *reference* a plugin that the embedding application registered
  programmatically before the policy was loaded. `agentfence.yaml` can never
  introduce native code, and an id the host did not register is a validation
  error. No production entry point registers native plugins today, so a
  `native:` entry fails closed rather than being ignored.
- **Disabled plugins do not execute:** an entry with `enabled: false` is never
  registered, so it cannot influence a decision at all.
- **Per-plugin resource limits:** `max_memory_mb` on a WebAssembly entry is
  enforced by the sandbox (`Store::limiter`) over the exact bytes compiled.
  Fuel, module size (10 MB) and action size are sandbox-global and are not
  per-plugin configurable yet.
- **Bounded worker concurrency:** native plugin worker threads are capped at
  `MAX_PLUGIN_WORKERS` (16). A plugin that never returns cannot grow the thread
  count without bound; once the cap is reached, further plugins are skipped
  (fail-closed). This bounds resource growth but does **not** terminate a stuck
  thread — reliable termination is not guaranteed by the current architecture.
- Plugin API is versioned and stable
- Fixtures are committed and regenerable via `crates/wasm-plugin/build-fixtures.sh`

## Trust Boundaries

| Boundary | Trust Level |
|----------|-------------|
| User | High |
| AgentFence CLI | High |
| AgentFence PDP | High |
| AgentFence PEP | High |
| AgentFence Audit | High |
| AgentFence Approval | High |
| AI Agent | Low |
| MCP Server | Low |
| Shell Commands | Low |
| Network Resources | Low |

## Context Provenance

Authorization context is only as trustworthy as its source. Each gateway fills
`Context` from the most trusted source available to it:

| Gateway | `host` source | `client_ip` source |
|---------|---------------|--------------------|
| MCP | `McpToolCall.server` (server identity from the tool call) | not available |
| Network | parsed request target host | not available |
| Shell | `TrustedShellContext.host` (verified by the trusted integration layer) | `TrustedShellContext.client_ip` |

### Shell: structural enforcement

`ShellCommand` is **untrusted input** — it is parsed from a raw command string an
agent controls. It cannot carry location metadata:

- the `env_metadata` field has been **removed**; there is no public field or
  setter for one (enforced by the `compile_fail` doc-tests on `ShellCommand`);
- verified location data lives in a separate `TrustedShellContext` with
  **private fields** and **no public `Default`**;
- the only constructor requires a `TrustedContextToken`, whose own constructor
  is private to `agentfence-shell`. Tokens are minted by
  `ShellGateway::issue_trusted_context_token()`.

Consequences:

- **Untrusted input cannot assert its own `host`/`client_ip`.** It cannot build
  a `TrustedShellContext`, so it cannot reach `evaluate_with_context` with one.
- **The untrusted path (`evaluate`) supplies no location data**, so any location
  condition that requires a value fails closed (DENY).
- **`cmd.raw` is never parsed for a location.** A command that names a host does
  not authorise itself.

Rules:

- **Missing values stay `None`.** No fabricated defaults; the condition fails
  closed.
- **The token is a capability marker, not a cryptographic proof, and it is not a
  sandbox for in-process code.** `issue_trusted_context_token` is `pub`, and
  `ShellGateway::new` / `Pdp::new` are public, so any code running in the process
  can construct a gateway and mint tokens. The boundary that actually holds is
  that no untrusted component is *given* a gateway: `PluginContext` exposes no
  gateway or PDP, and the MCP/Network proxies hold a `Pdp` directly. Within one
  process the type system cannot distinguish trusted from untrusted *code* —
  only trusted from untrusted *data* — and that is exactly what this boundary
  enforces. Cooperative-mode code can bypass AgentFence entirely (see
  Cooperative Mode).

## Decision Model

Every authorization decision is structured:

```text
Decision {
    result: ALLOW | DENY | ASK
    rule_id: string
    reason: string
    evidence: ...
    risk_level: ...
    policy_version: ...
}
```

No bare `DENIED`. Every decision carries structured evidence.

## Risk Model

Risk is **advisory**, never authoritative. Authorization remains `Policy → Decision`.

Risk levels: LOW / MEDIUM / HIGH / CRITICAL

Risk is explainable through `rule_id`, `reason`, `evidence`.

## Audit Model

Audit events are tamper-evident through a hash chain:

```
event_1 → hash_1
event_2 + hash_1 → hash_2
event_3 + hash_2 → hash_3
```

Verification: `agentfence audit verify --session <id>`

Output: VALID / INVALID / INCOMPLETE

**Note:** Audit logs are tamper-evident, not tamper-proof. The underlying storage remains user-modifiable.

## Approval Model

Approval is a separate trust boundary from policy. Policy decides whether a
human is *needed*; a human decides whether the action proceeds.

### Lifecycle

```text
Pending -> Approved -> Consumed     (one execution)
Pending -> Rejected
Pending -> Approved -> Expired      (never executed)
```

A request is created by the enforcement point when the PDP returns `Ask`. The
side effect is prevented while it is outstanding.

### Binding

Every request stores a SHA-256 digest of the action being authorised. It covers
action type, tool, target, argument hash, session id, agent id **and the
authorization-relevant context**: `cwd`, `repository`, `branch`, `task_id`,
`client_ip`, `host`. Consuming the approval re-derives that digest, so an
approval cannot authorise a different command, tool call, target, session,
agent, directory or location.

`env_metadata` is deliberately excluded: it is untyped, untrusted, and consulted
by neither the PDP nor plugins.

### Information disclosure

`agentfence approve list` and `show` print the command text, because the operator
cannot decide without seeing what they authorise. When the command matches a
known credential pattern, a warning is printed to **stderr** listing the detected
categories — never the value, and never on stdout where it could be captured by
another tool. The command itself is still stored, in plaintext, in the local
approval database and audit trail. A credential embedded in a command is
therefore visible to the operator and persisted on their machine; that is a
property of a human approval step, and it is stated here rather than hidden.

### Replay and atomicity

- Consumption is a single atomic transition (`Approved` -> `Consumed`) inside a
  SQLite `BEGIN IMMEDIATE` transaction. Concurrent consumers, including separate
  processes, cannot both spend the same approval.
- Expired requests cannot be decided or consumed.
- A pending request can only be decided once.

### CLI

```bash
agentfence approve list              # pending requests
agentfence approve list --all        # decided, expired and consumed too
agentfence approve show <approval_id>
agentfence approve <approval_id> --decision allow
agentfence approve <approval_id> --decision deny
agentfence approve <approval_id>     # interactive
```

The command keys on the `approval_id` printed by the enforcement path. It refuses
any id that is not in the store. It can accept or refuse a request, but it cannot
widen the scope: the scope is fixed when the request is created.

### Trust assumption

`agentfence approve` is **not authenticated**. The trust boundary is the
operator's terminal — anyone able to run it in that environment can decide any
pending request.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AGENTFENCE_APPROVAL_DB` | `<data dir>/approvals.db` | shared approval store |
| `AGENTFENCE_APPROVAL_TIMEOUT_MS` | `300000` | how long a gateway waits for a human |
| `AGENTFENCE_APPROVAL_TTL_MINUTES` | `30` | how long a request stays valid |

The broker and the CLI must agree on `AGENTFENCE_APPROVAL_DB`, otherwise a
decision would never be seen.

## Approval Model

Approvals are issued through an external control surface (CLI or UI), never through the agent's own channel.

Supported scopes:
- `once` — Single use
- `session` — Valid for the session
- `repository` — Valid for the repository
- `path` — Valid for the path
- `host` — Valid for the host
- `expiry` — Valid until expiration

Approvals are narrow by default. Never promote a one-shot approval into a permanent permission unless the user explicitly asks.

## Local Storage Security

### What is stored, and where

| Data | Location | Written by |
|---|---|---|
| Approval records (redacted target, digest, scope, expiry) | `approvals.db` | `agentfence-approval` |
| Audit events (redacted target, `args_hash`, decision, rule) | `agentfence.db` | `agentfence-audit` |
| Approval / audit journal files | `*-wal`, `*-shm`, `*-journal` next to the DB | SQLite |
| AgentFence stdout/stderr | operator terminal or log capture | `agentfence-cli` |
| `AGENTFENCE_DATA_DIR` | operator-chosen; default `%APPDATA%gentfence` | operator |

### Credential exposure

`Action::target` for shell actions is the raw command line. AgentFence redacts
high-confidence credential shapes before that text is written to the approval
store, the audit store, the CLI display, or any log line. Redaction is
performed by `agentfence_secrets::redact` and covers GitHub, AWS, Google,
Slack, Stripe, npm, PyPI, bearer, JWT, and private-key patterns.

**Redaction is defence in depth, not an authorization control.** It matches
known shapes; a credential that does not match a known pattern is not masked.
The authorization decision is made by policy over the original action, and the
approval binding is the action digest, which is computed from the original
action and is unaffected by redaction.

`Action::args_hash` and the audit hash chain are computed from the original
values, so correlation and tamper-evidence are preserved.

### Filesystem permissions

`agentfence-core::secure_fs` restricts AgentFence-created directories to the
current OS account:

- **Unix**: directory `0700`, database files `0600`.
- **Windows**: the directory is restricted to the current user with
  `icacls /inheritance:r /grant:r <user>:F`.

**A pre-existing data directory is never rewritten.** On Windows,
`icacls /inheritance:r` applied to a directory also strips the inherited ACEs
of every child object, which leaves pre-existing files with an empty DACL and
locks the operator out of their own data. AgentFence therefore reports a
pre-existing directory as unverified and warns the operator to check it, rather
than modifying it.

Database files (`approvals.db`, `agentfence.db`, and their `-wal`/`-shm`/
`-journal` companions) are restricted to the current account whenever they are
opened, because files have no children and the operation is not destructive.

AgentFence does **not** claim host-wide filesystem protection. An OS
administrator, or code running under the same account, can read the stores.

### Operator authority

Approval authority is **possession of the local operator terminal**. Any
process that can run `agentfence approve` in the operator's session can approve
an action, and any process running as the same OS account can read or modify
the stores directly. AgentFence provides no separate operator authentication;
this is a documented trust boundary, not a control.

Approvals are narrow by default (`once`), bound to the action digest, and
expire. The agent cannot approve its own action: approvals are issued through
the CLI, never through the agent's own channel.

### Known limitations

- Redaction is pattern-based; unknown credential shapes are not masked.
- A pre-existing data directory is reported, not hardened.
- SQLite stores are protected by OS permissions only; they are not encrypted
  at rest. Disk encryption (BitLocker, FileVault, LUKS) remains the operator's
  responsibility.
- AgentFence does not protect against an OS administrator or code running under
  the same account.

## Container Execution Backend

AgentFence can execute policy-approved commands inside an isolated container
instead of directly on the host.

```text
Policy evaluation -> plugin evaluation -> approval (if required)
    -> execution backend -> container runtime -> container
```

### Selection

The backend is chosen once, from explicit configuration, before any command is
evaluated:

| Variable | Meaning |
|---|---|
| `AGENTFENCE_EXECUTION_BACKEND` | `host` (default) or `container` |
| `AGENTFENCE_CONTAINER_RUNTIME` | `docker` (default) or `podman` |
| `AGENTFENCE_CONTAINER_RUNTIME_PATH` | Explicit runtime executable path |
| `AGENTFENCE_CONTAINER_IMAGE` | Image reference (default `alpine:latest`) |
| `AGENTFENCE_CONTAINER_MAX_CPU` | CPU limit (default `1.0`) |
| `AGENTFENCE_CONTAINER_MAX_MEMORY_MB` | Memory limit (default `512`) |
| `AGENTFENCE_CONTAINER_PIDS_LIMIT` | Process limit (default `256`) |
| `AGENTFENCE_CONTAINER_TIMEOUT_SECS` | Wall-clock timeout (default `300`) |
| `AGENTFENCE_CONTAINER_RUN_AS_UID` / `_GID` | Container uid/gid (default `1000:1000`) |
| `AGENTFENCE_CONTAINER_NETWORK` | `none` disables networking |
| `AGENTFENCE_CONTAINER_READ_ONLY` | `true` mounts a read-only root filesystem |

**There is no host fallback.** If the container backend is selected and the
runtime is missing, misconfigured, or fails to start a container, the command
fails closed. No code path executes a command on the host instead.

### Controls applied to every container

| Control | Effect |
|---|---|
| `--user <uid>:<gid>` | Non-root execution; uid `0` is rejected by validation |
| `--read-only` | Root filesystem is read-only |
| `--cap-drop ALL` | No Linux capabilities |
| `--security-opt no-new-privileges:true` | Blocks setuid privilege escalation |
| `--cpus`, `--memory`, `--memory-swap`, `--pids-limit` | Resource ceilings |
| `--network none` | No host network by default |
| `--tmpfs /tmp:rw,nosuid,noexec,size=Nm` | Bounded, non-executable temp space |
| `--init` | Reaps zombie processes |
| `--rm --name <uuid>` | Automatic cleanup; named so a timed-out container can be killed |
| `--workdir` | Explicit working directory |
| `-v host:container[:ro]` | Only operator-listed mounts |
| `-e K=V` | Only operator-listed environment variables |

The host container runtime socket is never mounted: a mount whose host path
contains `docker.sock`, `containerd.sock`, or a Docker runtime directory is
rejected during configuration validation.

### What the container boundary protects against

- Direct modification of the host filesystem outside the declared mounts.
- Network access to the host network and to arbitrary hosts.
- Privilege escalation through capabilities or setuid binaries.
- Resource exhaustion through CPU, memory, or process-count abuse.

### What remains accessible

- Host files reachable through an explicitly declared mount (read-only or
  read-write, exactly as configured).
- Host process-tree visibility only insofar as the container runtime itself
  exposes it; `--pid` is not set, so the container has its own PID namespace.
- The container image and its contents, which must be trusted.
- Anything reachable through a kernel vulnerability in the host kernel.

### Explicit non-guarantees

- A container does **not** protect against a compromised host kernel.
- A container does **not** protect against a host administrator.
- A container does **not** make the policy decision; it only executes an
  already-approved action.
- Real isolation was verified only where a real runtime was available. The
  automated suite uses a **fake** runtime and proves invocation construction
  and fail-closed behaviour, not isolation.

### Real-runtime verification status

Real container isolation **was verified** against a real Docker Engine on
Windows 11 (Docker Desktop 4.98.0, Engine 29.9.2, WSL2 backend, Linux
containers), using `alpine:3.19` pinned by digest
`sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1`.

Verified by `docker inspect` and in-container measurement, not inferred from the
command line: non-root UID 1000, read-only root filesystem, `CapEff=0` with an
empty bounding set, `NoNewPrivs=1`, CPU/memory/swap/PID limits, `NetworkMode=none`,
`/tmp` as a writable tmpfs, timeout kill with no orphaned containers, and
stdout/stderr/exit-code propagation.

Scope of that claim:

- **Platform:** Windows 11 + WSL2 + Docker Desktop only. Linux Docker and Podman
  on any platform are unverified.
- **What is trusted:** the engine's own isolation (runc, overlayfs, seccomp).
  AgentFence configures these; it does not implement them.
- **Adversarially hardened in Phase 12.3** (see below); remaining
  file-replacement TOCTOU and host-mount races are documented, not eliminated.

The opt-in suites are the reproducible evidence:

```bash
AGENTFENCE_REAL_RUNTIME_TEST=1 cargo test -p agentfence-cli --test real_container_runtime -- --test-threads=1
AGENTFENCE_REAL_RUNTIME_TEST=1 cargo test -p agentfence-hermes --test real_container_backend -- --test-threads=1
```

#### Phase 12.3 hardening

Three classes of weakness were found and closed:

- **Runtime resolution TOCTOU.** The runtime executable was resolved separately
  for the `--version` probe, the container run, and cleanup, so a concurrent
  process could change `PATH` or swap a file between them. The executable is now
  resolved once, canonicalized, and cached; the same path is used for the probe,
  the run, and cleanup.
- **Mount validation by name only.** A symlink or Windows junction whose *name*
  was innocent could point at the host runtime socket or another protected path.
  Existing host paths are now canonicalized and checked against a blocklist using
  component-wise comparison, so `/srv/data` can never match `/srv/data-evil`.
- **Unstructured argument logging.** The log line joined arguments with spaces,
  so a payload containing spaces or shell metacharacters could be misread as a
  different command. Arguments are now logged as a JSON array, each element
  redacted individually.

Environment handling was tightened with a denylist of container-runtime control
variables (`DOCKER_*`, `CONTAINERD_*`, `AGENTFENCE_*`) and an optional configured
allowlist. The guest never inherits the host environment: Docker passes only the
values given with `-e`, and an empty value is sent as `KEY=`, never as a bare
`-e KEY` (which would inherit the host value).

**Remaining, documented races:**

- *File replacement after resolution.* A local attacker who can write to the
  resolved runtime binary can replace it after the probe. Closing this would
  require verifying the executable's identity at exec time, which
  `std::process::Command` cannot do. The runtime binary is therefore trusted.
- *Mount path replacement after validation.* A host path that does not exist at
  validation time is left to the runtime (Docker creates missing bind sources),
  so it could be created or replaced before the runtime resolves it. The Docker
  API offers no way to bind a file descriptor, so this cannot be closed from the
  client.
- *Daemon trust.* The daemon and its socket are trusted. AgentFence does not
  authenticate to the daemon or verify its identity.

Both skip every test unless `AGENTFENCE_REAL_RUNTIME_TEST=1` is set, so neither
can be mistaken for a passing verification on a machine without a runtime. With
the variable set but no daemon reachable, the CLI suite fails loudly and the
Hermes suite skips — neither reports success. The fake-runtime suite remains the
default and proves invocation construction and fail-closed behaviour only; it
provides no isolation.

### Execution entry points

Every path from a policy decision to a running process goes through the
selected `ExecutionBackend`:

| Entry point | Behaviour |
|---|---|
| `agentguard exec` | Backend selected once; allow and approved paths both route through it |
| `HermesWrapper` | Backend selected once; allow and approved paths both route through it |
| `agentguard run` | Spawns the supervised agent process, not shell commands |
| MCP proxy | Spawns the configured MCP server, not shell commands |
| `os_enforcement`, `vm`, `wsl` | Not wired to any execution path |

The Hermes wrapper previously spawned commands directly on the host, which
meant selecting the container backend for `agentguard exec` left Hermes on the
host. This was fixed and is covered by `crates/hermes/tests/backend_routing.rs`.

### Known container limitations

- **`/tmp` ownership.** `--tmpfs /tmp` is created by the runtime and may be
  owned by root. A non-root container user may not be able to write to `/tmp`.
  This is unverified without a real runtime and must be checked during
  real-runtime validation.
- **Check/use window.** The runtime is probed at backend creation and again at
  each execution, but a runtime can still disappear between the probe and
  `run`. A failure at that point is a fail-closed error, never a host
  execution.
- **Kill races.** `kill` is retried three times and `rm -f` follows. A runtime
  that ignores both can leak a container; that is a resource leak, not a
  privilege escalation.
- **Concurrent invocations.** Container names are UUID-derived, so concurrent
  executions cannot collide.
- **Mount access.** Every declared mount is fully accessible to the container,
  read-only or read-write exactly as configured. There is no partial mount.

## Known Limitations

- Cooperative mode only — no OS-level enforcement
- No filesystem enforcement
- No process enforcement
- No container/VM isolation
- Shell command parsing is POSIX-compliant (shell-words); complex shell features (process substitution, command substitution) are not fully parsed
- Network proxy supports HTTP and HTTPS CONNECT tunneling only
- MCP proxy supports stdio and HTTP transports; SSE is disabled (501); authentication not implemented
- Approval UI is terminal-only
- Rate limiting is shared across connections (token bucket via Arc<Mutex<>>); connection pooling with configurable max_size and idle timeout
