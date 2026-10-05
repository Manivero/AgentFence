# AgentFence Policy Language

## Overview

AgentFence uses YAML for policy configuration. The policy is parsed into a typed internal representation and evaluated deterministically.

## Policy File

Default location: `agentfence.yaml`

## Schema

```yaml
version: 1

defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny

filesystem:
  read:
    allow:
      - "./project/**"
  write:
    allow:
      - "./project/**"
  deny:
    - "~/.ssh/**"
    - "~/.aws/**"
    - "**/.env"
    - "**/*.pem"

shell:
  allow:
    - git
    - cargo
    - npm
    - python
  deny:
    - powershell
    - reg
    - netsh

network:
  allow:
    - github.com
    - crates.io
    - registry.npmjs.org

mcp:
  allow:
    - github
    - filesystem
```

## Decision Values

- `allow` — Explicitly allow
- `deny` — Explicitly deny
- `ask` — Require approval

## Ask List

Each policy section (shell, network, mcp) supports an `ask` list. Commands/tools/hosts
matching an `ask` entry require human approval before execution.

```yaml
shell:
  allow:
    - git
  ask:
    - npm        # npm install requires approval
    - docker     # docker build requires approval
  deny:
    - powershell
```

## Defaults

If no rule matches, the default decision is used.

## Path Matching

Supports glob-like patterns:
- `**` — Matches any depth of directories
- `*` — Matches within a path segment

Examples:
- `./project/**` — All files under `./project/`
- `~/.ssh/**` — All files under `~/.ssh/`
- `**/.env` — All `.env` files
- `**/*.pem` — All `.pem` files

## Shell Matching

Shell commands are matched by executable name:
- `git` — Matches `git status`, `git push`, etc.
- `cargo` — Matches `cargo build`, `cargo test`, etc.

## Network Matching

Network requests are matched by host:
- `github.com` — Matches `https://github.com/...`
- `crates.io` — Matches `https://crates.io/...`

## MCP Matching

MCP tools are matched by tool name:
- `github` — Matches `github.create_issue`, etc.
- `filesystem` — Matches `filesystem.read`, etc.

## Policy Evaluation Order

1. Check deny rules first
2. Check ask rules (require approval)
3. Check allow rules
4. Use default decision

## Policy Versioning

Policies have a version number. The version is included in audit events.

## Policy Hash

Policies have a hash computed from their content. The hash is included in audit events.
