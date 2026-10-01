//! Init command implementation.

use std::fs;
use std::path::Path;

use tracing::info;

pub fn execute(output: &str) {
    let output_path = Path::new(output);
    let config_path = output_path.join("agentfence.yaml");

    if config_path.exists() {
        println!(
            "agentfence.yaml already exists at {}",
            config_path.display()
        );
        return;
    }

    let default_config = r#"# AgentFence Policy Configuration
# This is a default policy that denies all actions.
# Modify it to fit your needs.

version: 1

defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny

# Filesystem policy
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

# Shell policy
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

# Network policy
network:
  allow:
    - github.com
    - crates.io
    - registry.npmjs.org

# MCP policy
mcp:
  allow:
    - github
    - filesystem
"#;

    if let Err(e) = fs::write(&config_path, default_config) {
        eprintln!("Failed to write config: {}", e);
        std::process::exit(1);
    }

    info!("Created agentfence.yaml at {}", config_path.display());
    println!("Created agentfence.yaml at {}", config_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit agentfence.yaml to configure your policy");
    println!("  2. Run: agentfence policy check agentfence.yaml");
    println!("  3. Run: agentfence exec --policy agentfence.yaml -- git status");
}
