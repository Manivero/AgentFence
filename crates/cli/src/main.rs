//! AgentFence CLI.
//!
//! User interaction layer. Commands:
//! agentfence init
//! agentfence run --policy agentfence.yaml -- hermes
//! agentfence mcp proxy --server github --policy agentfence.yaml
//! agentfence exec --policy agentfence.yaml -- git status
//! agentfence logs --session <id>
//! agentfence approve <action_id>
//! agentfence policy check agentfence.yaml
//! agentfence policy test agentfence.yaml
//! agentfence audit verify --session <id>

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentfence")]
#[command(about = "AgentFence — local policy/approval/audit broker for AI agents")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize AgentFence configuration
    Init {
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,
    },
    /// Run an agent through AgentFence
    Run {
        /// Policy file path
        #[arg(short, long)]
        policy: String,
        /// Agent to run
        agent: String,
    },
    /// Start MCP proxy
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },
    /// Start network proxy
    Network {
        /// Policy file path
        #[arg(short, long)]
        policy: String,
        /// Listen address
        #[arg(short, long, default_value = "127.0.0.1:8888")]
        listen: String,
    },
    /// Execute a shell command through AgentFence
    Exec {
        /// Policy file path
        #[arg(short, long)]
        policy: String,
        /// Command to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// View audit logs
    Logs {
        /// Session ID
        #[arg(short, long)]
        session: Option<String>,
        /// Output format
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Approve an action
    Approve {
        /// Action ID (or "list" to show pending approvals)
        action_id: String,
        /// Decision (allow/deny). If not specified, shows interactive prompt.
        #[arg(short, long)]
        decision: Option<String>,
    },
    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Audit commands
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start MCP proxy
    Proxy {
        /// Server name
        #[arg(short, long)]
        server: String,
        /// Policy file path
        #[arg(short, long)]
        policy: String,
    },
    /// Start MCP HTTP transport
    Http {
        /// Server name
        #[arg(short, long)]
        server: String,
        /// Policy file path
        #[arg(short, long)]
        policy: String,
        /// Listen address
        #[arg(short, long, default_value = "127.0.0.1:9000")]
        listen: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Check policy file
    Check {
        /// Policy file path
        path: String,
    },
    /// Test policy file
    Test {
        /// Policy file path
        path: String,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Verify audit log integrity
    Verify {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { output } => {
            commands::init::execute(&output);
        }
        Commands::Run { policy, agent } => {
            commands::run::execute(&policy, &agent);
        }
        Commands::Mcp { command } => match command {
            McpCommands::Proxy { server, policy } => {
                commands::mcp_proxy::execute(&server, &policy);
            }
            McpCommands::Http {
                server,
                policy,
                listen,
            } => {
                commands::mcp_http::execute(&server, &policy, &listen);
            }
        },
        Commands::Network { policy, listen } => {
            commands::network_proxy::execute(&policy, &listen);
        }
        Commands::Exec { policy, command } => {
            commands::exec::execute(&policy, &command);
        }
        Commands::Logs { session, format } => {
            commands::logs::execute(session, &format);
        }
        Commands::Approve {
            action_id,
            decision,
        } => {
            let decision = decision.as_deref().unwrap_or("ask");
            commands::approve::execute(&action_id, decision);
        }
        Commands::Policy { command } => match command {
            PolicyCommands::Check { path } => {
                commands::policy_check::execute(&path);
            }
            PolicyCommands::Test { path } => {
                commands::policy_test::execute(&path);
            }
        },
        Commands::Audit { command } => match command {
            AuditCommands::Verify { session } => {
                commands::audit_verify::execute(&session);
            }
        },
    }
}
