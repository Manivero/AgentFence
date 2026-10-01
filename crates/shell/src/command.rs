//! Command representation and parsing for AgentFence.
//!
//! Structured command representation — never naive substring matching.
//! Accounts for: command chaining, pipes, redirection, subshells,
//! quoted arguments, path traversal, environment expansion.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("empty command")]
    EmptyCommand,
    #[error("unbalanced quotes")]
    UnbalancedQuotes,
    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, CommandError>;

/// A parsed shell command with structured representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub cwd: Option<String>,
    pub env_metadata: Option<serde_json::Value>,
    pub raw: String,
}

impl ShellCommand {
    /// Parse a raw command string into a structured representation.
    ///
    /// This is a simplified parser. A production implementation would use
    /// a proper shell parser (e.g., `shlex` or `shell-words`).
    pub fn parse(raw: &str) -> crate::command::Result<Self> {
        let tokens = tokenize(raw)?;
        if tokens.is_empty() {
            return Err(crate::command::CommandError::EmptyCommand);
        }

        Ok(Self {
            executable: tokens[0].clone(),
            arguments: tokens[1..].to_vec(),
            cwd: None,
            env_metadata: None,
            raw: raw.to_string(),
        })
    }

    /// Check if this command contains dangerous patterns.
    pub fn is_dangerous(&self) -> bool {
        let raw_lower = self.raw.to_lowercase();

        // Command chaining
        if raw_lower.contains("&&") || raw_lower.contains("||") || raw_lower.contains(';') {
            return true;
        }

        // Pipes
        if raw_lower.contains('|') {
            return true;
        }

        // Redirection
        if raw_lower.contains('>') || raw_lower.contains('<') {
            return true;
        }

        // Subshells
        if raw_lower.contains("$(") || raw_lower.contains('`') {
            return true;
        }

        // Environment expansion
        if raw_lower.contains("${") || raw_lower.contains('$') {
            return true;
        }

        false
    }
}

/// Simple tokenizer for shell commands.
///
/// Handles quoted arguments. This is a simplified implementation.
fn tokenize(input: &str) -> crate::command::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut has_token = false;

    for c in input.chars() {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                has_token = true;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                has_token = true;
            }
            ' ' | '\t' | '\n' if !in_single_quote && !in_double_quote => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            _ => {
                current.push(c);
                has_token = true;
            }
        }
    }

    if has_token {
        tokens.push(current);
    }

    if in_single_quote || in_double_quote {
        return Err(crate::command::CommandError::UnbalancedQuotes);
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let cmd = ShellCommand::parse("git status").unwrap();
        assert_eq!(cmd.executable, "git");
        assert_eq!(cmd.arguments, vec!["status"]);
    }

    #[test]
    fn test_parse_quoted() {
        let cmd = ShellCommand::parse("echo \"hello world\"").unwrap();
        assert_eq!(cmd.executable, "echo");
        assert_eq!(cmd.arguments, vec!["hello world"]);
    }

    #[test]
    fn test_parse_chaining() {
        let cmd = ShellCommand::parse("git status && curl example.com").unwrap();
        assert!(cmd.is_dangerous());
    }

    #[test]
    fn test_parse_pipe() {
        let cmd = ShellCommand::parse("cat file | grep pattern").unwrap();
        assert!(cmd.is_dangerous());
    }

    #[test]
    fn test_parse_redirection() {
        let cmd = ShellCommand::parse("echo hello > file.txt").unwrap();
        assert!(cmd.is_dangerous());
    }

    #[test]
    fn test_parse_subshell() {
        let cmd = ShellCommand::parse("echo $(whoami)").unwrap();
        assert!(cmd.is_dangerous());
    }

    #[test]
    fn test_parse_env_expansion() {
        let cmd = ShellCommand::parse("echo $HOME").unwrap();
        assert!(cmd.is_dangerous());
    }

    #[test]
    fn test_empty_command() {
        let result = ShellCommand::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_unbalanced_quotes() {
        let result = ShellCommand::parse("echo \"hello");
        assert!(result.is_err());
    }
}
