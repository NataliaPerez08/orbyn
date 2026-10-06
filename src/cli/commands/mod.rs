//! Command handlers, grouped by command family. Each handler receives the
//! parsed CLI arguments plus the resolved [`Config`] and owns the
//! terminal-facing behavior of its command.

use std::io::Write;

use anyhow::Result;
use clap::CommandFactory;

use crate::cli::args::{Cli, Shell};

pub(crate) mod applications;
pub(crate) mod assessment;
pub(crate) mod audit;
pub(crate) mod cloud;
pub(crate) mod dependencies;
pub(crate) mod discover;
pub(crate) mod integrations;
pub(crate) mod inventory;
pub(crate) mod metrics;
pub(crate) mod planning;
pub(crate) mod sku;
pub(crate) mod waves;

/// Handle `orbyn completions <shell>`.
pub(crate) fn completions(shell: Shell) -> Result<()> {
    let shell = match shell {
        Shell::Bash => clap_complete::Shell::Bash,
        Shell::Zsh => clap_complete::Shell::Zsh,
        Shell::Fish => clap_complete::Shell::Fish,
    };
    let mut cmd = Cli::command();
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cmd, "orbyn", &mut buf);
    // Broken pipe (e.g. `orbyn completions zsh | head`) must not panic.
    std::io::stdout().write_all(&buf).or_else(|e| {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    Ok(())
}
