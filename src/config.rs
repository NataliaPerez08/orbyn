//! Configuration loaded from environment variables.
//!
//! CLI arguments take precedence over environment variables, which take
//! precedence over defaults.

use std::path::PathBuf;

/// Runtime configuration resolved for a CLI invocation.
#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: PathBuf,
}

impl Config {
    /// Resolve configuration, preferring the `--db` CLI flag over
    /// `ORBYN_DB` and finally the default of `./data/orbyn.db`.
    pub fn resolve(db_flag: Option<PathBuf>) -> Self {
        let db_path = db_flag
            .or_else(|| std::env::var("ORBYN_DB").map(PathBuf::from).ok())
            .unwrap_or_else(|| PathBuf::from("./data/orbyn.db"));
        Self { db_path }
    }
}
