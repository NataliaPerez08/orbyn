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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_wins_over_default() {
        let config = Config::resolve(Some(PathBuf::from("/tmp/flagged.db")));
        assert_eq!(config.db_path, PathBuf::from("/tmp/flagged.db"));
    }

    #[test]
    fn defaults_to_local_db_when_no_flag() {
        // ORBYN_DB is not set in a clean environment; if a dev shell exports
        // it, that only affects the env branch, which we do not assert here.
        let config = Config::resolve(None);
        let is_default = config.db_path.as_os_str() == "./data/orbyn.db";
        let is_env = std::env::var_os("ORBYN_DB")
            .map(|v| config.db_path.as_os_str() == v)
            .unwrap_or(false);
        assert!(
            is_default || is_env,
            "unexpected db_path {}",
            config.db_path.display()
        );
    }
}
