//! Configuration loaded from environment variables.
//!
//! CLI arguments take precedence over environment variables, which take
//! precedence over defaults.

use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: String,
    pub db_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            addr: normalize_addr(
                &std::env::var("ORBYN_ADDR").unwrap_or_else(|_| ":8080".to_string()),
            ),
            db_path: std::env::var("ORBYN_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./data/orbyn.db")),
        })
    }

    pub fn with_overrides(&self, addr: Option<String>, db: Option<PathBuf>) -> Self {
        let addr = addr
            .map(|a| normalize_addr(&a))
            .unwrap_or_else(|| self.addr.clone());
        Self {
            addr,
            db_path: db.unwrap_or_else(|| self.db_path.clone()),
        }
    }
}

/// Translate the Go-style `:8080` form into an explicit bind address. Rust's
/// `TcpListener::bind` treats a leading colon as an empty host, which fails DNS
/// resolution instead of binding all interfaces.
fn normalize_addr(addr: &str) -> String {
    if let Some(port) = addr.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        addr.to_string()
    }
}
