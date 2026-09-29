//! Configuration loaded from environment variables.
//!
//! CLI arguments take precedence over environment variables, which take
//! precedence over defaults.

use std::path::PathBuf;

/// Where Orbyn persists its inventory: a SQLite file or a PostgreSQL URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbTarget {
    /// Filesystem path of the SQLite database.
    Sqlite(PathBuf),
    /// Connection URL (`postgres://` or `postgresql://`) of a PostgreSQL
    /// database.
    Postgres(String),
}

impl DbTarget {
    /// Classify a `--db`/`ORBYN_DB` value: `postgres://` and `postgresql://`
    /// URLs select the PostgreSQL backend, anything else is a SQLite path.
    pub fn parse(value: String) -> Self {
        if value.starts_with("postgres://") || value.starts_with("postgresql://") {
            Self::Postgres(value)
        } else {
            Self::Sqlite(PathBuf::from(value))
        }
    }
}

/// Extract the password embedded in a `postgres://` URL's userinfo
/// (`postgres://user:password@host/db`), as written in the URL.
///
/// Returns `None` for URLs without userinfo, without a password separator,
/// or with an empty password. The value is only used to register redaction
/// and to decide whether the env fallback applies (audit OY-06).
pub fn postgres_password_value(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let (userinfo, _) = rest.split_once('@')?;
    let (_, password) = userinfo.split_once(':')?;
    if password.is_empty() {
        None
    } else {
        Some(password.to_string())
    }
}

/// Password supplied out-of-band for a PostgreSQL URL without one:
/// `ORBYN_PG_PASSWORD` (Orbyn-specific) wins over the standard `PGPASSWORD`,
/// mirroring libpq's env fallback so the password never lands in argv
/// (audit OY-06).
pub fn postgres_env_password() -> Option<String> {
    std::env::var("ORBYN_PG_PASSWORD")
        .ok()
        .or_else(|| std::env::var("PGPASSWORD").ok())
}

/// Runtime configuration resolved for a CLI invocation.
#[derive(Debug, Clone)]
pub struct Config {
    pub db: DbTarget,
}

impl Config {
    /// Resolve configuration, preferring the `--db` CLI flag over
    /// `ORBYN_DB` and finally the default of `./data/orbyn.db`. Both accept
    /// a filesystem path (SQLite) or a `postgres://` URL (PostgreSQL).
    pub fn resolve(db_flag: Option<String>) -> Self {
        let db = db_flag
            .or_else(|| std::env::var("ORBYN_DB").ok())
            .map(DbTarget::parse)
            .unwrap_or_else(|| DbTarget::Sqlite(PathBuf::from("./data/orbyn.db")));
        Self { db }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_wins_over_default() {
        let config = Config::resolve(Some("/tmp/flagged.db".into()));
        assert_eq!(
            config.db,
            DbTarget::Sqlite(PathBuf::from("/tmp/flagged.db"))
        );
    }

    #[test]
    fn postgres_urls_select_the_postgres_backend() {
        assert_eq!(
            DbTarget::parse("postgres://orbyn@localhost/orbyn".into()),
            DbTarget::Postgres("postgres://orbyn@localhost/orbyn".into())
        );
        assert_eq!(
            DbTarget::parse("postgresql://orbyn:pw@db.example.com:5432/orbyn".into()),
            DbTarget::Postgres("postgresql://orbyn:pw@db.example.com:5432/orbyn".into())
        );
        // a path that merely contains the scheme is still a SQLite path
        assert_eq!(
            DbTarget::parse("./backups/postgres://notes.db".into()),
            DbTarget::Sqlite(PathBuf::from("./backups/postgres://notes.db"))
        );
    }

    #[test]
    fn postgres_password_value_extracts_userinfo_passwords() {
        assert_eq!(
            postgres_password_value("postgres://orbyn:secret@localhost/orbyn"),
            Some("secret".to_string())
        );
        assert_eq!(
            postgres_password_value("postgresql://orbyn:p%40ss@db.example.com:5432/orbyn"),
            Some("p%40ss".to_string()),
            "the raw userinfo substring is what argv exposes"
        );
        assert_eq!(
            postgres_password_value("postgres://orbyn@localhost/orbyn"),
            None,
            "no password separator"
        );
        assert_eq!(
            postgres_password_value("postgres://orbyn:@localhost/orbyn"),
            None,
            "empty password is no password"
        );
        assert_eq!(
            postgres_password_value("postgres://localhost/orbyn"),
            None,
            "no userinfo at all"
        );
        assert_eq!(
            postgres_password_value("./data/orbyn.db"),
            None,
            "SQLite paths have no password"
        );
    }

    #[test]
    fn defaults_to_local_db_when_no_flag() {
        // ORBYN_DB is not set in a clean environment; if a dev shell exports
        // it, that only affects the env branch, which we do not assert here.
        let config = Config::resolve(None);
        let is_default = config.db == DbTarget::Sqlite(PathBuf::from("./data/orbyn.db"));
        let is_env = std::env::var_os("ORBYN_DB")
            .map(|v| config.db == DbTarget::parse(v.to_string_lossy().into_owned()))
            .unwrap_or(false);
        assert!(is_default || is_env, "unexpected db target {:?}", config.db);
    }
}
