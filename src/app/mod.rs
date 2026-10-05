//! Application layer: use-case orchestration coordinating the store and
//! domain services on behalf of the CLI. Functions here must be callable
//! independently of clap; terminal-facing behavior (warnings, arg
//! validation, output) stays in [`crate::cli`].

pub(crate) mod assessment;
pub(crate) mod dependencies;
pub(crate) mod discovery;
pub(crate) mod inventory;

use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::Utc;

use orbyn::config::{Config, DbTarget};
use orbyn::domain::{AuditEvent, JobStatus};
use orbyn::store::postgres::PostgresStore;
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::Store;

/// Open the configured store: a SQLite file (filesystem path) or a
/// PostgreSQL database (`postgres://`/`postgresql://` URL). Migrations run
/// automatically on open for both backends.
pub(crate) async fn open_store(config: &Config) -> Result<Arc<dyn Store>> {
    match &config.db {
        DbTarget::Sqlite(path) => {
            let store = SqliteStore::open(path).await?;
            Ok(Arc::new(store))
        }
        DbTarget::Postgres(url) => {
            if orbyn::config::postgres_password_value(url).is_some() {
                eprintln!(
                    "WARNING: the --db URL embeds the PostgreSQL password, which \
                     is visible in the process arguments (ps, /proc); prefer a \
                     URL without a password plus ORBYN_PG_PASSWORD or PGPASSWORD \
                     (audit OY-06)."
                );
            }
            // Defense in depth: register the password (URL userinfo or env
            // fallback) so it is redacted if it ever reaches an error string.
            let mut redactor = orbyn::redact::Redactor::from_env();
            if let Some(password) = orbyn::config::postgres_password_value(url)
                .or_else(orbyn::config::postgres_env_password)
            {
                redactor.add_value(password);
            }
            let store = PostgresStore::open(url)
                .await
                .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
            Ok(Arc::new(store))
        }
    }
}

pub(crate) async fn begin_audit(
    store: &dyn Store,
    action: &str,
    target: &str,
    details: Option<&str>,
) -> Result<AuditEvent> {
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        action: action.into(),
        target: target.into(),
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        details: details.map(str::to_string),
        error: None,
    };
    store.create_audit_event(event.clone()).await?;
    Ok(event)
}

pub(crate) async fn finish_audit_result<T>(
    store: &dyn Store,
    event: AuditEvent,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => {
            store
                .finish_audit_event(&event.id, JobStatus::Succeeded, None)
                .await?;
            Ok(value)
        }
        Err(error) => {
            let message = error.to_string();
            if let Err(audit_error) = store
                .finish_audit_event(&event.id, JobStatus::Failed, Some(message))
                .await
            {
                tracing::error!(error = %audit_error, "could not finish failed audit event");
            }
            Err(error)
        }
    }
}
