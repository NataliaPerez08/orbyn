//! CLI layer: clap definitions ([`args`]) and command handlers
//! ([`commands`]), plus the helpers shared across command handlers.
//!
//! This layer owns terminal-facing behavior: argument validation, warnings,
//! and output. Workflows that should be callable independently of clap move
//! to `src/app/` in a later phase of the v1.1 plan.

pub(crate) mod args;
pub(crate) mod commands;

use std::io::BufRead;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;

use orbyn::assessment::{AssessmentInput, AssetWindow};
use orbyn::config::{Config, DbTarget};
use orbyn::domain::{Asset, AuditEvent, JobStatus, MetricSample};
use orbyn::output::Format;
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

/// Resolve a secret flag value: the literal `-` reads one trimmed line from
/// stdin so the secret never appears in argv or the environment; any other
/// value passes through unchanged. Values containing newlines or NUL bytes
/// are rejected: they would split the temporary SNMP config file, curl's
/// `-H @-` header stream or curl's `-K -` config stream (config/header
/// injection).
///
/// A literal value warns on stderr: it sits in the process arguments (and
/// shell history) for the whole process lifetime (audit OY-07). Values
/// sourced from `env_var` (clap's env fallback) do not warn.
pub(crate) fn resolve_secret(
    value: Option<String>,
    flag: &str,
    env_var: &str,
) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let secret = if value == "-" {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .with_context(|| format!("reading {flag} from stdin"))?;
        let secret = line.trim();
        if secret.is_empty() {
            bail!("{flag} read an empty secret from stdin");
        }
        secret.to_string()
    } else {
        if secret_needs_argv_warning(&value, env_var) {
            eprintln!(
                "WARNING: {flag} passed as a literal value is visible in the \
                 process arguments (ps, shell history); prefer '-' to read it \
                 from stdin, or set {env_var} (audit OY-07)."
            );
        }
        value
    };
    if secret.contains(['\n', '\r', '\0']) {
        bail!("{flag} cannot contain newlines or NUL bytes");
    }
    Ok(Some(secret))
}

/// True when a secret arrived as a literal flag value (not the stdin marker
/// and not matching the env fallback), leaving it exposed in argv.
fn secret_needs_argv_warning(value: &str, env_var: &str) -> bool {
    value != "-" && std::env::var(env_var).ok().as_deref() != Some(value)
}

/// True when a URL uses plaintext HTTP: an Authorization token would travel
/// unencrypted (audit OY-12).
pub(crate) fn is_plain_http(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

/// Gather the full inventory snapshot the assessment engine evaluates.
pub(crate) async fn assessment_input(store: &dyn Store) -> Result<AssessmentInput> {
    let assets = store.list_assets().await?;
    let services = store.list_all_services().await?;
    let filesystems = store.list_all_filesystems().await?;
    let capacities = store.list_all_capacities().await?;
    let connections = store.list_all_connections().await?;
    let dependencies = store.list_dependencies().await?;
    let metric_windows = metric_windows(store).await?;
    Ok(AssessmentInput {
        assets,
        services,
        filesystems,
        capacities,
        dependencies,
        connections,
        metric_windows,
    })
}

/// Summarize every asset's recorded samples into utilization windows (one
/// bulk read; no per-asset queries). Assets with too few samples produce
/// no window at all — `capacity.missing` already covers the gap.
pub(crate) async fn metric_windows(store: &dyn Store) -> Result<Vec<AssetWindow>> {
    let samples = store.list_all_metric_samples().await?;
    let mut by_asset: std::collections::HashMap<String, Vec<MetricSample>> =
        std::collections::HashMap::new();
    for sample in samples {
        by_asset
            .entry(sample.asset_id.clone())
            .or_default()
            .push(sample);
    }
    let mut windows: Vec<AssetWindow> = by_asset
        .into_iter()
        .filter_map(|(asset_id, samples)| {
            orbyn::metrics::summarize(&samples).map(|stats| AssetWindow { asset_id, stats })
        })
        .collect();
    windows.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
    Ok(windows)
}

/// Resolve an asset reference that may be an id, an IP address, or a
/// hostname (exact, case-insensitive).
pub(crate) async fn resolve_asset(store: &dyn Store, key: &str) -> Result<Asset> {
    if let Some(asset) = store.get_asset(key).await? {
        return Ok(asset);
    }
    if let Some(asset) = store.get_asset_by_ip(key).await? {
        return Ok(asset);
    }
    if let Some(asset) = store.get_asset_by_hostname(key).await? {
        return Ok(asset);
    }
    Err(anyhow!("no asset matches '{key}'"))
}

/// Fetch every asset facet from the store and render the composite detail.
pub(crate) async fn render_asset_detail(
    store: &dyn Store,
    asset: &Asset,
    format: Format,
) -> Result<String> {
    let services = store.list_services(&asset.id).await?;
    let ifaces = store.list_interfaces(&asset.id).await?;
    let capacity = store.get_capacity(&asset.id).await?;
    let filesystems = store.list_filesystems(&asset.id).await?;
    let running = store.list_running_services(&asset.id).await?;
    Ok(orbyn::output::asset_detail(
        asset,
        &services,
        &ifaces,
        capacity.as_ref(),
        &filesystems,
        &running,
        format,
    ))
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

/// Asset rows written per transaction during an import.
///
/// Large enough that a bulk import pays a handful of commits instead of one
/// per asset, small enough that a single transaction never holds the database
/// write lock for a very long time.
pub(crate) const IMPORT_WRITE_CHUNK: usize = 500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_secret_rejects_control_characters() {
        assert!(resolve_secret(
            Some("bad\nsecret".into()),
            "--community",
            "ORBYN_SNMP_COMMUNITY"
        )
        .is_err());
        assert!(
            resolve_secret(Some("bad\rsecret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert!(
            resolve_secret(Some("bad\0secret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert_eq!(
            resolve_secret(Some("good-secret".into()), "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            Some("good-secret".to_string())
        );
        assert_eq!(
            resolve_secret(None, "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            None
        );
    }

    #[test]
    fn literal_secrets_warn_but_env_sourced_do_not() {
        // A throwaway env var keeps this test independent from a developer
        // shell that exports the real secret variables.
        let var = "ORBYN_TEST_SECRET_WARN";
        std::env::remove_var(var);
        assert!(
            secret_needs_argv_warning("literal-value", var),
            "literal flag values are exposed in argv and must warn"
        );
        assert!(
            !secret_needs_argv_warning("-", var),
            "the stdin marker never warns"
        );
        std::env::set_var(var, "from-env");
        assert!(
            !secret_needs_argv_warning("from-env", var),
            "values matching the env fallback do not warn"
        );
        assert!(secret_needs_argv_warning("other", var));
        std::env::remove_var(var);
    }

    #[test]
    fn plain_http_urls_are_detected() {
        assert!(is_plain_http("http://netbox.example.com"));
        assert!(is_plain_http("  HTTP://netbox.example.com  "));
        assert!(!is_plain_http("https://netbox.example.com"));
        assert!(!is_plain_http("https://netbox.example.com/http://x"));
    }
}
