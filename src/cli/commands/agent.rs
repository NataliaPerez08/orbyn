//! Handlers for `orbyn agent run|report` (v1.5 local profiler).

use std::time::Duration;

use anyhow::{bail, Context, Result};

use orbyn::agent::{self, AgentConfig};
use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;
use crate::cli::args::{AgentAction, ReportFormat};

pub(crate) async fn agent(config: &Config, action: AgentAction) -> Result<()> {
    match action {
        AgentAction::Run {
            interval_secs,
            once,
            duration_secs,
            retention_hours,
            asset_ip,
            facts_interval_secs,
        } => {
            if interval_secs == 0 {
                bail!("--interval-secs must be at least 1");
            }
            if retention_hours == 0 {
                bail!("--retention-hours must be at least 1");
            }
            let agent_config = AgentConfig {
                asset_ip: resolve_asset_ip(asset_ip.as_deref())?,
                interval: Duration::from_secs(interval_secs),
                retention: chrono::Duration::hours(retention_hours as i64),
                duration: if once {
                    Some(Duration::ZERO)
                } else {
                    duration_secs.map(Duration::from_secs)
                },
                facts_interval: Duration::from_secs(facts_interval_secs),
            };
            let store = open_store(config).await?;
            let persisted = agent::run(store.as_ref(), &agent_config).await?;
            eprintln!("Agent run persisted {persisted} sample(s).");
        }
        AgentAction::Report { asset_ip, format } => {
            let ip = resolve_asset_ip(asset_ip.as_deref())?;
            let store = open_store(config).await?;
            let id = orbyn::domain::asset_id(ip);
            let samples = store.list_metric_samples(&id, None).await?;
            match format {
                ReportFormat::Html => {
                    let stats = orbyn::metrics::summarize(&samples)
                        .context("not enough samples for a report (run `orbyn agent run` first)");
                    let cov = agent::coverage(&samples);
                    print!("{}", agent::render_html(&stats?, &cov, &id));
                }
                ReportFormat::Json => {
                    // Window stats plus coverage in one machine-readable doc.
                    let payload = serde_json::json!({
                        "asset_id": id,
                        "window": orbyn::metrics::summarize(&samples),
                        "coverage": agent::coverage(&samples),
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                }
                ReportFormat::Table => {
                    let stats = orbyn::metrics::summarize(&samples);
                    print!("{}", orbyn::output::metrics(stats.as_ref(), Format::Table));
                    let cov = agent::coverage(&samples);
                    if cov.sample_count > 0 {
                        eprintln!(
                            "coverage: {} samples, first {}, last {}, largest gap {}",
                            cov.sample_count,
                            cov.first
                                .map(|t| t.to_rfc3339())
                                .unwrap_or_else(|| "-".into()),
                            cov.last
                                .map(|t| t.to_rfc3339())
                                .unwrap_or_else(|| "-".into()),
                            cov.largest_gap_secs
                                .map(|g| format!("{g:.0}s"))
                                .unwrap_or_else(|| "-".into()),
                        );
                    }
                }
            }
        }
        AgentAction::Sync {
            url,
            token,
            asset_ip,
        } => {
            let cfg = agent::sync::SyncConfig {
                url,
                token,
                asset_ip: resolve_asset_ip(asset_ip.as_deref())?,
            };
            let store = open_store(config).await?;
            let stats = agent::sync::sync(store.as_ref(), &cfg).await?;
            eprintln!(
                "Synced {} sample(s) in {} batch(es); local buffer drained.",
                stats.samples, stats.batches
            );
        }
    }
    Ok(())
}

/// `--asset-ip` override or the auto-detected local address.
fn resolve_asset_ip(raw: Option<&str>) -> Result<std::net::IpAddr> {
    match raw {
        Some(raw) => raw
            .parse()
            .with_context(|| format!("invalid --asset-ip '{raw}'")),
        None => Ok(agent::detect_local_ip()),
    }
}
