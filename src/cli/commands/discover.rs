//! Handler for the discovery command and its job orchestration.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use chrono::Utc;

use orbyn::collectors::credentials::CredentialProfile;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::LinuxCollector;
use orbyn::collectors::windows::{WindowsCollector, WindowsTransport};
use orbyn::collectors::winrm::WinRmTransport;
use orbyn::collectors::{validate_target_with_policy, Collector, ScanTarget, ScanTargetError};
use orbyn::config::Config;
use orbyn::domain::{DiscoveryJob, JobOutcome, JobStatus, Observation};
use orbyn::output::Format;
use orbyn::store::Store;
use tokio::task::JoinHandle;

use crate::cli::args::DiscoveryCollector;
use crate::cli::{open_store, resolve_secret};

/// Handle `orbyn discover`.
#[allow(clippy::too_many_arguments)] // mirrors the discover CLI surface
pub(crate) async fn discover(
    config: &Config,
    target: Vec<String>,
    format: Format,
    collector: DiscoveryCollector,
    concurrency: usize,
    rate_limit: Option<u32>,
    allow_large_cidr: bool,
    community: Option<String>,
    snmp_version: String,
    snmp_port: u16,
    user: Option<String>,
    port: u16,
    identity_file: Option<PathBuf>,
    winrm_password: Option<String>,
    winrm_port: u16,
    winrm_insecure: bool,
) -> Result<()> {
    let store = open_store(config).await?;
    if concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if rate_limit == Some(0) {
        bail!("--rate-limit must be at least 1");
    }
    let mut scan_targets = Vec::with_capacity(target.len());
    for raw in &target {
        scan_targets.push(
            validate_target_with_policy(raw, allow_large_cidr)
                .map_err(|e| anyhow!(large_scope_hint(&e, allow_large_cidr)))?,
        );
    }
    let community = resolve_secret(community, "--community", "ORBYN_SNMP_COMMUNITY")?;
    let winrm_password =
        resolve_secret(winrm_password, "--winrm-password", "ORBYN_WINRM_PASSWORD")?;
    validate_ssh_user(user.as_deref())?;
    if collector == DiscoveryCollector::Winrm && user.as_deref().unwrap_or_default().is_empty() {
        bail!("--collector winrm requires --user (the Windows account, e.g. Administrator)");
    }
    let version: SnmpVersion = snmp_version.parse().map_err(anyhow::Error::msg)?;
    let profile = CredentialProfile::new(user.clone().unwrap_or_default(), port, identity_file);

    let collector: Arc<dyn Collector> = match collector {
        DiscoveryCollector::Nmap => Arc::new(NmapCollector::new()),
        DiscoveryCollector::Snmp => Arc::new(SnmpCollector::new(
            community.as_deref().unwrap_or_default(),
            version,
            snmp_port,
        )),
        DiscoveryCollector::Ssh => Arc::new(LinuxCollector::new(profile)),
        DiscoveryCollector::Windows => Arc::new(WindowsCollector::new(profile)),
        DiscoveryCollector::Winrm => {
            if winrm_insecure {
                tracing::warn!(
                    "--winrm-insecure disables TLS certificate verification for the WinRM endpoint"
                );
                eprintln!(
                    "WARNING: --winrm-insecure disables TLS certificate verification.\n\
                     Only use it against trusted endpoints with self-signed certificates."
                );
            }
            let winrm_profile = CredentialProfile::new(user.unwrap_or_default(), winrm_port, None);
            let transport =
                WinRmTransport::new(winrm_profile, winrm_password.clone(), winrm_insecure)?;
            Arc::new(WindowsCollector::with_transport(WindowsTransport::WinRm(
                transport,
            )))
        }
    };

    let mut redactor = orbyn::redact::Redactor::from_env();
    if let Some(community) = &community {
        redactor.add_value(community);
    }
    if let Some(password) = &winrm_password {
        redactor.add_value(password);
    }

    run_discovery(
        store.as_ref(),
        &scan_targets,
        collector,
        concurrency,
        rate_limit,
        &redactor,
    )
    .await?;
    let assets = store.list_assets().await?;
    print!("{}", orbyn::output::assets(&assets, format));
    Ok(())
}

/// Extend an oversized-scope validation error with the override hint when
/// the default CIDR floor rejected the target (audit OY-09).
fn large_scope_hint(e: &ScanTargetError, allow_large_cidr: bool) -> String {
    if !allow_large_cidr && matches!(e, ScanTargetError::TooLarge(_)) {
        format!(
            "{e}; pass --allow-large-cidr to override the default minimum \
             prefix (IPv4 /16, IPv6 /48)"
        )
    } else {
        e.to_string()
    }
}

/// Reject SSH usernames that the ssh binary would parse as options: the
/// username is embedded in the destination argument (`user@host`), and a
/// value starting with `-` is consumed as an ssh option instead
/// (argument injection, audit OY-11).
fn validate_ssh_user(user: Option<&str>) -> Result<()> {
    if let Some(user) = user {
        if user.starts_with('-') {
            bail!("--user cannot start with '-' (ssh would parse it as an option)");
        }
    }
    Ok(())
}

/// Run one discovery job over the given targets, fanning them out over a
/// bounded worker pool: at most `concurrency` collector scans run at once,
/// optionally paced to at most `rate_limit` launches per second.
///
/// Observations from successful targets are always persisted; if any target
/// fails the job is marked Failed with the per-target errors, keeping the
/// partial data. Errors are scrubbed with `redactor` before they are
/// persisted or printed.
async fn run_discovery(
    store: &dyn Store,
    scan_targets: &[ScanTarget],
    collector: Arc<dyn Collector>,
    concurrency: usize,
    rate_limit: Option<u32>,
    redactor: &orbyn::redact::Redactor,
) -> Result<()> {
    let targets: Vec<String> = scan_targets.iter().map(target_label).collect();

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: collector.name().into(),
        targets: targets.clone(),
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        assets_found: None,
        services_found: None,
        filesystems_found: None,
        running_services_found: None,
        connections_found: None,
    };
    store.create_job(job.clone()).await?;

    tracing::info!(
        job = %job.id,
        collector = job.collector,
        targets = ?targets,
        concurrency,
        rate_limit,
        "starting discovery"
    );

    let mut running: VecDeque<JoinHandle<anyhow::Result<Vec<Observation>>>> = VecDeque::new();
    let mut failures: Vec<String> = Vec::new();
    let mut outcome = JobOutcome {
        assets_found: 0,
        services_found: 0,
        filesystems_found: 0,
        running_services_found: 0,
        connections_found: 0,
    };
    let first_launch = Instant::now();

    for (index, scan_target) in scan_targets.iter().enumerate() {
        if let Some(rate) = rate_limit {
            // Pace launches: target `index` may not start before
            // `index / rate` seconds have elapsed since the first launch.
            let earliest = Duration::from_secs_f64(index as f64 / f64::from(rate));
            let wait = earliest.saturating_sub(first_launch.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        while running.len() >= concurrency {
            let handle = running.pop_front().expect("pool is at capacity");
            persist_scan_result(handle, store, redactor, &mut outcome, &mut failures).await?;
        }
        let collector = Arc::clone(&collector);
        let scan_target = scan_target.clone();
        running.push_back(tokio::spawn(
            async move { collector.scan(&scan_target).await },
        ));
    }
    while let Some(handle) = running.pop_front() {
        persist_scan_result(handle, store, redactor, &mut outcome, &mut failures).await?;
    }

    let assets = outcome.assets_found;
    let services = outcome.services_found;
    let filesystems = outcome.filesystems_found;
    let running_services = outcome.running_services_found;
    let connections = outcome.connections_found;

    if failures.is_empty() {
        store
            .finish_job(&job.id, JobStatus::Succeeded, None, Some(outcome))
            .await?;
        tracing::info!(job = %job.id, assets, services, "discovery complete");
        eprintln!(
            "Discovery job {} complete: {} assets, {} services, {} filesystems, {} running services, {} connections.",
            job.id, assets, services, filesystems, running_services, connections
        );
        Ok(())
    } else {
        let error = format!(
            "{} of {} targets failed: {}",
            failures.len(),
            scan_targets.len(),
            failures.join("; ")
        );
        store
            .finish_job(
                &job.id,
                JobStatus::Failed,
                Some(error.clone()),
                Some(outcome),
            )
            .await?;
        Err(anyhow!("discovery job {} failed: {error}", job.id))
    }
}

/// Await one worker task and persist its observations before accepting more
/// work, keeping memory bounded by the worker pool and one result batch.
async fn persist_scan_result(
    handle: JoinHandle<anyhow::Result<Vec<Observation>>>,
    store: &dyn Store,
    redactor: &orbyn::redact::Redactor,
    outcome: &mut JobOutcome,
    failures: &mut Vec<String>,
) -> Result<()> {
    let result = match handle.await {
        Ok(result) => result,
        Err(e) => Err(anyhow!("collector task failed: {e}")),
    };
    match result {
        Ok(observations) => {
            for observation in &observations {
                match observation {
                    Observation::Asset(_) => outcome.assets_found += 1,
                    Observation::Service(_) => outcome.services_found += 1,
                    Observation::Filesystem(_) => outcome.filesystems_found += 1,
                    Observation::RunningService(_) => outcome.running_services_found += 1,
                    Observation::Connection(_) => outcome.connections_found += 1,
                    _ => {}
                }
            }
            store.store_observations(observations).await?;
        }
        Err(e) => failures.push(redactor.redact(&format!("{e:#}"))),
    }
    Ok(())
}

fn target_label(target: &ScanTarget) -> String {
    match target {
        ScanTarget::Ip(ip) => ip.to_string(),
        ScanTarget::Cidr(cidr) => cidr.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_user_rejects_leading_dash() {
        assert!(validate_ssh_user(Some("-oProxyCommand=evil")).is_err());
        assert!(validate_ssh_user(Some("-Jevil.example")).is_err());
        assert!(validate_ssh_user(Some("deploy")).is_ok());
        assert!(validate_ssh_user(None).is_ok());
    }
}
