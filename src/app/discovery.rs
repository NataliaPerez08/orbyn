//! Discovery workflow: running one discovery job over a bounded worker
//! pool and persisting the observations it produces.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use chrono::Utc;

use orbyn::collectors::{Collector, ScanTarget};
use orbyn::domain::{DiscoveryJob, JobOutcome, JobStatus, Observation};
use orbyn::store::Store;
use tokio::task::JoinHandle;

/// Run one discovery job over the given targets, fanning them out over a
/// bounded worker pool: at most `concurrency` collector scans run at once,
/// optionally paced to at most `rate_limit` launches per second.
///
/// Observations from successful targets are always persisted; if any target
/// fails the job is marked Failed with the per-target errors, keeping the
/// partial data. Errors are scrubbed with `redactor` before they are
/// persisted or printed.
pub(crate) async fn run(
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
