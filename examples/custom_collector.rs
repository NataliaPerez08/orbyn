//! A minimal example collector, demonstrating the plugin SDK contract.
//!
//! A collector is any type implementing [`orbyn::collectors::Collector`]: it
//! declares a stable name and a read-only `scan` that turns a validated target
//! into normalized [`orbyn::domain::Observation`]s. Collectors never write to
//! the database directly.
//!
//! Run with: `cargo run --example custom_collector`

use anyhow::{bail, Result};
use async_trait::async_trait;
use chrono::Utc;
use orbyn::collectors::{validate_target, Collector, ScanTarget};
use orbyn::domain::{Asset, Observation};

/// A toy collector that "discovers" the target address itself.
struct StaticCollector;

#[async_trait]
impl Collector for StaticCollector {
    fn name(&self) -> &'static str {
        "static"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let ip = match target {
            ScanTarget::Ip(ip) => *ip,
            ScanTarget::Cidr(cidr) => bail!("static collector wants a single IP (got '{cidr}')"),
        };
        let now = Utc::now();
        Ok(vec![Observation::Asset(Asset {
            id: ip.to_string().replace(['.', ':'], "-"),
            ip,
            hostname: Some(format!("static-{ip}")),
            device_class: Some("example".into()),
            os_name: Some("Example OS".into()),
            os_version: None,
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: vec!["example-collector".into()],
            first_seen: now,
            last_seen: now,
        })])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let target = validate_target("10.0.0.42")?;
    let collector = StaticCollector;
    println!("collector name: {}", collector.name());
    let observations = collector.scan(&target).await?;
    println!("produced {} observation(s)", observations.len());
    Ok(())
}
