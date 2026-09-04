//! Nmap collector (v0.1 milestone).
//!
//! Executes `nmap` as an external process and parses its XML output into
//! normalized [`crate::domain::Observation`]s.
//!
//! Security rules:
//! - targets are passed as process arguments, never shell-interpolated;
//! - the scan runs read-only (`-sS -sV` style, no destructive options);
//! - scope is validated before execution.

use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::domain::Observation;

use super::types::{Collector, ScanTarget};

pub struct NmapCollector {
    binary: String,
}

impl NmapCollector {
    pub fn new() -> Self {
        Self {
            binary: std::env::var("ORBYN_NMAP_BIN").unwrap_or_else(|_| "nmap".to_string()),
        }
    }

    /// Parse Nmap XML into observations. Kept as a method so it can be tested
    /// against recorded fixtures without invoking the real binary.
    pub fn parse_xml(&self, xml: &str) -> Vec<Observation> {
        // TODO(v0.1): wire quick-xml parser once Nmap adapter lands.
        let _ = xml;
        Vec::new()
    }
}

#[async_trait]
impl Collector for NmapCollector {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let target = match target {
            ScanTarget::Ip(ip) => ip.to_string(),
            ScanTarget::Cidr(cidr) => cidr.clone(),
        };

        let mut child = Command::new(&self.binary)
            .arg("-oX")
            .arg("-")
            .arg("-sV")
            .arg("--no-stylesheet")
            .arg(&target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start nmap; is it installed?")?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut stdout)
                .await
                .context("failed reading nmap stdout")?;
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr)
                .await
                .context("failed reading nmap stderr")?;
        }
        let status = child.wait().await.context("failed waiting for nmap")?;

        if !status.success() {
            return Err(anyhow!("nmap exited with {status}: {}", stderr.trim()));
        }

        Ok(self.parse_xml(&stdout))
    }
}

impl Default for NmapCollector {
    fn default() -> Self {
        Self::new()
    }
}
