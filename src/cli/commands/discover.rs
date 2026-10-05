//! Handler for the discovery command: argument validation, collector
//! construction, and the terminal-facing prelude. The job orchestration is
//! in `app::discovery`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

use orbyn::collectors::credentials::CredentialProfile;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::LinuxCollector;
use orbyn::collectors::windows::{WindowsCollector, WindowsTransport};
use orbyn::collectors::winrm::WinRmTransport;
use orbyn::collectors::{validate_target_with_policy, Collector, ScanTargetError};
use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;
use crate::cli::args::DiscoveryCollector;
use crate::cli::resolve_secret;

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

    crate::app::discovery::run(
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
