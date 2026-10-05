//! Orbyn CLI entry point: bootstrap (environment, logging, config) and
//! command dispatch. Argument definitions live in [`cli::args`], command
//! handlers in [`cli::commands`], and application workflows in [`app`].

mod app;
mod cli;

use clap::Parser;

use orbyn::config::Config;

use cli::args::{Cli, Command};
use cli::commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_dotenv_from(std::path::Path::new(".env"));

    let cli = Cli::parse();
    init_logging(cli.verbose);
    let config = Config::resolve(cli.db.clone());

    match cli.command {
        Command::Discover {
            target,
            format,
            collector,
            concurrency,
            rate_limit,
            allow_large_cidr,
            community,
            snmp_version,
            snmp_port,
            user,
            port,
            identity_file,
            winrm_password,
            winrm_port,
            winrm_insecure,
        } => {
            commands::discover::discover(
                &config,
                target,
                format,
                collector,
                concurrency,
                rate_limit,
                allow_large_cidr,
                community,
                snmp_version,
                snmp_port,
                user,
                port,
                identity_file,
                winrm_password,
                winrm_port,
                winrm_insecure,
            )
            .await?
        }
        Command::Completions { shell } => commands::completions(shell)?,
        Command::Assets { format } => commands::inventory::assets(&config, format).await?,
        Command::Asset { asset, format } => {
            commands::inventory::asset(&config, asset, format).await?
        }
        Command::Annotate {
            asset,
            environment,
            owner,
            criticality,
            unset,
            add_tag,
            remove_tag,
            format,
        } => {
            commands::inventory::annotate(
                &config,
                asset,
                environment,
                owner,
                criticality,
                unset,
                add_tag,
                remove_tag,
                format,
            )
            .await?
        }
        Command::Services { asset, format } => {
            commands::inventory::services(&config, asset, format).await?
        }
        Command::Interfaces { asset, format } => {
            commands::inventory::interfaces(&config, asset, format).await?
        }
        Command::Capacity { asset, format } => {
            commands::inventory::capacity(&config, asset, format).await?
        }
        Command::Disks { asset, format } => {
            commands::inventory::disks(&config, asset, format).await?
        }
        Command::HostServices { asset, format } => {
            commands::inventory::host_services(&config, asset, format).await?
        }
        Command::Connections { asset, format } => {
            commands::inventory::connections(&config, asset, format).await?
        }
        Command::Metrics {
            asset,
            samples,
            format,
        } => commands::metrics::metrics(&config, asset, samples, format).await?,
        Command::Deps { action } => commands::dependencies::deps(&config, action).await?,
        Command::Jobs { limit, format } => commands::audit::jobs(&config, limit, format).await?,
        Command::Audit { limit, format } => commands::audit::audit(&config, limit, format).await?,
        Command::Export {
            format,
            group_by,
            tf_import,
            output,
        } => commands::inventory::export(&config, format, group_by, tf_import, output).await?,
        Command::Import { format, file } => {
            commands::integrations::import(&config, format, file).await?
        }
        Command::Netbox { action } => commands::integrations::netbox(&config, action).await?,
        Command::Prometheus { action } => {
            commands::integrations::prometheus(&config, action).await?
        }
        Command::Zabbix { action } => commands::integrations::zabbix(&config, action).await?,
        Command::Proxmox { action } => commands::cloud::proxmox(&config, action).await?,
        Command::Aws { action } => commands::cloud::aws(&config, action).await?,
        Command::Huawei { action } => commands::cloud::huawei(&config, action).await?,
        Command::Openstack { action } => commands::cloud::openstack(&config, action).await?,
        Command::Gcp { action } => commands::cloud::gcp(&config, action).await?,
        Command::Azure { action } => commands::cloud::azure(&config, action).await?,
        Command::Graph {
            format,
            mermaid,
            asset,
        } => commands::dependencies::graph(&config, format, mermaid, asset).await?,
        Command::Assess { format, rules } => {
            commands::assessment::assess(&config, format, rules).await?
        }
        Command::SkuMatch {
            provider,
            cores,
            ram_mb,
            format,
        } => commands::sku::sku_match(provider, cores, ram_mb, format),
        Command::Waves {
            format,
            pins,
            excludes,
        } => commands::waves::waves(&config, format, pins, excludes).await?,
    }

    Ok(())
}

/// Load `.env` from `path` only — never from parent directories (audit
/// OY-01: `dotenvy::dotenv()` ascends the tree, so a stray `.env` in an
/// ancestor could execute arbitrary binaries via `ORBYN_*_BIN`).
///
/// Preserves `dotenvy` semantics: variables already present in the
/// environment win over file values. Warns when the file overrides an
/// `ORBYN_*_BIN` with anything but the built-in default binary name —
/// Orbyn executes that binary, and the operator should see it.
fn load_dotenv_from(path: &std::path::Path) {
    let Ok(iter) = dotenvy::from_path_iter(path) else {
        return;
    };
    for (key, value) in iter.flatten() {
        if key.starts_with("ORBYN_") && key.ends_with("_BIN") && !is_default_bin(&key, &value) {
            eprintln!(
                "WARNING: {} configures {key}={value}; Orbyn will execute that binary.",
                path.display()
            );
        }
        if std::env::var_os(&key).is_none() {
            std::env::set_var(&key, value);
        }
    }
}

/// True when `key`/`value` reproduce the built-in binary default, in which
/// case the `.env` line changes nothing and deserves no warning.
fn is_default_bin(key: &str, value: &str) -> bool {
    matches!(
        (key, value),
        ("ORBYN_NMAP_BIN", "nmap")
            | ("ORBYN_SNMP_BIN", "snmpwalk")
            | ("ORBYN_SSH_BIN", "ssh")
            | ("ORBYN_CURL_BIN", "curl")
    )
}

fn init_logging(verbose: u8) {
    let default_filter = match verbose {
        0 => "orbyn=warn",
        1 => "orbyn=info",
        _ => "orbyn=debug",
    };
    let filter = std::env::var("ORBYN_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_filter.to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_loads_only_the_given_file_without_overwrite() {
        let dir = std::env::temp_dir().join(format!("orbyn-dotenv-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create dotenv test dir");
        let env_file = dir.join(".env");
        std::fs::write(
            &env_file,
            "ORBYN_DOTENV_TEST_NEW=loaded\nORBYN_DOTENV_TEST_EXISTING=from_file\n",
        )
        .expect("write test .env");
        std::env::set_var("ORBYN_DOTENV_TEST_EXISTING", "from_env");

        load_dotenv_from(&env_file);

        assert_eq!(
            std::env::var("ORBYN_DOTENV_TEST_NEW").expect("new var loaded"),
            "loaded"
        );
        assert_eq!(
            std::env::var("ORBYN_DOTENV_TEST_EXISTING").expect("existing var kept"),
            "from_env",
            "environment must win over the .env file"
        );
        std::env::remove_var("ORBYN_DOTENV_TEST_NEW");
        std::env::remove_var("ORBYN_DOTENV_TEST_EXISTING");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_bin_overrides_are_recognized() {
        assert!(is_default_bin("ORBYN_NMAP_BIN", "nmap"));
        assert!(is_default_bin("ORBYN_SNMP_BIN", "snmpwalk"));
        assert!(is_default_bin("ORBYN_SSH_BIN", "ssh"));
        assert!(is_default_bin("ORBYN_CURL_BIN", "curl"));
        assert!(!is_default_bin("ORBYN_NMAP_BIN", "/tmp/evil-nmap"));
        assert!(!is_default_bin("ORBYN_NMAP_BIN", "nmap-backup"));
        assert!(!is_default_bin("ORBYN_DB", "nmap"));
    }
}
