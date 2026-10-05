//! Handlers for the cloud provider imports: `proxmox`, `aws`, `huawei`,
//! `openstack`, `gcp`, and `azure`.

use anyhow::{anyhow, Result};

use orbyn::config::Config;
use orbyn::integrations::cloud::aws::{AwsClient, AwsCredentials};
use orbyn::integrations::cloud::azure::{AzureClient, AzureCredentials};
use orbyn::integrations::cloud::gcp::GcpClient;
use orbyn::integrations::cloud::huawei::{HuaweiClient, HuaweiCredentials};
use orbyn::integrations::cloud::openstack::OpenStackClient;
use orbyn::integrations::cloud::proxmox::ProxmoxClient;
use orbyn::integrations::cloud::CloudInventory;

use crate::app::open_store;
use crate::app::{begin_audit, finish_audit_result};
use crate::cli::args::{
    AwsAction, AzureAction, GcpAction, HuaweiAction, OpenstackAction, ProxmoxAction,
};
use crate::cli::{is_plain_http, resolve_secret};

/// Handle `orbyn proxmox <action>`.
pub(crate) async fn proxmox(config: &Config, action: ProxmoxAction) -> Result<()> {
    let ProxmoxAction::Import {
        url,
        token,
        no_verify,
        node,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_PROXMOX_TOKEN")?.ok_or_else(|| {
        anyhow!(
            "a Proxmox API token is required: pass --token, set \
             ORBYN_PROXMOX_TOKEN, or use --token - to read it from stdin"
        )
    })?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for Proxmox");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed Proxmox instance; \
             connections can be silently intercepted."
        );
    }
    if is_plain_http(&url) {
        eprintln!(
            "WARNING: --url uses plain HTTP; the Proxmox API token will travel \
             unencrypted over the network (audit OY-12)."
        );
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&token);
    let audit = begin_audit(
        store.as_ref(),
        "proxmox.import",
        "cloud",
        Some(&format!(
            "url={url}{}",
            node.as_deref()
                .map(|n| format!(", node={n}"))
                .unwrap_or_default()
        )),
    )
    .await?;
    let result: Result<()> = async {
        let client = ProxmoxClient::new(&url, token, no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?
            .with_node(node);
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("Proxmox", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn aws <action>`.
pub(crate) async fn aws(config: &Config, action: AwsAction) -> Result<()> {
    let AwsAction::Import {
        region,
        access_key,
        secret_key,
        session_token,
        endpoint_url,
        no_verify,
    } = action;
    let region = region
        .or_else(|| std::env::var("AWS_REGION").ok())
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| anyhow!("an AWS region is required: pass --region or set AWS_REGION"))?;
    let access_key = access_key.filter(|k| !k.is_empty()).ok_or_else(|| {
        anyhow!(
            "an AWS access key id is required: pass --access-key or set \
             AWS_ACCESS_KEY_ID"
        )
    })?;
    let secret_key = resolve_secret(secret_key, "--secret-key", "AWS_SECRET_ACCESS_KEY")?
        .ok_or_else(|| {
            anyhow!(
                "an AWS secret access key is required: pass --secret-key, set \
                     AWS_SECRET_ACCESS_KEY, or use --secret-key - to read it from stdin"
            )
        })?;
    let session_token = resolve_secret(session_token, "--session-token", "AWS_SESSION_TOKEN")?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for AWS");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed endpoint; connections \
             can be silently intercepted."
        );
    }
    if let Some(endpoint) = &endpoint_url {
        if is_plain_http(endpoint) {
            eprintln!(
                "WARNING: --endpoint-url uses plain HTTP; AWS credentials and the \
                 signed request will travel unencrypted (audit OY-12)."
            );
        }
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&secret_key);
    if let Some(token) = &session_token {
        redactor.add_value(token);
    }
    let audit = begin_audit(
        store.as_ref(),
        "aws.import",
        "cloud",
        Some(&format!(
            "region={region}{}",
            endpoint_url
                .as_deref()
                .map(|e| format!(", endpoint={e}"))
                .unwrap_or_default()
        )),
    )
    .await?;
    let result: Result<()> = async {
        let credentials = AwsCredentials {
            access_key,
            secret_key,
            session_token,
        };
        let client = AwsClient::new(credentials, &region, endpoint_url.as_deref(), no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("AWS", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn huawei <action>`.
pub(crate) async fn huawei(config: &Config, action: HuaweiAction) -> Result<()> {
    let HuaweiAction::Import {
        region,
        access_key,
        secret_key,
        project_id,
        endpoint_url,
        no_verify,
    } = action;
    let region = region
        .or_else(|| std::env::var("HUAWEICLOUD_REGION").ok())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "a Huawei Cloud region is required: pass --region or set \
                 HUAWEICLOUD_REGION"
            )
        })?;
    let access_key = access_key.filter(|k| !k.is_empty()).ok_or_else(|| {
        anyhow!(
            "a Huawei Cloud access key is required: pass --access-key or set \
             HUAWEICLOUD_SDK_AK"
        )
    })?;
    let secret_key =
        resolve_secret(secret_key, "--secret-key", "HUAWEICLOUD_SDK_SK")?.ok_or_else(|| {
            anyhow!(
                "a Huawei Cloud secret key is required: pass --secret-key, set \
                 HUAWEICLOUD_SDK_SK, or use --secret-key - to read it from stdin"
            )
        })?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for Huawei Cloud");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed endpoint; connections \
             can be silently intercepted."
        );
    }
    if let Some(endpoint) = &endpoint_url {
        if is_plain_http(endpoint) {
            eprintln!(
                "WARNING: --endpoint-url uses plain HTTP; Huawei Cloud credentials \
                 and the signed request will travel unencrypted (audit OY-12)."
            );
        }
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&secret_key);
    let audit = begin_audit(
        store.as_ref(),
        "huawei.import",
        "cloud",
        Some(&format!(
            "region={region}{}",
            endpoint_url
                .as_deref()
                .map(|e| format!(", endpoint={e}"))
                .unwrap_or_default()
        )),
    )
    .await?;
    let result: Result<()> = async {
        let credentials = HuaweiCredentials {
            access_key,
            secret_key,
        };
        let client = HuaweiClient::new(
            credentials,
            &region,
            project_id,
            endpoint_url.as_deref(),
            no_verify,
        )
        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("Huawei Cloud", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn openstack <action>`.
pub(crate) async fn openstack(config: &Config, action: OpenstackAction) -> Result<()> {
    let OpenstackAction::Import {
        url,
        token,
        project,
        region,
        no_verify,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_OPENSTACK_TOKEN")?
        .ok_or_else(|| anyhow!("an OpenStack token is required: pass --token, set ORBYN_OPENSTACK_TOKEN, or use --token -"))?;
    if no_verify {
        eprintln!("WARNING: --no-verify disables TLS certificate verification for OpenStack.");
    }
    if is_plain_http(&url) {
        eprintln!("WARNING: --url uses plain HTTP; the OpenStack token will travel unencrypted.");
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&token);
    let audit = begin_audit(store.as_ref(), "openstack.import", "cloud", Some(&url)).await?;
    let result: Result<()> = async {
        let client = OpenStackClient::new(&url, token, project, region, no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("OpenStack", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn gcp <action>`.
pub(crate) async fn gcp(config: &Config, action: GcpAction) -> Result<()> {
    let GcpAction::Import {
        project,
        token,
        endpoint_url,
        no_verify,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_GCP_TOKEN")?.ok_or_else(|| {
        anyhow!(
            "a GCP bearer token is required: pass --token, set ORBYN_GCP_TOKEN, or use --token -"
        )
    })?;
    if no_verify {
        eprintln!("WARNING: --no-verify disables TLS certificate verification for GCP.");
    }
    if endpoint_url.as_deref().is_some_and(is_plain_http) {
        eprintln!(
            "WARNING: --endpoint-url uses plain HTTP; the GCP token will travel unencrypted."
        );
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&token);
    let audit = begin_audit(store.as_ref(), "gcp.import", "cloud", Some(&project)).await?;
    let result: Result<()> = async {
        let client = GcpClient::new(token, &project, endpoint_url.as_deref(), no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("GCP", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn azure <action>`.
pub(crate) async fn azure(config: &Config, action: AzureAction) -> Result<()> {
    let AzureAction::Import {
        subscription_id,
        token,
        endpoint_url,
        no_verify,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_AZURE_TOKEN")?
        .ok_or_else(|| anyhow!("an Azure bearer token is required: pass --token, set ORBYN_AZURE_TOKEN, or use --token -"))?;
    if no_verify {
        eprintln!("WARNING: --no-verify disables TLS certificate verification for Azure.");
    }
    if endpoint_url.as_deref().is_some_and(is_plain_http) {
        eprintln!(
            "WARNING: --endpoint-url uses plain HTTP; the Azure token will travel unencrypted."
        );
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    redactor.add_value(&token);
    let audit = begin_audit(
        store.as_ref(),
        "azure.import",
        "cloud",
        Some(&subscription_id),
    )
    .await?;
    let result: Result<()> = async {
        let client = AzureClient::new(
            AzureCredentials {
                bearer_token: token,
            },
            &subscription_id,
            endpoint_url.as_deref(),
            no_verify,
        )
        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let inventory = client
            .fetch_inventory()
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        crate::app::inventory::persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("Azure", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Print the operator-facing summary of a cloud import.
fn print_cloud_import(provider: &str, inv: &CloudInventory) {
    let counts = inv.counts();
    let mut parts = vec![format!("{} assets", counts.assets)];
    if counts.interfaces > 0 {
        parts.push(format!("{} interfaces", counts.interfaces));
    }
    if counts.capacities > 0 {
        parts.push(format!("{} capacity rows", counts.capacities));
    }
    if counts.filesystems > 0 {
        parts.push(format!("{} filesystems", counts.filesystems));
    }
    eprintln!(
        "Imported {} from {provider} ({}).",
        parts.join(", "),
        inv.provenance.label()
    );
    for note in &inv.skipped {
        tracing::warn!(note, "skipped a cloud resource");
    }
    if !inv.skipped.is_empty() {
        eprintln!(
            "Skipped {} resource(s) that could not be represented.",
            inv.skipped.len()
        );
    }
}
