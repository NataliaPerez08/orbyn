//! Handlers for the cloud provider imports: `proxmox`, `aws`, `huawei`,
//! `openstack`, `gcp`, and `azure`.

use anyhow::{anyhow, Result};
use chrono::Utc;

use orbyn::config::Config;
use orbyn::domain::{DiscoveryJob, JobOutcome, JobStatus, Observation};
use orbyn::integrations::cloud::aws::{AwsClient, AwsCredentials};
use orbyn::integrations::cloud::azure::{AzureClient, AzureCredentials};
use orbyn::integrations::cloud::gcp::GcpClient;
use orbyn::integrations::cloud::huawei::{HuaweiClient, HuaweiCredentials};
use orbyn::integrations::cloud::openstack::OpenStackClient;
use orbyn::integrations::cloud::proxmox::ProxmoxClient;
use orbyn::integrations::cloud::{CloudCounts, CloudInventory};
use orbyn::store::traits::AssetAnnotations;
use orbyn::store::Store;

use crate::cli::args::{
    AwsAction, AzureAction, GcpAction, HuaweiAction, OpenstackAction, ProxmoxAction,
};
use crate::cli::{
    begin_audit, finish_audit_result, is_plain_http, open_store, resolve_secret, IMPORT_WRITE_CHUNK,
};

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
        persist_cloud_inventory(store.as_ref(), &inventory)
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
        persist_cloud_inventory(store.as_ref(), &inventory)
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
        persist_cloud_inventory(store.as_ref(), &inventory)
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
        persist_cloud_inventory(store.as_ref(), &inventory)
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
        persist_cloud_inventory(store.as_ref(), &inventory)
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
        persist_cloud_inventory(store.as_ref(), &inventory)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        print_cloud_import("Azure", &inventory);
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Persist a normalized cloud inventory — assets, interfaces, services,
/// capacity and filesystems — recording a discovery job named after the
/// provider and attaching its provenance tags to every asset.
///
/// Unlike a flat file import, a cloud adapter has already validated and
/// normalized its rows, so this writes them directly. Assets are written
/// first so interface/service/capacity references satisfy their foreign keys.
async fn persist_cloud_inventory(store: &dyn Store, inv: &CloudInventory) -> Result<CloudCounts> {
    let counts = inv.counts();

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: inv.provenance.provider.clone(),
        targets: vec![inv.provenance.label()],
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

    // Assets first, in bounded chunks, then their annotations in one
    // transaction (one commit per asset would be thousands of disk syncs).
    let mut asset_observations = Vec::with_capacity(inv.assets.len());
    let mut annotation_edits = Vec::with_capacity(inv.assets.len());
    for cloud_asset in &inv.assets {
        asset_observations.push(Observation::Asset(cloud_asset.asset.clone()));
        let mut tags = cloud_asset.tags.clone();
        tags.extend(inv.provenance.tags());
        annotation_edits.push((
            cloud_asset.asset.id.clone(),
            AssetAnnotations {
                environment: cloud_asset.environment.clone(),
                owner: cloud_asset.owner.clone(),
                criticality: cloud_asset.criticality,
                unset: Vec::new(),
                add_tags: tags,
                remove_tags: Vec::new(),
            },
        ));
    }
    for chunk in asset_observations.chunks(IMPORT_WRITE_CHUNK) {
        store.store_observations(chunk.to_vec()).await?;
    }
    if !annotation_edits.is_empty() {
        store.annotate_assets(annotation_edits).await?;
    }

    let mut observations: Vec<Observation> = Vec::new();
    observations.extend(inv.interfaces.iter().cloned().map(Observation::Interface));
    observations.extend(inv.services.iter().cloned().map(Observation::Service));
    observations.extend(inv.capacities.iter().cloned().map(Observation::Capacity));
    observations.extend(inv.filesystems.iter().cloned().map(Observation::Filesystem));
    if !observations.is_empty() {
        store.store_observations(observations).await?;
    }

    store
        .finish_job(
            &job.id,
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: counts.assets as u32,
                services_found: counts.services as u32,
                filesystems_found: counts.filesystems as u32,
                running_services_found: 0,
                connections_found: 0,
            }),
        )
        .await?;

    Ok(counts)
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
