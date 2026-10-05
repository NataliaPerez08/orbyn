//! Handlers for the inventory command family: read-only asset views,
//! annotation, and inventory export.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use orbyn::config::Config;
use orbyn::domain::Criticality;
use orbyn::integrations::ansible::{render_ansible_inventory, render_ansible_yaml, GroupBy};
use orbyn::integrations::terraform::{render_import_blocks, render_terraform};
use orbyn::output::{Format, Inventory};
use orbyn::store::traits::{AnnotationField, AssetAnnotations};

use crate::cli::args::{ExportFormat, UnsetField};
use crate::cli::{
    begin_audit, finish_audit_result, open_store, render_asset_detail, resolve_asset,
};

pub(crate) async fn assets(config: &Config, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let assets = store.list_assets().await?;
    print!("{}", orbyn::output::assets(&assets, format));
    Ok(())
}

pub(crate) async fn asset(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let rendered = render_asset_detail(store.as_ref(), &asset, format).await?;
    print!("{rendered}");
    Ok(())
}

#[allow(clippy::too_many_arguments)] // mirrors the annotate CLI surface
pub(crate) async fn annotate(
    config: &Config,
    asset: String,
    environment: Option<String>,
    owner: Option<String>,
    criticality: Option<String>,
    unset: Vec<UnsetField>,
    add_tag: Vec<String>,
    remove_tag: Vec<String>,
    format: Format,
) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let criticality = criticality
        .map(|c| c.parse::<Criticality>())
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let audit = begin_audit(
        store.as_ref(),
        "annotate",
        &asset.id,
        Some("asset annotation"),
    )
    .await?;
    let result = store
        .annotate_asset(
            &asset.id,
            AssetAnnotations {
                environment,
                owner,
                criticality,
                unset: unset.into_iter().map(AnnotationField::from).collect(),
                add_tags: add_tag,
                remove_tags: remove_tag,
            },
        )
        .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    let updated = store.get_asset(&asset.id).await?.expect("asset exists");
    let rendered = render_asset_detail(store.as_ref(), &updated, format).await?;
    print!("{rendered}");
    Ok(())
}

pub(crate) async fn services(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let services = store.list_services(&asset.id).await?;
    print!("{}", orbyn::output::services(&services, format));
    Ok(())
}

pub(crate) async fn interfaces(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let ifaces = store.list_interfaces(&asset.id).await?;
    print!("{}", orbyn::output::interfaces(&ifaces, format));
    Ok(())
}

pub(crate) async fn capacity(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let capacity = store.get_capacity(&asset.id).await?;
    print!("{}", orbyn::output::capacity(capacity.as_ref(), format));
    Ok(())
}

pub(crate) async fn disks(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let filesystems = store.list_filesystems(&asset.id).await?;
    print!("{}", orbyn::output::filesystems(&filesystems, format));
    Ok(())
}

pub(crate) async fn host_services(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let running = store.list_running_services(&asset.id).await?;
    print!("{}", orbyn::output::running_services(&running, format));
    Ok(())
}

pub(crate) async fn connections(config: &Config, asset: String, format: Format) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let conns = store.list_connections(&asset.id).await?;
    print!("{}", orbyn::output::connections(&conns, format));
    Ok(())
}

pub(crate) async fn export(
    config: &Config,
    format: ExportFormat,
    group_by: GroupBy,
    tf_import: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    if tf_import.is_some() && format != ExportFormat::Terraform {
        bail!("--tf-import requires --format terraform");
    }
    let store = open_store(config).await?;
    let assets = store.list_assets().await?;

    let rendered = match format {
        ExportFormat::Ansible => render_ansible_inventory(&assets, group_by),
        ExportFormat::AnsibleYaml => render_ansible_yaml(&assets, group_by),
        ExportFormat::Terraform => {
            let mut out = render_terraform(&assets);
            if let Some(resource_type) = tf_import {
                out.push_str(&render_import_blocks(&assets, &resource_type)?);
            }
            out
        }
        ExportFormat::Json | ExportFormat::Csv => {
            let services = store.list_all_services().await?;
            let interfaces = store.list_all_interfaces().await?;
            let format = match format {
                ExportFormat::Json => Format::Json,
                ExportFormat::Csv => Format::Csv,
                _ => unreachable!(),
            };
            orbyn::output::inventory(
                &Inventory {
                    assets,
                    services,
                    interfaces,
                },
                format,
            )
        }
    };
    match output {
        Some(path) => std::fs::write(&path, rendered)
            .with_context(|| format!("writing export to {}", path.display()))?,
        None => print!("{rendered}"),
    }
    Ok(())
}
