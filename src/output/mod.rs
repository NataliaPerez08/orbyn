//! CLI output rendering.
//!
//! Every command produces either a human-friendly table (default) or a
//! machine-readable stream (`json` / `csv`). Rendering is centralized here so
//! commands stay focused on fetching and computing data.

use std::fmt;

use comfy_table::{Cell, ContentArrangement, Table};

use crate::assessment::{AssessmentReport, Severity};
use crate::domain::{Asset, Criticality, Dependency, DiscoveryJob, Interface, JobStatus, Service};

/// Output format selected through `--format` on each command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Table,
    Json,
    Csv,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Table => write!(f, "table"),
            Format::Json => write!(f, "json"),
            Format::Csv => write!(f, "csv"),
        }
    }
}

/// Render a list of assets.
pub fn assets(assets: &[Asset], format: Format) -> String {
    match format {
        Format::Json => json(&assets),
        Format::Csv => {
            let mut out = String::from(
                "id,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n",
            );
            for a in assets {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    csv(&a.id),
                    csv(&a.ip.to_string()),
                    csv(&a.hostname.clone().unwrap_or_default()),
                    csv(&a.device_class.clone().unwrap_or_default()),
                    csv(&a.os_name.clone().unwrap_or_default()),
                    csv(&a.os_version.clone().unwrap_or_default()),
                    csv(&a.environment.clone().unwrap_or_default()),
                    csv(&a.owner.clone().unwrap_or_default()),
                    csv(&a.criticality.map(|c| c.to_string()).unwrap_or_default()),
                    csv(&a.tags.join(",")),
                    a.first_seen.to_rfc3339(),
                    a.last_seen.to_rfc3339(),
                ));
            }
            out
        }
        Format::Table => {
            if assets.is_empty() {
                return "No assets discovered yet. Run `orbyn discover --target <cidr>`.\n"
                    .to_string();
            }
            let mut table = table(&[
                "ID",
                "IP",
                "Hostname",
                "Class",
                "OS",
                "Env",
                "Owner",
                "Crit",
                "Tags",
                "First seen",
                "Last seen",
            ]);
            for a in assets {
                table.add_row(vec![
                    Cell::new(&a.id),
                    Cell::new(a.ip.to_string()),
                    Cell::new(a.hostname.clone().unwrap_or_default()),
                    Cell::new(a.device_class.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(os_label(a)),
                    Cell::new(a.environment.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(a.owner.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(criticality_label(a.criticality)),
                    Cell::new(a.tags.join(",")),
                    Cell::new(a.first_seen.format("%Y-%m-%d %H:%M:%S").to_string()),
                    Cell::new(a.last_seen.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render the services of a single asset.
pub fn services(services: &[Service], format: Format) -> String {
    match format {
        Format::Json => json(&services),
        Format::Csv => {
            let mut out = String::from("asset_id,proto,port,name,state,banner\n");
            for s in services {
                out.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    csv(&s.asset_id),
                    csv(&s.proto),
                    s.port,
                    csv(&s.name.clone().unwrap_or_default()),
                    csv(&s.state),
                    csv(&s.banner.clone().unwrap_or_default()),
                ));
            }
            out
        }
        Format::Table => {
            if services.is_empty() {
                return "No services observed for this asset.\n".to_string();
            }
            let mut table = table(&["Proto", "Port", "Service", "State", "Banner"]);
            for s in services {
                table.add_row(vec![
                    Cell::new(&s.proto),
                    Cell::new(s.port),
                    Cell::new(s.name.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(&s.state),
                    Cell::new(s.banner.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render the interfaces of a single asset.
pub fn interfaces(ifaces: &[Interface], format: Format) -> String {
    match format {
        Format::Json => json(ifaces),
        Format::Csv => {
            let mut out = String::from("asset_id,name,mac,ip,vendor,mtu,if_index,up\n");
            for i in ifaces {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    csv(&i.asset_id),
                    csv(&i.name.clone().unwrap_or_default()),
                    csv(&i.mac.clone().unwrap_or_default()),
                    csv(&i.ip.map(|ip| ip.to_string()).unwrap_or_default()),
                    csv(&i.vendor.clone().unwrap_or_default()),
                    i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
                    i.if_index
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".into()),
                    match i.is_up {
                        Some(true) => "up",
                        Some(false) => "down",
                        None => "-",
                    },
                ));
            }
            out
        }
        Format::Table => {
            if ifaces.is_empty() {
                return "No interfaces observed for this asset.\n".to_string();
            }
            let mut table = table(&["Name", "MAC", "IP", "Vendor", "MTU", "State"]);
            for i in ifaces {
                table.add_row(vec![
                    Cell::new(i.name.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(i.mac.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(i.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "-".into())),
                    Cell::new(i.vendor.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into())),
                    Cell::new(match i.is_up {
                        Some(true) => "up",
                        Some(false) => "down",
                        None => "-",
                    }),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render a discovery job history listing.
pub fn jobs(jobs: &[DiscoveryJob], format: Format) -> String {
    match format {
        Format::Json => json(jobs),
        Format::Csv => {
            let mut out = String::from(
                "id,collector,status,targets,started_at,finished_at,assets_found,services_found,error\n",
            );
            for j in jobs {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    csv(&j.id),
                    csv(&j.collector),
                    job_status_str(j.status),
                    csv(&j.targets.join(";")),
                    j.started_at.to_rfc3339(),
                    j.finished_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    j.assets_found.map(|n| n.to_string()).unwrap_or_default(),
                    j.services_found.map(|n| n.to_string()).unwrap_or_default(),
                    csv(&j.error.clone().unwrap_or_default()),
                ));
            }
            out
        }
        Format::Table => {
            if jobs.is_empty() {
                return "No discovery jobs recorded yet. Run `orbyn discover --target <cidr>`.\n"
                    .to_string();
            }
            let mut table = table(&[
                "ID",
                "Collector",
                "Status",
                "Targets",
                "Started",
                "Duration",
                "Assets",
                "Services",
            ]);
            for j in jobs {
                table.add_row(vec![
                    Cell::new(&j.id),
                    Cell::new(&j.collector),
                    Cell::new(job_status_str(j.status)),
                    Cell::new(j.targets.join(",")),
                    Cell::new(j.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                    Cell::new(duration_label(j)),
                    Cell::new(
                        j.assets_found
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                    Cell::new(
                        j.services_found
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render a rich asset detail view: annotations, services, and interfaces.
pub fn asset_detail(
    asset: &Asset,
    svcs: &[Service],
    ifaces: &[Interface],
    format: Format,
) -> String {
    match format {
        Format::Json => json(&AssetDetail {
            asset: asset.clone(),
            services: svcs.to_vec(),
            interfaces: ifaces.to_vec(),
        }),
        Format::Csv => {
            let mut out = assets(std::slice::from_ref(asset), Format::Csv);
            out.push_str(&interfaces(ifaces, Format::Csv));
            out.push_str(&services(svcs, Format::Csv));
            out
        }
        Format::Table => {
            let mut out = String::new();
            out.push_str(&format!("Asset     : {}\n", asset.id));
            out.push_str(&format!("IP        : {}\n", asset.ip));
            out.push_str(&format!(
                "Hostname  : {}\n",
                asset.hostname.clone().unwrap_or_default()
            ));
            out.push_str(&format!(
                "Class     : {}\n",
                asset.device_class.clone().unwrap_or_else(|| "-".into())
            ));
            out.push_str(&format!("OS        : {}\n", os_label(asset)));
            out.push_str(&format!(
                "Env       : {}\n",
                asset.environment.clone().unwrap_or_else(|| "-".into())
            ));
            out.push_str(&format!(
                "Owner     : {}\n",
                asset.owner.clone().unwrap_or_else(|| "-".into())
            ));
            out.push_str(&format!(
                "Criticality: {}\n",
                criticality_label(asset.criticality)
            ));
            out.push_str(&format!(
                "Tags      : {}\n",
                if asset.tags.is_empty() {
                    "-".into()
                } else {
                    asset.tags.join(",")
                }
            ));
            out.push_str(&format!(
                "First seen: {}\n",
                asset.first_seen.format("%Y-%m-%d %H:%M:%S")
            ));
            out.push_str(&format!(
                "Last seen : {}\n",
                asset.last_seen.format("%Y-%m-%d %H:%M:%S")
            ));
            out.push('\n');
            out.push_str(&interfaces(ifaces, Format::Table));
            out.push('\n');
            out.push_str(&services(svcs, Format::Table));
            out
        }
    }
}

/// Render the dependency graph (edge list).
pub fn dependencies(edges: &[Dependency], format: Format) -> String {
    match format {
        Format::Json => json(&edges),
        Format::Csv => {
            let mut out = String::from(
                "source_asset_id,target_asset_id,proto,port,evidence_source,confidence,confirmed\n",
            );
            for d in edges {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    csv(&d.source_asset_id),
                    csv(&d.target_asset_id),
                    csv(&d.proto),
                    d.port,
                    csv(&d.evidence_source),
                    d.confidence,
                    d.confirmed,
                ));
            }
            out
        }
        Format::Table => {
            if edges.is_empty() {
                return "No dependencies yet. Dependency mapping arrives in v0.4.\n".to_string();
            }
            let mut table = table(&[
                "Source",
                "->",
                "Target",
                "Proto",
                "Port",
                "Evidence",
                "Confidence",
            ]);
            for d in edges {
                table.add_row(vec![
                    Cell::new(&d.source_asset_id),
                    Cell::new("->"),
                    Cell::new(&d.target_asset_id),
                    Cell::new(&d.proto),
                    Cell::new(d.port),
                    Cell::new(&d.evidence_source),
                    Cell::new(format!("{:.0}%", d.confidence * 100.0)),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render an assessment report.
pub fn report(report: &AssessmentReport, format: Format) -> String {
    match format {
        Format::Json => json(report),
        Format::Csv => {
            let mut out = String::from("rule_id,severity,asset_id,message,evidence\n");
            for f in &report.findings {
                out.push_str(&format!(
                    "{},{},{},{},{}\n",
                    csv(&f.rule_id),
                    severity_str(f.severity),
                    csv(&f.asset_id.clone().unwrap_or_default()),
                    csv(&f.message),
                    csv(&f.evidence.join(";")),
                ));
            }
            out.push_str(&format!("#overall_score,{}\n", report.overall_score));
            out
        }
        Format::Table => {
            let mut out = String::new();
            let mut findings = String::new();
            if report.findings.is_empty() {
                findings.push_str("  (no findings)\n");
            } else {
                let mut table = table(&["Rule", "Severity", "Asset", "Finding"]);
                for f in &report.findings {
                    table.add_row(vec![
                        Cell::new(&f.rule_id),
                        Cell::new(severity_str(f.severity)),
                        Cell::new(f.asset_id.clone().unwrap_or_else(|| "-".into())),
                        Cell::new(&f.message),
                    ]);
                }
                findings = table.to_string();
            }
            out.push_str(&format!(
                "Assets assessed : {}\nOverall score   : {}\n\n{}",
                report.assets_assessed, report.overall_score, findings
            ));
            out
        }
    }
}

/// An inventory snapshot used by `orbyn export`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Inventory {
    pub assets: Vec<Asset>,
    pub services: Vec<Service>,
    pub interfaces: Vec<Interface>,
}

/// A full asset record used by `orbyn asset <id-or-ip>`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssetDetail {
    pub asset: Asset,
    pub services: Vec<Service>,
    pub interfaces: Vec<Interface>,
}

/// Render a full inventory export.
pub fn inventory(inv: &Inventory, format: Format) -> String {
    match format {
        Format::Json => json(inv),
        // CSV export is a set of worksheets: assets, then interfaces, then
        // services, each introduced by its column header.
        Format::Csv => {
            let mut out = format!("#assets\n{}", assets(&inv.assets, Format::Csv));
            out.push_str(&format!(
                "\n#interfaces\n{}",
                interfaces(&inv.interfaces, Format::Csv)
            ));
            out.push_str(&format!(
                "\n#services\n{}",
                services(&inv.services, Format::Csv)
            ));
            out
        }
        Format::Table => {
            let mut out = assets(&inv.assets, Format::Table);
            out.push('\n');
            out.push_str(&interfaces(&inv.interfaces, Format::Table));
            out.push('\n');
            out.push_str(&services(&inv.services, Format::Table));
            out
        }
    }
}

fn os_label(asset: &Asset) -> String {
    if let (Some(name), Some(version)) = (&asset.os_name, &asset.os_version) {
        format!("{name} {version}")
    } else {
        asset.os_name.clone().unwrap_or_else(|| "-".into())
    }
}

fn criticality_label(criticality: Option<Criticality>) -> String {
    match criticality {
        Some(c) => c.to_string(),
        None => "-".into(),
    }
}

fn job_status_str(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
    }
}

fn duration_label(job: &DiscoveryJob) -> String {
    match job.finished_at {
        Some(finished) => {
            let secs = (finished - job.started_at).num_seconds().max(0);
            if secs < 60 {
                format!("{secs}s")
            } else {
                format!("{}m {:02}s", secs / 60, secs % 60)
            }
        }
        None => "-".into(),
    }
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

fn csv(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn table(header: &[&str]) -> Table {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(header);
    table
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::High => "high",
    }
}
