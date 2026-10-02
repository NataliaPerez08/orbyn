//! CLI output rendering.
//!
//! Every command produces either a human-friendly table (default) or a
//! machine-readable stream (`json` / `csv`). Rendering is centralized here so
//! commands stay focused on fetching and computing data.

use std::fmt;

use comfy_table::{Cell, ContentArrangement, Table};

use crate::assessment::rules::Rule;
use crate::assessment::{AssessmentReport, Severity};
use crate::domain::{
    Asset, AuditEvent, Capacity, Connection, Criticality, Dependency, DiscoveryJob, EvidenceKind,
    Filesystem, Interface, JobStatus, RunningService, Service,
};
use crate::metrics::{SampleConfidence, WindowStats};

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

/// Render recorded CPU/RAM capacity for an asset.
pub fn capacity(cap: Option<&Capacity>, format: Format) -> String {
    match format {
        Format::Json => json(&cap),
        Format::Csv => {
            let mut out = String::from(
                "asset_id,cpu_model,cpu_sockets,cpu_cores,cpu_threads,ram_total_mb,hypervisor,collected_at\n",
            );
            if let Some(c) = cap {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    csv(&c.asset_id),
                    csv(&c.cpu_model.clone().unwrap_or_default()),
                    c.cpu_sockets.map(|v| v.to_string()).unwrap_or_default(),
                    c.cpu_cores.map(|v| v.to_string()).unwrap_or_default(),
                    c.cpu_threads.map(|v| v.to_string()).unwrap_or_default(),
                    c.ram_total_mb.map(|v| v.to_string()).unwrap_or_default(),
                    csv(&c.hypervisor.clone().unwrap_or_default()),
                    c.collected_at.to_rfc3339(),
                ));
            }
            out
        }
        Format::Table => match cap {
            None => "No capacity recorded for this asset yet.\n".to_string(),
            Some(c) => {
                let vcpu = c
                    .cpu_threads
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into());
                format!(
                    "CPU model  : {}\nSockets    : {}\nCores      : {}\nvCPU       : {}\nRAM        : {}\nHypervisor : {}\nCollected  : {}\n",
                    c.cpu_model.clone().unwrap_or_else(|| "-".into()),
                    c.cpu_sockets.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                    c.cpu_cores.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                    vcpu,
                    c.ram_total_mb
                        .map(|mb| format!("{mb} MB"))
                        .unwrap_or_else(|| "-".into()),
                    c.hypervisor
                        .clone()
                        .unwrap_or_else(|| "- (bare metal or undetected)".into()),
                    c.collected_at.format("%Y-%m-%d %H:%M:%S"),
                )
            }
        },
    }
}

/// Render a utilization window: avg/p95/p99/peak + evidence confidence.
pub fn metrics(stats: Option<&WindowStats>, format: Format) -> String {
    match format {
        Format::Json => json(&stats),
        Format::Csv => {
            let mut out = String::from("metric,statistic,value\n");
            if let Some(s) = stats {
                let rows = [
                    (
                        "cpu_usage_percent",
                        s.cpu_avg_percent,
                        s.cpu_p95_percent,
                        s.cpu_p99_percent,
                        s.cpu_peak_percent,
                    ),
                    (
                        "ram_used_mb",
                        s.ram_avg_mb,
                        s.ram_p95_mb,
                        s.ram_p99_mb,
                        s.ram_peak_mb,
                    ),
                    (
                        "swap_used_mb",
                        s.swap_avg_mb,
                        s.swap_p95_mb,
                        s.swap_p99_mb,
                        s.swap_peak_mb,
                    ),
                ];
                for (name, avg, p95, p99, peak) in rows {
                    out.push_str(&format!(
                        "{name},avg,{}\n{name},p95,{}\n{name},p99,{}\n{name},peak,{}\n",
                        fmt_opt_float(avg),
                        fmt_opt_float(p95),
                        fmt_opt_float(p99),
                        fmt_opt_float(peak),
                    ));
                }
                if let Some(cmp) = &s.comparison {
                    for (name, prior, recent) in [
                        (
                            "cpu_usage_percent",
                            cmp.cpu_p95_prior_percent,
                            cmp.cpu_p95_recent_percent,
                        ),
                        ("ram_used_mb", cmp.ram_p95_prior_mb, cmp.ram_p95_recent_mb),
                        (
                            "swap_used_mb",
                            cmp.swap_p95_prior_mb,
                            cmp.swap_p95_recent_mb,
                        ),
                    ] {
                        out.push_str(&format!(
                            "{name},prior_p95,{}\n{name},recent_p95,{}\n",
                            fmt_opt_float(prior),
                            fmt_opt_float(recent),
                        ));
                    }
                    out.push_str(&format!(
                        "comparison_sub_window_hours,,{}\ncomparison_prior_samples,,{}\n\
                         comparison_recent_samples,,{}\n",
                        fmt_opt_float(Some(cmp.sub_window_hours)),
                        cmp.prior_sample_count,
                        cmp.recent_sample_count,
                    ));
                }
                out.push_str(&format!(
                    "confidence,,{}\nsample_count,0,{}\n",
                    s.confidence, s.sample_count
                ));
                out.push_str(&format!(
                    "window_start,,{}\nwindow_end,,{}\nspan_hours,,{}\n",
                    s.window_start.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    s.window_end.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    fmt_opt_float(s.span_hours),
                ));
                out.push_str(&format!(
                    "right_sizing_ready,,{}\n",
                    if s.right_sizing_ready() {
                        "true"
                    } else {
                        "false"
                    }
                ));
            }
            out
        }
        Format::Table => match stats {
            None => "No metric samples recorded for this asset yet.\n".to_string(),
            Some(s) => {
                let span = match (s.span_hours, s.window_start, s.window_end) {
                    (Some(hours), Some(start), Some(end)) => format!(
                        "{} samples over {:.1}h ({} .. {})",
                        s.sample_count,
                        hours,
                        start.format("%Y-%m-%d %H:%M"),
                        end.format("%Y-%m-%d %H:%M"),
                    ),
                    _ => format!("{} samples (no time span)", s.sample_count),
                };
                let readiness = if s.right_sizing_ready() {
                    "sufficient for right-sizing".to_string()
                } else {
                    format!(
                        "insufficient for right-sizing (needs >= {:.0}h of history \
                         with high confidence; import periodic samples, e.g. \
                         `orbyn prometheus import`)",
                        crate::metrics::MIN_WINDOW_HOURS_FOR_RIGHT_SIZING
                    )
                };
                format!(
                    "Utilization window: {span}\n\
                     CPU usage : avg {}   p95 {}   p99 {}   peak {}\n\
                     RAM used  : avg {}   p95 {}   p99 {}   peak {}\n",
                    fmt_pct(s.cpu_avg_percent),
                    fmt_pct(s.cpu_p95_percent),
                    fmt_pct(s.cpu_p99_percent),
                    fmt_pct(s.cpu_peak_percent),
                    fmt_mb(s.ram_avg_mb),
                    fmt_mb(s.ram_p95_mb),
                    fmt_mb(s.ram_p99_mb),
                    fmt_mb(s.ram_peak_mb),
                ) + &swap_line(s)
                    + &comparison_lines(s)
                    + &format!(
                        "Confidence: {} (evidence quality)\n\
                         Window    : {readiness}\n",
                        display_confidence(s.confidence),
                    )
            }
        },
    }
}

/// Swap row, shown only when the window actually carries swap samples: a
/// dash everywhere would read as "swap is zero" on hosts that never report
/// it.
fn swap_line(s: &WindowStats) -> String {
    if s.swap_p95_mb.is_none() {
        return String::new();
    }
    format!(
        "Swap used  : avg {}   p95 {}   p99 {}   peak {}\n",
        fmt_mb(s.swap_avg_mb),
        fmt_mb(s.swap_p95_mb),
        fmt_mb(s.swap_p99_mb),
        fmt_mb(s.swap_peak_mb),
    )
}

/// Week-over-week block, shown only when the window spans two right-sizing
/// weeks and both halves carry enough samples.
fn comparison_lines(s: &WindowStats) -> String {
    let Some(cmp) = &s.comparison else {
        return String::new();
    };
    let mut out = format!(
        "Trend      : last {:.0}h vs the {:.0}h before it ({} vs {} samples)\n",
        cmp.sub_window_hours, cmp.sub_window_hours, cmp.recent_sample_count, cmp.prior_sample_count,
    );
    let mut line = |label: &str,
                    prior: Option<f64>,
                    recent: Option<f64>,
                    render: &dyn Fn(Option<f64>) -> String| {
        if prior.is_none() && recent.is_none() {
            return;
        }
        out.push_str(&format!(
            "  {label}: p95 {} -> {}\n",
            render(prior),
            render(recent)
        ));
    };
    line(
        "CPU p95",
        cmp.cpu_p95_prior_percent,
        cmp.cpu_p95_recent_percent,
        &fmt_pct,
    );
    line(
        "RAM p95",
        cmp.ram_p95_prior_mb,
        cmp.ram_p95_recent_mb,
        &fmt_mb,
    );
    line(
        "Swap p95",
        cmp.swap_p95_prior_mb,
        cmp.swap_p95_recent_mb,
        &fmt_mb,
    );
    out
}

fn fmt_mb(v: Option<f64>) -> String {
    v.map(|mb| {
        if mb >= 1024.0 {
            format!("{:.2} GiB", mb / 1024.0)
        } else {
            format!("{mb:.0} MB")
        }
    })
    .unwrap_or_else(|| "-".into())
}

fn fmt_pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.2}%")).unwrap_or_else(|| "-".into())
}

fn display_confidence(c: SampleConfidence) -> &'static str {
    match c {
        SampleConfidence::High => "high",
        SampleConfidence::Medium => "medium",
        SampleConfidence::Low => "low (keep collecting samples)",
    }
}

pub fn fmt_opt_float(v: Option<f64>) -> String {
    match v {
        Some(v) => {
            let mut s = format!("{v:.2}");
            if s.ends_with(".00") {
                s.truncate(s.len() - 3);
            }
            s
        }
        None => String::new(),
    }
}

/// Render the filesystem inventory of an asset.
pub fn filesystems(filesystems: &[Filesystem], format: Format) -> String {
    match format {
        Format::Json => json(filesystems),
        Format::Csv => {
            let mut out = String::from(
                "asset_id,device,mount,fs_type,size_kb,used_kb,available_kb,used_pct\n",
            );
            for f in filesystems {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    csv(&f.asset_id),
                    csv(&f.device.clone().unwrap_or_default()),
                    csv(&f.mount),
                    csv(&f.fs_type.clone().unwrap_or_default()),
                    f.size_kb,
                    f.used_kb.map(|v| v.to_string()).unwrap_or_default(),
                    f.available_kb.map(|v| v.to_string()).unwrap_or_default(),
                    f.used_pct.map(|v| v.to_string()).unwrap_or_default(),
                ));
            }
            out
        }
        Format::Table => {
            if filesystems.is_empty() {
                return "No filesystems recorded for this asset yet.\n".to_string();
            }
            let mut table = table(&["Device", "Mount", "Type", "Size", "Used", "Free", "Use%"]);
            for f in filesystems {
                table.add_row(vec![
                    Cell::new(f.device.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(&f.mount),
                    Cell::new(f.fs_type.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(human_kb(f.size_kb)),
                    Cell::new(f.used_kb.map(human_kb).unwrap_or_else(|| "-".into())),
                    Cell::new(f.available_kb.map(human_kb).unwrap_or_else(|| "-".into())),
                    Cell::new(
                        f.used_pct
                            .map(|p| format!("{p}%"))
                            .unwrap_or_else(|| "-".into()),
                    ),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render the running host services of an asset.
pub fn running_services(services: &[RunningService], format: Format) -> String {
    match format {
        Format::Json => json(services),
        Format::Csv => {
            let mut out = String::from("asset_id,name,state,description\n");
            for s in services {
                out.push_str(&format!(
                    "{},{},{},{}\n",
                    csv(&s.asset_id),
                    csv(&s.name),
                    csv(&s.state.clone().unwrap_or_default()),
                    csv(&s.description.clone().unwrap_or_default()),
                ));
            }
            out
        }
        Format::Table => {
            if services.is_empty() {
                return "No running services recorded for this asset yet.\n".to_string();
            }
            let mut table = table(&["Service", "State", "Description"]);
            for s in services {
                table.add_row(vec![
                    Cell::new(&s.name),
                    Cell::new(s.state.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(s.description.clone().unwrap_or_else(|| "-".into())),
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
                "id,collector,status,targets,started_at,finished_at,assets_found,services_found,\
                 filesystems_found,running_services_found,connections_found,error\n",
            );
            for j in jobs {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    csv(&j.id),
                    csv(&j.collector),
                    job_status_str(j.status),
                    csv(&j.targets.join(";")),
                    j.started_at.to_rfc3339(),
                    j.finished_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    j.assets_found.map(|n| n.to_string()).unwrap_or_default(),
                    j.services_found.map(|n| n.to_string()).unwrap_or_default(),
                    j.filesystems_found
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
                    j.running_services_found
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
                    j.connections_found
                        .map(|n| n.to_string())
                        .unwrap_or_default(),
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
                "Filesystems",
                "Running",
                "Conns",
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
                    Cell::new(
                        j.filesystems_found
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                    Cell::new(
                        j.running_services_found
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                    Cell::new(
                        j.connections_found
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render mutating CLI operations recorded in the operational audit trail.
pub fn audit_events(events: &[AuditEvent], format: Format) -> String {
    match format {
        Format::Json => json(events),
        Format::Csv => {
            let mut out =
                String::from("id,action,target,status,started_at,finished_at,details,error\n");
            for event in events {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    csv(&event.id),
                    csv(&event.action),
                    csv(&event.target),
                    job_status_str(event.status),
                    event.started_at.to_rfc3339(),
                    event
                        .finished_at
                        .map(|ts| ts.to_rfc3339())
                        .unwrap_or_default(),
                    csv(&event.details.clone().unwrap_or_default()),
                    csv(&event.error.clone().unwrap_or_default()),
                ));
            }
            out
        }
        Format::Table => {
            if events.is_empty() {
                return "No audit events recorded yet.\n".to_string();
            }
            let mut table = table(&[
                "ID", "Action", "Target", "Status", "Started", "Duration", "Details", "Error",
            ]);
            for event in events {
                table.add_row(vec![
                    Cell::new(&event.id),
                    Cell::new(&event.action),
                    Cell::new(&event.target),
                    Cell::new(job_status_str(event.status)),
                    Cell::new(event.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                    Cell::new(audit_duration_label(event)),
                    Cell::new(event.details.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(event.error.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render a rich asset detail view: annotations, interfaces, capacity,
/// filesystems, network services and running host services.
#[allow(clippy::too_many_arguments)]
pub fn asset_detail(
    asset: &Asset,
    svcs: &[Service],
    ifaces: &[Interface],
    cap: Option<&Capacity>,
    disks: &[Filesystem],
    running: &[RunningService],
    format: Format,
) -> String {
    match format {
        Format::Json => json(&AssetDetail {
            asset: asset.clone(),
            services: svcs.to_vec(),
            interfaces: ifaces.to_vec(),
            capacity: cap.cloned(),
            filesystems: disks.to_vec(),
            running_services: running.to_vec(),
        }),
        Format::Csv => {
            let mut out = assets(std::slice::from_ref(asset), Format::Csv);
            out.push_str(&interfaces(ifaces, Format::Csv));
            out.push_str(&capacity(cap, Format::Csv));
            out.push_str(&filesystems(disks, Format::Csv));
            out.push_str(&services(svcs, Format::Csv));
            out.push_str(&running_services(running, Format::Csv));
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
            out.push_str(&capacity(cap, Format::Table));
            out.push('\n');
            out.push_str(&filesystems(disks, Format::Table));
            out.push('\n');
            out.push_str(&services(svcs, Format::Table));
            out.push('\n');
            out.push_str(&running_services(running, Format::Table));
            out
        }
    }
}

/// Render the dependency graph (edge list) with readable asset labels.
///
/// `assets` supplies hostname/IP labels; edges whose endpoints are missing
/// from the inventory fall back to raw asset ids.
pub fn dependencies(edges: &[Dependency], assets: &[Asset], format: Format) -> String {
    let label = |id: &str| asset_label(assets, id);
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
                return "No dependencies recorded yet.\nRun host-level collection \
(--collector ssh / --collector windows / --collector winrm) or `orbyn deps add`.\n"
                    .to_string();
            }
            let mut table = table(&[
                "Source",
                "->",
                "Target",
                "Via",
                "Evidence",
                "Confidence",
                "Confirmed",
            ]);
            for d in edges {
                table.add_row(vec![
                    Cell::new(label(&d.source_asset_id)),
                    Cell::new("->"),
                    Cell::new(label(&d.target_asset_id)),
                    Cell::new(edge_via(d)),
                    Cell::new(&d.evidence_source),
                    Cell::new(format!("{:.0}%", d.confidence * 100.0)),
                    Cell::new(if d.confirmed { "yes" } else { "no" }),
                ]);
            }
            table.to_string()
        }
    }
}

/// Render the dependency graph as a Mermaid flowchart.
///
/// Confirmed edges render solid; observed-but-unconfirmed edges render
/// dotted so guesses look like guesses.
pub fn mermaid(edges: &[Dependency], assets: &[Asset]) -> String {
    let mut out = String::from("graph TD\n");
    if edges.is_empty() {
        return out;
    }
    let label = |id: &str| mermaid_label(assets, id);
    for d in edges {
        let arrow = if d.confirmed {
            format!("-->|{}|", mermaid_edge_label(d))
        } else {
            format!("-. {}.->", mermaid_edge_label(d))
        };
        out.push_str(&format!(
            "  {}[\"{}\"] {} {}[\"{}\"]\n",
            mermaid_node_id(&d.source_asset_id),
            label(&d.source_asset_id),
            arrow,
            mermaid_node_id(&d.target_asset_id),
            label(&d.target_asset_id),
        ));
    }
    out
}

/// Render the active connections observed on an asset.
pub fn connections(conns: &[Connection], format: Format) -> String {
    match format {
        Format::Json => json(conns),
        Format::Csv => {
            let mut out =
                String::from("asset_id,proto,local_ip,local_port,remote_ip,remote_port,process\n");
            for c in conns {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    csv(&c.asset_id),
                    csv(&c.proto),
                    csv(&c.local_ip.map(|ip| ip.to_string()).unwrap_or_default()),
                    c.local_port.map(|p| p.to_string()).unwrap_or_default(),
                    c.remote_ip,
                    c.remote_port,
                    csv(&c.process.clone().unwrap_or_default()),
                ));
            }
            out
        }
        Format::Table => {
            if conns.is_empty() {
                return "No active connections observed for this asset.\n".to_string();
            }
            let mut table = table(&["Local", "Remote", "Proto", "Process"]);
            for c in conns {
                table.add_row(vec![
                    Cell::new(match c.local_ip {
                        Some(ip) => format!(
                            "{ip}:{}",
                            c.local_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".into())
                        ),
                        None => "-".into(),
                    }),
                    Cell::new(format!("{}:{}", c.remote_ip, c.remote_port)),
                    Cell::new(&c.proto),
                    Cell::new(c.process.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            table.to_string()
        }
    }
}

fn asset_label(assets: &[Asset], id: &str) -> String {
    match assets.iter().find(|a| a.id == id) {
        Some(asset) => match &asset.hostname {
            Some(host) => format!("{host} ({})", asset.ip),
            None => asset.ip.to_string(),
        },
        None => id.to_string(),
    }
}

fn edge_via(d: &Dependency) -> String {
    if d.evidence_kind() == EvidenceKind::Dns {
        "dns".into()
    } else {
        format!("{}/{}", d.proto, d.port)
    }
}

fn mermaid_edge_label(d: &Dependency) -> String {
    if d.evidence_kind() == EvidenceKind::Dns {
        format!("dns {:.0}%", d.confidence * 100.0)
    } else {
        format!("{}/{} {:.0}%", d.proto, d.port, d.confidence * 100.0)
    }
}

fn mermaid_node_id(id: &str) -> String {
    let readable: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded = id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("n_{readable}_{encoded}")
}

fn mermaid_label(assets: &[Asset], id: &str) -> String {
    // Escape characters Mermaid treats specially inside quoted labels.
    asset_label(assets, id).replace(['"', '[', ']', '\n', '\r'], "_")
}

/// Render an assessment report.
pub fn report(report: &AssessmentReport, format: Format) -> String {
    match format {
        Format::Json => json(report),
        Format::Csv => {
            let mut out =
                String::from("#summary\nrules_version,assets_assessed,overall_score,complexity\n");
            out.push_str(&format!(
                "{},{},{},{}\n",
                report.rules_version,
                report.assets_assessed,
                report.overall_score,
                report.complexity
            ));
            out.push_str("\n#findings\nrule_id,severity,asset_id,message,evidence\n");
            for f in &report.findings {
                out.push_str(&format!(
                    "{},{},{},{},{}\n",
                    csv(&f.rule_id),
                    severity_str(f.severity),
                    csv(&f.asset_id.clone().unwrap_or_default()),
                    csv(&f.message),
                    csv(&f.evidence.join("; ")),
                ));
            }
            out.push_str("\n#asset_scores\nasset_id,score,findings\n");
            for s in &report.asset_scores {
                out.push_str(&format!("{},{},{}\n", s.asset_id, s.score, s.findings));
            }
            out.push_str("\n#application_groups\ngroup_id,assets,edge_count\n");
            for g in &report.application_groups {
                out.push_str(&format!(
                    "{},{},{}\n",
                    g.id,
                    csv(&g.asset_ids.join(";")),
                    g.edge_count
                ));
            }
            out
        }
        Format::Table => {
            let mut out = String::new();
            out.push_str("Migration assessment\n");
            out.push_str(&format!(
                "Rules version : {}\nAssets assessed : {}\nOverall score  : {}/100 ({})\n",
                report.rules_version,
                report.assets_assessed,
                report.overall_score,
                report.complexity
            ));

            out.push_str("\nFindings:\n");
            if report.findings.is_empty() {
                out.push_str("  (no findings)\n");
            } else {
                let mut t = table(&["Rule", "Severity", "Asset", "Finding"]);
                for f in &report.findings {
                    t.add_row(vec![
                        Cell::new(&f.rule_id),
                        Cell::new(severity_str(f.severity)),
                        Cell::new(f.asset_id.clone().unwrap_or_else(|| "-".into())),
                        Cell::new(&f.message),
                    ]);
                }
                out.push_str(&t.to_string());
            }

            out.push_str("\nAsset complexity:\n");
            let mut t = table(&["Asset", "Score", "Findings"]);
            for s in &report.asset_scores {
                t.add_row(vec![
                    Cell::new(&s.asset_id),
                    Cell::new(s.score),
                    Cell::new(s.findings),
                ]);
            }
            out.push_str(&t.to_string());

            out.push_str("\nApplication groups:\n");
            if report.application_groups.is_empty() {
                out.push_str("  (none detected; run dependency collection)\n");
            } else {
                let mut t = table(&["Group", "Assets", "Edges"]);
                for g in &report.application_groups {
                    t.add_row(vec![
                        Cell::new(&g.id),
                        Cell::new(g.asset_ids.join(", ")),
                        Cell::new(g.edge_count),
                    ]);
                }
                out.push_str(&t.to_string());
            }
            out
        }
    }
}

/// Render the assessment rule catalog (`orbyn assess --rules`).
pub fn rules_catalog(rules: &[Rule], version: &str) -> String {
    let mut out = format!("Rules version: {version}\n\n");
    let mut t = table(&["Rule", "Description"]);
    for rule in rules {
        t.add_row(vec![Cell::new(rule.id), Cell::new(rule.description)]);
    }
    out.push_str(&t.to_string());
    out
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
    pub capacity: Option<Capacity>,
    pub filesystems: Vec<Filesystem>,
    pub running_services: Vec<RunningService>,
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

fn audit_duration_label(event: &AuditEvent) -> String {
    match event.finished_at {
        Some(finished) => {
            let secs = (finished - event.started_at).num_seconds().max(0);
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

/// Human-readable size from kilobytes (e.g. `49.9G`, `12.0M`, `512K`).
fn human_kb(kb: u64) -> String {
    if kb >= 10 * 1024 * 1024 {
        format!("{:.1}G", kb as f64 / 1024.0 / 1024.0)
    } else if kb >= 10 * 1024 {
        format!("{:.1}M", kb as f64 / 1024.0)
    } else {
        format!("{kb}K")
    }
}

/// Quote a CSV field, neutralizing spreadsheet formula injection (audit
/// OY-04): a field starting with `=`, `+`, `-`, `@`, tab or CR is prefixed
/// with `'` so Excel/LibreOffice treat it as text. Device-controlled values
/// (SNMP `sysName`, PTR hostnames, imported tags) reach the export, and a
/// hostile `=HYPERLINK(...)` or DDE payload must never execute.
fn csv(field: &str) -> String {
    let field = if field.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{field}")
    } else {
        field.to_string()
    };
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::WindowComparison;
    use chrono::{Duration, Utc};

    fn asset(id: &str, ip: &str, hostname: Option<&str>) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
            device_class: None,
            os_name: None,
            os_version: None,
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn dep(source: &str, target: &str, port: u16, confirmed: bool, evidence: &str) -> Dependency {
        Dependency {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port,
            evidence_source: evidence.into(),
            confidence: 0.9,
            confirmed,
        }
    }

    #[test]
    fn human_kb_boundaries() {
        assert_eq!(human_kb(512), "512K");
        assert_eq!(human_kb(10 * 1024), "10.0M");
        assert_eq!(human_kb(50 * 1024 * 1024), "50.0G");
        assert_eq!(human_kb(1024 * 1024 * 1024), "1024.0G");
    }

    /// A window with CPU/RAM only, as an importer that never queries swap
    /// would produce.
    fn stats_without_swap() -> WindowStats {
        WindowStats {
            sample_count: 24,
            window_start: None,
            window_end: None,
            span_hours: Some(184.0),
            cpu_avg_percent: Some(20.0),
            cpu_p95_percent: Some(25.0),
            cpu_p99_percent: Some(25.0),
            cpu_peak_percent: Some(25.0),
            ram_avg_mb: Some(2560.0),
            ram_p95_mb: Some(3072.0),
            ram_p99_mb: Some(3072.0),
            ram_peak_mb: Some(3072.0),
            swap_avg_mb: None,
            swap_p95_mb: None,
            swap_p99_mb: None,
            swap_peak_mb: None,
            confidence: SampleConfidence::High,
            comparison: None,
        }
    }

    #[test]
    fn metrics_table_hides_swap_when_there_are_no_swap_samples() {
        let out = metrics(Some(&stats_without_swap()), Format::Table);
        assert!(!out.contains("Swap used"), "{out}");
        assert!(!out.contains("Trend"), "{out}");
    }

    #[test]
    fn metrics_table_renders_swap_and_the_week_over_week_trend() {
        let mut stats = stats_without_swap();
        stats.swap_avg_mb = Some(512.0);
        stats.swap_p95_mb = Some(1024.0);
        stats.swap_p99_mb = Some(2048.0);
        stats.swap_peak_mb = Some(2048.0);
        stats.comparison = Some(WindowComparison {
            sub_window_hours: 168.0,
            prior_sample_count: 26,
            recent_sample_count: 22,
            prior_span_hours: Some(168.0),
            recent_span_hours: Some(168.0),
            cpu_p95_prior_percent: Some(10.0),
            cpu_p95_recent_percent: Some(40.0),
            ram_p95_prior_mb: Some(2048.0),
            ram_p95_recent_mb: Some(3072.0),
            swap_p95_prior_mb: None,
            swap_p95_recent_mb: Some(1024.0),
        });

        let out = metrics(Some(&stats), Format::Table);
        assert!(
            out.contains("Swap used  : avg 512 MB   p95 1.00 GiB"),
            "{out}"
        );
        assert!(
            out.contains("Trend      : last 168h vs the 168h before it (22 vs 26 samples)"),
            "{out}"
        );
        assert!(out.contains("CPU p95: p95 10.00% -> 40.00%"), "{out}");
        assert!(out.contains("RAM p95: p95 2.00 GiB -> 3.00 GiB"), "{out}");
        // A half that carries no swap data shows as "-", not as a silent
        // omission: "swap appeared this week" is the useful signal.
        assert!(out.contains("Swap p95: p95 - -> 1.00 GiB"), "{out}");
        // A metric with no data in either half gets no trend line at all.
        stats
            .comparison
            .as_mut()
            .expect("comparison")
            .swap_p95_recent_mb = None;
        let out = metrics(Some(&stats), Format::Table);
        assert!(!out.contains("Swap p95:"), "{out}");

        let csv = metrics(Some(&stats), Format::Csv);
        assert!(csv.contains("swap_used_mb,p95,1024"), "{csv}");
        assert!(csv.contains("cpu_usage_percent,prior_p95,10"), "{csv}");
        assert!(csv.contains("cpu_usage_percent,recent_p95,40"), "{csv}");
        assert!(csv.contains("comparison_sub_window_hours,,168"), "{csv}");
    }

    #[test]
    fn mermaid_sanitizes_node_ids_and_labels() {
        let assets = vec![asset("10-0-0-5", "10.0.0.5", Some("web-01"))];
        let edges = vec![dep(
            "10-0-0-5",
            "10-0-0-9",
            5432,
            true,
            "active-connections",
        )];
        let out = mermaid(&edges, &assets);
        assert!(out.starts_with("graph TD\n"));
        assert!(out.contains("n_10_0_0_5_"));
        assert!(!out.contains("10-0-0-5"));
        assert!(out.contains("web-01 (10.0.0.5)"));
    }

    #[test]
    fn mermaid_node_ids_do_not_collide_after_sanitizing() {
        let first = mermaid_node_id("10.0.0.1");
        let second = mermaid_node_id("10_0_0_1");
        assert_ne!(first, second);
    }

    #[test]
    fn mermaid_dotted_for_unconfirmed_solid_for_confirmed() {
        let assets = vec![asset("a", "10.0.0.1", None), asset("b", "10.0.0.2", None)];
        let confirmed = dep("a", "b", 443, true, "manual");
        let observed = dep("b", "a", 80, false, "active-connections");
        let out = mermaid(&[confirmed, observed], &assets);
        assert!(out.contains("-->|tcp/443"), "confirmed edge must be solid");
        assert!(out.contains("-. tcp/80"), "observed edge must be dotted");
    }

    #[test]
    fn mermaid_empty_graph_is_header_only() {
        assert_eq!(mermaid(&[], &[]), "graph TD\n");
    }

    #[test]
    fn dns_edges_render_as_dns_label() {
        let mut edge = dep("a", "b", 0, false, "dns");
        edge.proto = "dns".into();
        edge.port = 0;
        assert_eq!(edge_via(&edge), "dns");
        assert!(mermaid_edge_label(&edge).starts_with("dns "));
    }

    #[test]
    fn duration_label_running_and_finished() {
        let started = Utc::now();
        let running = DiscoveryJob {
            id: "j".into(),
            collector: "nmap".into(),
            targets: vec![],
            status: JobStatus::Running,
            started_at: started,
            finished_at: None,
            error: None,
            assets_found: None,
            services_found: None,
            filesystems_found: None,
            running_services_found: None,
            connections_found: None,
        };
        assert_eq!(duration_label(&running), "-");

        let finished = DiscoveryJob {
            finished_at: Some(started + Duration::seconds(65)),
            ..running.clone()
        };
        assert_eq!(duration_label(&finished), "1m 05s");

        let quick = DiscoveryJob {
            finished_at: Some(started + Duration::seconds(3)),
            ..running
        };
        assert_eq!(duration_label(&quick), "3s");
    }

    #[test]
    fn csv_quotes_fields_with_special_chars() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("has,comma"), "\"has,comma\"");
        assert_eq!(csv("has\"quote"), "\"has\"\"quote\"");
        assert_eq!(csv("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn csv_neutralizes_formula_injection() {
        assert_eq!(
            csv("=HYPERLINK(\"http://evil\",\"x\")"),
            "\"'=HYPERLINK(\"\"http://evil\"\",\"\"x\"\")\""
        );
        assert_eq!(csv("=cmd|'/c calc'!A1"), "'=cmd|'/c calc'!A1");
        assert_eq!(
            csv("+WEBSERVICE(\"http://evil\")"),
            "\"'+WEBSERVICE(\"\"http://evil\"\")\""
        );
        assert_eq!(csv("@evil"), "'@evil");
        assert_eq!(csv("-2+3|cmd"), "'-2+3|cmd");
        assert_eq!(csv("\ttab-led"), "'\ttab-led");
        // Neutralized fields still get quoted when they carry separators.
        assert_eq!(csv("=1,2"), "\"'=1,2\"");
        // Ordinary values are untouched.
        assert_eq!(csv("web-01"), "web-01");
        assert_eq!(csv("10.0.0.5"), "10.0.0.5");
        assert_eq!(csv("\revil"), "'\revil");
        assert_eq!(csv("|cmd"), "|cmd", "pipe alone is not a formula prefix");
    }

    #[test]
    fn mermaid_strips_quotes_brackets_and_newlines_from_labels() {
        let assets = vec![asset("a", "10.0.0.1", Some("\"]\n  x-->y[\""))];
        let edges = vec![dep("a", "b", 443, true, "manual")];
        let out = mermaid(&edges, &assets);
        assert!(
            !out.contains("x-->y["),
            "raw bracket must not survive: {out}"
        );
        assert_eq!(
            out.lines().count(),
            2,
            "newline in hostname must not split the graph: {out}"
        );
    }

    #[test]
    fn assets_table_reports_empty_state() {
        let out = assets(&[], Format::Table);
        assert!(out.contains("No assets discovered"));
    }

    #[test]
    fn capacity_empty_state() {
        assert!(capacity(None, Format::Table).contains("No capacity recorded"));
        // CSV renders only the header when no capacity
        let csv = capacity(None, Format::Csv);
        assert!(csv.starts_with("asset_id,cpu_model,"));
        assert_eq!(csv.lines().count(), 1);
    }

    #[test]
    fn capacity_renders_hypervisor() {
        let cap = crate::domain::Capacity {
            asset_id: "10-0-0-5".into(),
            cpu_model: Some("Xeon Gold 6138".into()),
            cpu_sockets: Some(1),
            cpu_cores: Some(4),
            cpu_threads: Some(8),
            ram_total_mb: Some(16001),
            hypervisor: Some("vmware".into()),
            collected_at: chrono::Utc::now(),
        };
        let table = capacity(Some(&cap), Format::Table);
        assert!(table.contains("Hypervisor : vmware"), "{table}");

        let bare = crate::domain::Capacity {
            hypervisor: None,
            ..cap.clone()
        };
        let table = capacity(Some(&bare), Format::Table);
        assert!(
            table.contains("Hypervisor : - (bare metal or undetected)"),
            "{table}"
        );

        let csv = capacity(Some(&cap), Format::Csv);
        assert!(csv.contains(",vmware,"), "{csv}");
    }

    #[test]
    fn dependencies_table_uses_hostname_labels() {
        let assets = vec![
            asset("a", "10.0.0.1", Some("web-01")),
            asset("b", "10.0.0.2", None),
        ];
        let out = dependencies(
            &[dep("a", "b", 5432, false, "active-connections")],
            &assets,
            Format::Table,
        );
        assert!(out.contains("web-01 (10.0.0.1)"));
        assert!(out.contains("10.0.0.2"));
        assert!(out.contains("no"), "unconfirmed edges show 'no'");
    }

    #[test]
    fn running_services_table_uses_service_header() {
        let services = vec![RunningService {
            asset_id: "a".into(),
            name: "nginx.service".into(),
            state: Some("running".into()),
            description: Some("web server".into()),
        }];
        let out = running_services(&services, Format::Table);
        assert!(
            out.contains("Service"),
            "header is 'Service', not 'Unit': {out}"
        );
        assert!(out.contains("nginx.service"));
    }
}
