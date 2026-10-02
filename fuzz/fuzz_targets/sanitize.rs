#![no_main]

use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use orbyn::domain::{Asset, Criticality, Dependency};
use orbyn::integrations::ansible::{render_ansible_inventory, GroupBy};
use orbyn::integrations::terraform::{render_import_blocks, render_terraform};
use orbyn::output::{assets, mermaid, Format};

fuzz_target!(|data: &[u8]| {
    let hostname = String::from_utf8_lossy(data).into_owned();
    let asset = Asset {
        id: "10-0-0-1".into(),
        ip: "10.0.0.1".parse().unwrap(),
        hostname: Some(hostname),
        device_class: Some("server".into()),
        os_name: None,
        os_version: None,
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: Some(Criticality::High),
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };

    let assets_slice = [asset];
    let _ = assets(&assets_slice, Format::Csv);
    let _ = render_ansible_inventory(&assets_slice, GroupBy::DeviceClass);
    let _ = render_terraform(&assets_slice);
    let _ = render_import_blocks(&assets_slice, "aws_instance");

    let edge = Dependency {
        source_asset_id: "10-0-0-1".into(),
        target_asset_id: "10-0-0-1".into(),
        proto: "tcp".into(),
        port: 443,
        evidence_source: "manual".into(),
        confidence: 1.0,
        confirmed: true,
    };
    let graph = mermaid(&[edge], &assets_slice);
    assert_eq!(graph.lines().count(), 2);
});
