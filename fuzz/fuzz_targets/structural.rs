#![no_main]

use arbitrary::Arbitrary;
use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use orbyn::domain::{Asset, Criticality, Dependency};
use orbyn::integrations::ansible::{render_ansible_inventory, render_ansible_yaml, GroupBy};
use orbyn::integrations::terraform::{render_import_blocks, render_terraform};
use orbyn::output::{assets, mermaid, Format};

#[derive(Arbitrary, Debug)]
struct HostileAsset {
    id: String,
    ip: String,
    hostname: Option<String>,
    device_class: Option<String>,
    environment: Option<String>,
    owner: Option<String>,
    tags: Vec<String>,
}

fuzz_target!(|input: HostileAsset| {
    let Ok(ip) = input.ip.parse() else {
        return;
    };
    let asset = Asset {
        id: if input.id.is_empty() {
            "10-0-0-1".into()
        } else {
            input.id
        },
        ip,
        hostname: input.hostname,
        device_class: input.device_class,
        os_name: None,
        os_version: None,
        sys_descr: None,
        environment: input.environment,
        owner: input.owner,
        criticality: Some(Criticality::High),
        tags: input.tags,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let slice = [asset];
    let _ = assets(&slice, Format::Csv);
    let _ = render_ansible_inventory(&slice, GroupBy::DeviceClass);
    let _ = render_ansible_yaml(&slice, GroupBy::DeviceClass);
    let _ = render_terraform(&slice);
    let _ = render_import_blocks(&slice, "aws_instance");
    let edge = Dependency {
        source_asset_id: "10-0-0-1".into(),
        target_asset_id: "10-0-0-1".into(),
        proto: "tcp".into(),
        port: 443,
        evidence_source: "manual".into(),
        confidence: 1.0,
        confirmed: true,
    };
    assert_eq!(mermaid(&[edge], &slice).lines().count(), 2);
});
