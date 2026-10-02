//! Generate a deterministic representative inventory for the performance
//! benchmarks (`scripts/bench.sh`).
//!
//! Mirrors `tests/common::representative_inventory` (test-only code, not
//! importable from an example) so the benchmark input is byte-identical to the
//! inventory the scale tests use.
//!
//! Usage: `cargo run --release --example bench_inventory -- <assets>`

const INTERFACES_PER_ASSET: usize = 2;
const SERVICES_PER_ASSET: usize = 4;

fn main() {
    let assets: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .expect("usage: bench_inventory <assets>");
    print!("{}", inventory(assets));
}

fn inventory(assets: usize) -> String {
    const CLASSES: [&str; 4] = ["server", "network", "storage", "virtual-machine"];
    const OSES: [(&str, &str); 3] = [
        ("Ubuntu 22.04.4 LTS", "5.15.0-94-generic"),
        ("RHEL 8.9", "4.18.0-513.9.1.el8_9.x86_64"),
        ("Windows Server 2022 Standard", "10.0.20348"),
    ];

    let mut rows = Vec::with_capacity(assets);
    let mut interfaces = Vec::with_capacity(assets * INTERFACES_PER_ASSET);
    let mut services = Vec::with_capacity(assets * SERVICES_PER_ASSET);
    for i in 0..assets {
        let third = i / 250;
        let ip = format!("10.{third}.{}.1", i % 250);
        let device_class = CLASSES[i % CLASSES.len()];
        let (os_name, os_version) = OSES[i % OSES.len()];
        rows.push(format!(
            r#"{{"ip":"{ip}","hostname":"host-{i:05}","device_class":"{device_class}","os_name":"{os_name}","os_version":"{os_version}","environment":"env-{}","owner":"team-{}","criticality":"{}","tags":["tag-{}","zone-{}"]}}"#,
            i % 4,
            i % 12,
            ["low", "medium", "high"][i % 3],
            i % 20,
            i % 5
        ));
        for n in 0..INTERFACES_PER_ASSET {
            interfaces.push(format!(
                r#"{{"asset_id":"{ip}","name":"eth{n}","mac":"02:00:00:{:02x}:{:02x}","ip":"{ip}"}}"#,
                i % 256,
                n
            ));
        }
        for (n, port) in [22u16, 443, 3306, 9090].into_iter().enumerate() {
            services.push(format!(
                r#"{{"asset_id":"{ip}","proto":"tcp","port":{port},"name":"svc-{n}","state":"open"}}"#
            ));
        }
    }
    format!(
        r#"{{"assets":[{}],"interfaces":[{}],"services":[{}]}}"#,
        rows.join(","),
        interfaces.join(","),
        services.join(",")
    )
}
