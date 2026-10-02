//! End-to-end test for `orbyn sku-match`: the CLI matches a vCPU/RAM baseline
//! to candidate provider instance types in every output format.

mod common;

#[cfg(unix)]
use common::*;

#[cfg(unix)]
#[test]
fn sku_match_lists_smallest_fit_and_all_formats() {
    let dir = TempDir::new("sku");

    let table = run_ok(orbyn(&dir).args([
        "sku-match",
        "--provider",
        "aws",
        "--cores",
        "4",
        "--ram-mb",
        "16384",
    ]));
    assert!(table.contains("t3.xlarge"), "{table}");
    assert!(table.contains("smallest fit first"), "{table}");

    let json = run_ok(orbyn(&dir).args([
        "sku-match",
        "--provider",
        "gcp",
        "--cores",
        "2",
        "--ram-mb",
        "8192",
        "--format",
        "json",
    ]));
    let value: serde_json::Value = serde_json::from_str(&json).expect("json output");
    assert_eq!(value[0]["name"], "e2-standard-2");

    let csv = run_ok(orbyn(&dir).args([
        "sku-match",
        "--provider",
        "azure",
        "--cores",
        "2",
        "--ram-mb",
        "8192",
        "--format",
        "csv",
    ]));
    assert!(csv.contains("Standard_B2ms"), "{csv}");
    assert!(csv.starts_with("provider,name,vcpu,ram_mib"), "{csv}");

    // A baseline beyond the curated catalog fails with a clear message.
    let none = run_ok(orbyn(&dir).args([
        "sku-match",
        "--provider",
        "aws",
        "--cores",
        "64",
        "--ram-mb",
        "262144",
    ]));
    assert!(none.contains("no aws instance type"), "{none}");
}
