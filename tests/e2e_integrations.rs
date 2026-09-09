//! End-to-end integration tests: Ansible/Terraform exporters and the NetBox
//! source-of-truth importer (against a fake `curl`).

mod common;

use common::*;

/// A fake `curl` that dispatches NetBox endpoints to fixtures.
const FAKE_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    */api/dcim/devices/*)
      cat <<'JSON'
{"count":2,"next":null,"results":[
  {"name":"rtr-core-1","role":{"name":"Router","slug":"router"},"tenant":{"name":"neteng"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[{"name":"core"},{"name":"env:prod"}]},
  {"name":"no-ip-device","role":{"name":"Switch","slug":"switch"},"primary_ip":null,"tags":[]}
]}
JSON
      ;;
    */api/virtualization/virtual-machines/*)
      cat <<'JSON'
{"count":1,"next":null,"results":[
  {"name":"vm-web-01","role":{"name":"VM","slug":"vm"},"tenant":{"name":"appteam"},"primary_ip":{"address":"10.0.0.5/24"},"tags":[{"name":"staging"}]}
]}
JSON
      ;;
  esac
done
"#;

const THREE_ASSETS_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.1","hostname":"web-01","device_class":"server","environment":"prod","owner":"platform","criticality":"high","tags":["core","api"]},
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod"},
  {"ip":"10.0.0.3","hostname":"cache-01","device_class":"server","environment":"staging"}
]}"#;

#[cfg(unix)]
#[test]
fn export_ansible_inventory() {
    let dir = TempDir::new("ansible-export");
    import_json(&dir, THREE_ASSETS_JSON);

    let out = run_ok(orbyn(&dir).args(["export", "--format", "ansible"]));
    assert!(out.contains("[server]"));
    assert!(out.contains("web-01 ansible_host=10.0.0.1"));
    assert!(out.contains("orbyn_environment=prod"));
    assert!(out.contains("orbyn_owner=platform"));
    assert!(out.contains("orbyn_criticality=high"));
    assert!(out.contains("orbyn_tags=core,api"));

    // group by environment
    let out =
        run_ok(orbyn(&dir).args(["export", "--format", "ansible", "--group-by", "environment"]));
    assert!(out.contains("[prod]"));
    assert!(out.contains("[staging]"));
}

#[cfg(unix)]
#[test]
fn export_terraform_locals() {
    let dir = TempDir::new("terraform-export");
    import_json(&dir, THREE_ASSETS_JSON);

    let out = run_ok(orbyn(&dir).args(["export", "--format", "terraform"]));
    assert!(out.contains("locals {"));
    assert!(out.contains("orbyn_inventory = {"));
    assert!(out.contains("\"web-01\" = {"));
    assert!(out.contains("ip           = \"10.0.0.1\""));
    assert!(out.contains("tags         = [\"core\", \"api\"]"));
}

#[cfg(unix)]
#[test]
fn netbox_import_pulls_devices_and_vms() {
    let dir = TempDir::new("netbox");
    let curl = fake_bin(&dir, "curl", FAKE_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(out.contains("Imported 2 assets from NetBox"));

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("rtr-core-1"));
    assert!(assets.contains("vm-web-01"));
    assert!(
        !assets.contains("no-ip-device"),
        "device without IP is skipped"
    );

    // annotations mapped from NetBox (role -> device_class, tenant -> owner, env tag)
    let router = run_ok(orbyn(&dir).args(["asset", "rtr-core-1"]));
    assert!(router.contains("router"));
    assert!(router.contains("neteng"));
    assert!(router.contains("prod"));

    let vm = run_ok(orbyn(&dir).args(["asset", "vm-web-01"]));
    assert!(vm.contains("vm"));
    assert!(vm.contains("appteam"));
    assert!(vm.contains("staging"));

    // job recorded under the netbox collector
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("netbox,succeeded"));
}

#[cfg(unix)]
#[test]
fn netbox_token_never_leaks_into_output() {
    let dir = TempDir::new("netbox-token");
    let curl = fake_bin(&dir, "curl", FAKE_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .args(["--token", "supersecrettoken123"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        !out.contains("supersecrettoken123"),
        "token must never be logged or printed"
    );
}

#[cfg(unix)]
#[test]
fn netbox_bad_url_fails_cleanly() {
    let dir = TempDir::new("netbox-bad");
    let curl = dir.path().join("curl");
    std::fs::write(&curl, "#!/usr/bin/env bash\nexit 22\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = run_fail(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(out.contains("curl exited"), "got: {out}");
}
