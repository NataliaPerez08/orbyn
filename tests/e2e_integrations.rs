//! End-to-end integration tests: Ansible/Terraform exporters and the NetBox
//! source-of-truth importer (against a fake `curl`).

mod common;

#[cfg(unix)]
use common::*;

/// A fake `curl` that dispatches NetBox endpoints to fixtures.
#[cfg(unix)]
const FAKE_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    */api/dcim/devices/*)
      cat <<'JSON'
{"count":3,"next":null,"results":[
  {"id":101,"name":"rtr-core-1","role":{"name":"Router","slug":"router"},"tenant":{"name":"neteng"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[{"name":"core"},{"name":"env:prod"}]},
  {"id":102,"name":"no-ip-device","role":{"name":"Switch","slug":"switch"},"primary_ip":null,"tags":[]},
  {"id":103,"name":null,"primary_ip":{"address":"10.0.0.7/24"},"tags":[]}
]}
JSON
      ;;
    */api/virtualization/virtual-machines/*)
      cat <<'JSON'
{"count":1,"next":null,"results":[
  {"id":201,"name":"vm-web-01","role":{"name":"VM","slug":"vm"},"tenant":{"name":"appteam"},"primary_ip":{"address":"10.0.0.5/24"},"tags":[{"name":"staging"}]}
]}
JSON
      ;;
    */api/dcim/interfaces/*)
      cat <<'JSON'
{"count":3,"next":null,"results":[
  {"id":301,"device":{"id":101},"name":"eth0","mac_address":"AA:BB:CC:DD:EE:01","mtu":1500,"enabled":true},
  {"id":302,"device":{"id":102},"name":"eth0","mac_address":null,"mtu":null,"enabled":true},
  {"id":303,"device":{"id":103},"name":"eth1","mac_address":null,"mtu":null,"enabled":true}
]}
JSON
      ;;
    */api/virtualization/interfaces/*)
      cat <<'JSON'
{"count":1,"next":null,"results":[
  {"id":401,"virtual_machine":{"id":201},"name":"ens3","mac_address":null,"mtu":null,"enabled":true}
]}
JSON
      ;;
    */api/ipam/ip-addresses/*)
      cat <<'JSON'
{"count":3,"next":null,"results":[
  {"address":"10.0.0.1/24","dns_name":"rtr-core-1.dns.example.com","assigned_object_type":"dcim.interface","assigned_object_id":301},
  {"address":"10.0.0.5/24","dns_name":"","assigned_object_type":"virtualization.vminterface","assigned_object_id":401},
  {"address":"10.0.0.7/24","dns_name":"sw-1.dns.example.com","assigned_object_type":"dcim.interface","assigned_object_id":303}
]}
JSON
      ;;
  esac
done
# The status curl appends with -w: Orbyn reads it to tell a good response
# from a rate limit or a server error. One trailer per invocation, after the
# body of the matched endpoint.
printf '200'
"#;

#[cfg(unix)]
const PAGINATED_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  *"/api/dcim/devices/"*"page=2"*)
    cat <<'JSON'
{"count":2,"next":null,"results":[
  {"id":2,"name":"rtr-edge-2","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.2/24"},"tags":[]}
]}
JSON
    ;;
  *"/api/dcim/devices/"*)
    cat <<'JSON'
{"count":2,"next":"https://netbox.example.com/api/dcim/devices/?limit=100&page=2","results":[
  {"id":1,"name":"rtr-edge-1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}
]}
JSON
    ;;
  *"/api/virtualization/virtual-machines/"*)
    printf '%s\n' '{"count":0,"next":null,"results":[]}'
    ;;
  *"/api/dcim/interfaces/"*|*"/api/virtualization/interfaces/"*|*"/api/ipam/ip-addresses/"*)
    printf '%s\n' '{"count":0,"next":null,"results":[]}'
    ;;
  *)
    printf 'malformed request'
    exit 22
    ;;
esac
printf '200'
"#;

#[cfg(unix)]
const THREE_ASSETS_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.1","hostname":"web-01","device_class":"server","os_name":"Ubuntu 22.04","os_version":"5.15.0","environment":"prod","owner":"platform","criticality":"high","tags":["core","api"]},
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
fn export_ansible_yaml_inventory() {
    let dir = TempDir::new("ansible-yaml-export");
    import_json(&dir, THREE_ASSETS_JSON);

    let out = run_ok(orbyn(&dir).args(["export", "--format", "ansible-yaml"]));
    assert!(out.contains("all:\n  children:\n"), "{out}");
    assert!(out.contains("    server:\n      hosts:\n"), "{out}");
    assert!(out.contains("        web-01:\n"), "{out}");
    assert!(out.contains("          ansible_host: 10.0.0.1\n"), "{out}");
    assert!(out.contains("          orbyn_environment: prod\n"), "{out}");
    assert!(out.contains("          orbyn_criticality: high\n"), "{out}");
    assert!(
        out.contains("          orbyn_tags:\n            - core\n            - api\n"),
        "{out}"
    );

    let out = run_ok(orbyn(&dir).args([
        "export",
        "--format",
        "ansible-yaml",
        "--group-by",
        "environment",
    ]));
    assert!(
        out.contains("    prod:\n") && out.contains("    staging:\n"),
        "{out}"
    );
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
fn export_terraform_includes_full_metadata() {
    let dir = TempDir::new("terraform-metadata");
    import_json(&dir, THREE_ASSETS_JSON);

    let out = run_ok(orbyn(&dir).args(["export", "--format", "terraform"]));
    assert!(out.contains("os_name      = \"Ubuntu 22.04\""), "{out}");
    assert!(out.contains("os_version   = \"5.15.0\""), "{out}");
    assert!(out.contains("first_seen   = \""), "{out}");
    assert!(out.contains("last_seen    = \""), "{out}");
}

#[cfg(unix)]
#[test]
fn export_terraform_import_blocks() {
    let dir = TempDir::new("terraform-import-blocks");
    import_json(&dir, THREE_ASSETS_JSON);

    let out = run_ok(orbyn(&dir).args([
        "export",
        "--format",
        "terraform",
        "--tf-import",
        "aws_instance",
    ]));
    assert!(
        out.contains("import {\n  to = aws_instance.web-01\n"),
        "{out}"
    );
    assert!(out.contains("id = \"10.0.0.1\" # TODO"), "{out}");
    assert_eq!(out.matches("import {").count(), 3, "one block per asset");
}

#[cfg(unix)]
#[test]
fn export_tf_import_requires_terraform_format() {
    let dir = TempDir::new("terraform-import-format");
    import_json(&dir, THREE_ASSETS_JSON);

    let out =
        run_fail(orbyn(&dir).args(["export", "--format", "json", "--tf-import", "aws_instance"]));
    assert!(
        out.contains("--tf-import requires --format terraform"),
        "{out}"
    );
}

#[cfg(unix)]
#[test]
fn netbox_import_pulls_devices_vms_interfaces_and_ips() {
    let dir = TempDir::new("netbox");
    let curl = fake_bin(&dir, "curl", FAKE_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 3 assets, 3 interfaces from NetBox"),
        "{out}"
    );

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("rtr-core-1"));
    assert!(assets.contains("vm-web-01"));
    assert!(
        !assets.contains("no-ip-device"),
        "device without IP is skipped"
    );
    assert!(
        assets.contains("sw-1.dns.example.com"),
        "dns_name fills the hostname of an unnamed device: {assets}"
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

    // interfaces: MACs from dcim/interfaces, IPs from ipam/ip-addresses
    let ifaces = run_ok(orbyn(&dir).args(["interfaces", "rtr-core-1", "--format", "csv"]));
    assert!(ifaces.contains("eth0"), "{ifaces}");
    assert!(
        ifaces.contains("aa:bb:cc:dd:ee:01"),
        "MAC normalized: {ifaces}"
    );
    assert!(ifaces.contains("1500"), "{ifaces}");

    let vm_ifaces = run_ok(orbyn(&dir).args(["interfaces", "vm-web-01", "--format", "csv"]));
    assert!(vm_ifaces.contains("ens3"), "{vm_ifaces}");
    assert!(vm_ifaces.contains("10.0.0.5"), "{vm_ifaces}");

    // job recorded under the netbox collector
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("netbox,succeeded"));
}

#[cfg(unix)]
#[test]
fn netbox_import_follows_pagination() {
    let dir = TempDir::new("netbox-pagination");
    let curl = fake_bin(&dir, "curl", PAGINATED_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(out.contains("Imported 2 assets from NetBox"), "{out}");
    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("rtr-edge-1"));
    assert!(assets.contains("rtr-edge-2"));
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
fn netbox_token_from_stdin_reaches_curl() {
    let dir = TempDir::new("netbox-stdin");
    // A fake curl that logs its stdin payload (the Authorization header)
    // and serves a minimal one-device inventory.
    let script = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_CURL_STDIN_LOG" ]]; then
  cat >> "$ORBYN_CURL_STDIN_LOG"
fi
url="${@: -1}"
case "$url" in
  */api/dcim/devices/*)
    printf '%s\n' '{"count":1,"next":null,"results":[{"id":1,"name":"rtr-stdin-1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}]}'
    ;;
  *)
    printf '%s\n' '{"count":0,"next":null,"results":[]}'
    ;;
esac
printf '200'
"#;
    let curl = fake_bin(&dir, "curl", script);
    let stdin_log = dir.path().join("curl-stdin.log");

    let output = run_with_stdin(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .args(["--token", "-"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_CURL_STDIN_LOG", &stdin_log),
        "supersecrettoken123\n",
    );
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Imported 1 assets from NetBox"),
        "import must succeed: {combined}"
    );
    assert!(
        !combined.contains("supersecrettoken123"),
        "stdin token must never be printed: {combined}"
    );
    let payload = std::fs::read_to_string(&stdin_log).expect("curl stdin log");
    assert!(
        payload.contains("Authorization: Token supersecrettoken123"),
        "stdin token must reach curl's stdin: {payload}"
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

/// A fake `curl` whose first devices page points `next` at a host that
/// passes a naive prefix check (`netbox.example.com.evil`) but is a
/// different origin, logging every invocation.
#[cfg(unix)]
const HOSTILE_NEXT_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_CURL_ARGS_LOG" ]]; then
  printf '%s\n' "$*" >> "$ORBYN_CURL_ARGS_LOG"
fi
url="${@: -1}"
case "$url" in
  *"/api/dcim/devices/"*)
    cat <<'JSON'
{"count":1,"next":"https://netbox.example.com.evil/api/dcim/devices/?limit=100&page=2","results":[
  {"id":1,"name":"rtr-edge-1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}
]}
JSON
    ;;
  *)
    printf '%s\n' '{"count":0,"next":null,"results":[]}'
    ;;
esac
printf '200'
"#;

#[cfg(unix)]
#[test]
fn netbox_import_rejects_hostile_pagination_url() {
    let dir = TempDir::new("netbox-hostile-next");
    let curl = fake_bin(&dir, "curl", HOSTILE_NEXT_CURL_SCRIPT);
    let log = dir.path().join("curl-args.log");

    let out = run_fail(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .args(["--token", "supersecrettoken123"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_CURL_ARGS_LOG", &log),
    );
    assert!(out.contains("unexpected URL"), "got: {out}");
    assert!(
        !out.contains("supersecrettoken123"),
        "token must never be printed"
    );

    // The hostile next URL must never have been requested: exactly one
    // curl invocation (the first devices page).
    let log = std::fs::read_to_string(&log).expect("curl args log");
    assert_eq!(log.lines().count(), 1, "exactly one request: {log}");
    assert!(!log.contains(".evil"), "hostile URL must not be fetched");
}

/// A fake `curl` that answers the first `ORBYN_RETRY_FAILURES` calls with a
/// 503 and then serves the NetBox fixtures, counting every invocation in
/// `$ORBYN_RETRY_COUNTER`. It proves the client replays a transient failure
/// and then succeeds.
#[cfg(unix)]
const RETRY_THEN_OK_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
counter="${ORBYN_RETRY_COUNTER}"
n=0
if [[ -f "$counter" ]]; then n="$(cat "$counter")"; fi
n=$((n + 1))
printf '%s' "$n" > "$counter"
if [[ "$n" -le "${ORBYN_RETRY_FAILURES:-2}" ]]; then
  printf 'the NetBox API is warming up'
  printf '503'
  exit 0
fi
for a in "$@"; do
  case "$a" in
    */api/dcim/devices/*)
      cat <<'JSON'
{"count":1,"next":null,"results":[
  {"id":101,"name":"rtr-core-1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}
]}
JSON
      ;;
    *"/api/"*)
      printf '%s\n' '{"count":0,"next":null,"results":[]}'
      ;;
  esac
done
printf '200'
"#;

/// A fake `curl` that rejects every call with a 401 and counts invocations:
/// a rejected credential is permanent, so the client must not replay it.
#[cfg(unix)]
const UNAUTHORIZED_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
counter="${ORBYN_RETRY_COUNTER}"
n=0
if [[ -f "$counter" ]]; then n="$(cat "$counter")"; fi
n=$((n + 1))
printf '%s' "$n" > "$counter"
printf 'invalid token'
printf '401'
"#;

#[cfg(unix)]
#[test]
fn netbox_retries_a_server_error_then_succeeds() {
    let dir = TempDir::new("netbox-retry");
    let curl = fake_bin(&dir, "curl", RETRY_THEN_OK_CURL_SCRIPT);
    let counter = dir.path().join("curl-calls");

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_RETRY_COUNTER", &counter),
    );
    assert!(out.contains("Imported 1 assets from NetBox"), "got: {out}");

    let calls: usize = std::fs::read_to_string(&counter)
        .expect("counter")
        .trim()
        .parse()
        .expect("numeric counter");
    // 2 rejected attempts + 1 that succeeded + the four empty endpoints.
    assert_eq!(
        calls,
        3 + 4,
        "the 503 must be replayed, then succeed: {calls}"
    );
}

#[cfg(unix)]
#[test]
fn netbox_does_not_replay_a_rejected_credential() {
    let dir = TempDir::new("netbox-401");
    let curl = fake_bin(&dir, "curl", UNAUTHORIZED_CURL_SCRIPT);
    let counter = dir.path().join("curl-calls");

    let out = run_fail(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_RETRY_COUNTER", &counter),
    );
    assert!(
        out.contains("HTTP 401"),
        "the status must be reported: {out}"
    );
    assert!(
        out.contains("failed: NetBox returned HTTP 401"),
        "a permanent failure must not claim retries: {out}"
    );

    let calls: usize = std::fs::read_to_string(&counter)
        .expect("counter")
        .trim()
        .parse()
        .expect("numeric counter");
    assert_eq!(calls, 1, "a 401 must be attempted exactly once: {calls}");
}

#[cfg(unix)]
#[test]
fn netbox_reports_an_exhausted_retry_budget() {
    let dir = TempDir::new("netbox-retry-exhausted");
    let curl = fake_bin(&dir, "curl", RETRY_THEN_OK_CURL_SCRIPT);
    let counter = dir.path().join("curl-calls");

    // More failures than the retry budget allows: the import fails, and the
    // message says how many attempts were spent.
    let out = run_fail(
        orbyn(&dir)
            .args(["netbox", "import", "--url", "https://netbox.example.com"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_RETRY_COUNTER", &counter)
            .env("ORBYN_RETRY_FAILURES", "99"),
    );
    assert!(out.contains("failed after 3 attempts"), "got: {out}");

    let calls: usize = std::fs::read_to_string(&counter)
        .expect("counter")
        .trim()
        .parse()
        .expect("numeric counter");
    assert_eq!(calls, 3, "attempts stay bounded: {calls}");
}

#[cfg(unix)]
#[test]
fn netbox_import_rejects_credential_bearing_base_url() {
    let dir = TempDir::new("netbox-userinfo-url");
    let curl = fake_bin(&dir, "curl", FAKE_CURL_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args([
                "netbox",
                "import",
                "--url",
                "https://user:pass@netbox.example.com",
            ])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("invalid NetBox URL"),
        "userinfo in the base URL must be rejected: {out}"
    );
}
