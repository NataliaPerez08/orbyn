//! End-to-end cloud adapter tests: the Proxmox VE importer against a fake
//! `curl`. No network or real Proxmox cluster is required.

mod common;

#[cfg(unix)]
use common::*;

/// A fake `curl` that serves the Proxmox API endpoints the adapter calls.
///
/// It logs its stdin (the `Authorization` header) when `ORBYN_CURL_STDIN_LOG`
/// is set, so a test can prove the token reaches curl on stdin rather than in
/// argv.
#[cfg(unix)]
const FAKE_PROXMOX_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_CURL_STDIN_LOG" ]]; then
  cat >> "$ORBYN_CURL_STDIN_LOG"
fi
url="${@: -1}"
case "$url" in
  */cluster/status)
    cat <<'JSON'
{"data":[
  {"type":"cluster","name":"dc1","nodes":3},
  {"type":"node","name":"pve1","nodeid":0,"online":1,"ip":"10.0.0.10"},
  {"type":"node","name":"pve2","nodeid":1,"online":0,"ip":"10.0.0.11"},
  {"type":"node","name":"pve3","nodeid":2,"online":1}
]}
JSON
    ;;
  */cluster/resources?type=vm)
    cat <<'JSON'
{"data":[
  {"id":"qemu/100","type":"qemu","vmid":100,"node":"pve1","name":"web-01","status":"running","maxcpu":4,"maxmem":8589934592,"tags":"prod;web","pool":"app"},
  {"id":"lxc/200","type":"lxc","vmid":200,"node":"pve1","name":"ct-01","status":"running","maxcpu":2,"maxmem":2147483648,"tags":"prod"},
  {"id":"qemu/300","type":"qemu","vmid":300,"node":"pve1","name":"no-agent","status":"stopped","maxcpu":1,"maxmem":1073741824}
]}
JSON
    ;;
  */nodes/pve1/qemu/100/agent/network-get-interfaces)
    cat <<'JSON'
{"data":{"result":[
  {"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]},
  {"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:01","ip-addresses":[{"ip-address":"10.0.0.5","ip-address-type":"ipv4","prefix":24}]}
]}}
JSON
    ;;
  */nodes/pve1/lxc/200/interfaces)
    cat <<'JSON'
{"data":[
  {"name":"lo","hwaddr":"00:00:00:00:00:00","inet":"127.0.0.1/8"},
  {"name":"eth0","hwaddr":"aa:bb:cc:dd:ee:02","inet":"10.0.0.6/24"}
]}
JSON
    ;;
  */nodes)
    cat <<'JSON'
{"data":[
  {"node":"pve1","status":"online","maxcpu":16,"maxmem":68719476736},
  {"node":"pve2","status":"offline","maxcpu":8,"maxmem":34359738368}
]}
JSON
    ;;
  *)
    printf 'unexpected request: %s' "$url" >&2
    exit 22
    ;;
esac
printf '200'
"#;

#[cfg(unix)]
#[test]
fn proxmox_import_pulls_nodes_vms_and_containers() {
    let dir = TempDir::new("proxmox");
    let curl = fake_bin(&dir, "curl", FAKE_PROXMOX_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["proxmox", "import", "--url", "https://pve.example.com:8006"])
            .args(["--token", "root@pam!orbyn=supersecrettoken123"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 4 assets, 2 interfaces, 4 capacity rows from Proxmox"),
        "{out}"
    );
    assert!(out.contains("proxmox:root@pam"), "{out}");
    assert!(
        !out.contains("supersecrettoken123"),
        "the token must never be printed: {out}"
    );

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("web-01"), "{assets}");
    assert!(assets.contains("ct-01"), "{assets}");
    assert!(assets.contains("pve1"), "the node is imported: {assets}");
    assert!(
        assets.contains("pve2"),
        "an offline node with an IP is imported"
    );
    assert!(
        !assets.contains("no-agent"),
        "a guest without an IP is skipped: {assets}"
    );

    // Interface detail from the guest agent and the container API.
    let vm_ifaces = run_ok(orbyn(&dir).args(["interfaces", "web-01", "--format", "csv"]));
    assert!(vm_ifaces.contains("eth0"), "{vm_ifaces}");
    assert!(vm_ifaces.contains("aa:bb:cc:dd:ee:01"), "{vm_ifaces}");
    assert!(vm_ifaces.contains("10.0.0.5"), "{vm_ifaces}");

    let ct_ifaces = run_ok(orbyn(&dir).args(["interfaces", "ct-01", "--format", "csv"]));
    assert!(ct_ifaces.contains("eth0"), "{ct_ifaces}");
    assert!(ct_ifaces.contains("10.0.0.6"), "{ct_ifaces}");

    // Provenance tags land on the imported rows.
    let web = run_ok(orbyn(&dir).args(["asset", "web-01"]));
    assert!(web.contains("cloud:proxmox"), "{web}");
    assert!(web.contains("proxmox-vmid:100"), "{web}");

    // The job is recorded under the provider.
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("proxmox,succeeded"), "{jobs}");

    // The audit event records the import.
    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("proxmox.import"), "{audit}");
}

#[cfg(unix)]
#[test]
fn proxmox_token_from_stdin_reaches_curl() {
    let dir = TempDir::new("proxmox-stdin");
    let curl = fake_bin(&dir, "curl", FAKE_PROXMOX_CURL_SCRIPT);
    let stdin_log = dir.path().join("curl-stdin.log");

    let output = run_with_stdin(
        orbyn(&dir)
            .args(["proxmox", "import", "--url", "https://pve.example.com:8006"])
            .args(["--token", "-"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_CURL_STDIN_LOG", &stdin_log),
        "root@pam!orbyn=supersecrettoken123\n",
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
        !combined.contains("supersecrettoken123"),
        "stdin token must never be printed: {combined}"
    );
    let payload = std::fs::read_to_string(&stdin_log).expect("curl stdin log");
    assert!(
        payload.contains("Authorization: PVEAPIToken=root@pam!orbyn=supersecrettoken123"),
        "token must reach curl's stdin as a header: {payload}"
    );
}

/// A fake `curl` serving the AWS EC2 and STS query APIs. The requests are
/// signed by the adapter; this fake ignores the signature but logs stdin so a
/// test can assert the credential reached curl on stdin.
#[cfg(unix)]
const FAKE_AWS_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_CURL_STDIN_LOG" ]]; then
  cat >> "$ORBYN_CURL_STDIN_LOG"
fi
url="${@: -1}"
case "$url" in
  *Action=GetCallerIdentity*)
    cat <<'XML'
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/ops</Arn>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>
XML
    ;;
  *NextToken=page-2*)
    cat <<'XML'
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item><instancesSet>
      <item>
        <instanceId>i-222</instanceId>
        <instanceType>m5.large</instanceType>
        <instanceState><code>16</code><name>running</name></instanceState>
        <privateIpAddress>10.0.0.6</privateIpAddress>
        <tagSet><item><key>Name</key><value>db-01</value></item></tagSet>
        <networkInterfaceSet>
          <item>
            <networkInterfaceId>eni-bbb</networkInterfaceId>
            <privateIpAddress>10.0.0.6</privateIpAddress>
            <macAddress>0a:1b:2c:3d:4e:60</macAddress>
          </item>
        </networkInterfaceSet>
      </item>
    </instancesSet></item>
  </reservationSet>
</DescribeInstancesResponse>
XML
    ;;
  *Action=DescribeInstances*)
    cat <<'XML'
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item><instancesSet>
      <item>
        <instanceId>i-111</instanceId>
        <instanceType>t3.micro</instanceType>
        <instanceState><code>16</code><name>running</name></instanceState>
        <privateIpAddress>10.0.0.5</privateIpAddress>
        <privateDnsName>ip-10-0-0-5.eu-west-1.compute.internal</privateDnsName>
        <platform>windows</platform>
        <tagSet>
          <item><key>Name</key><value>web-01</value></item>
          <item><key>env</key><value>prod</value></item>
        </tagSet>
        <networkInterfaceSet>
          <item>
            <networkInterfaceId>eni-aaa</networkInterfaceId>
            <privateIpAddress>10.0.0.5</privateIpAddress>
            <macAddress>0a:1b:2c:3d:4e:5f</macAddress>
            <association><publicIp>203.0.113.5</publicIp></association>
          </item>
        </networkInterfaceSet>
      </item>
    </instancesSet></item>
  </reservationSet>
  <nextToken>page-2</nextToken>
</DescribeInstancesResponse>
XML
    ;;
  *)
    printf 'unexpected request: %s' "$url" >&2
    exit 22
    ;;
esac
printf '200'
"#;

#[cfg(unix)]
#[test]
fn aws_import_pulls_instances_and_paginates() {
    let dir = TempDir::new("aws");
    let curl = fake_bin(&dir, "curl", FAKE_AWS_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["aws", "import", "--region", "eu-west-1"])
            .args(["--access-key", "AKIDEXAMPLE"])
            .args(["--secret-key", "supersecretkey123"])
            .args(["--endpoint-url", "https://ec2.test.local"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 2 assets, 2 interfaces from AWS"),
        "{out}"
    );
    assert!(out.contains("aws:123456789012:eu-west-1"), "{out}");
    assert!(
        !out.contains("supersecretkey123"),
        "the secret key must never be printed: {out}"
    );

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("web-01"), "{assets}");
    assert!(
        assets.contains("db-01"),
        "the second page is followed: {assets}"
    );

    let ifaces = run_ok(orbyn(&dir).args(["interfaces", "web-01", "--format", "csv"]));
    assert!(ifaces.contains("eni-aaa"), "{ifaces}");
    assert!(ifaces.contains("0a:1b:2c:3d:4e:5f"), "{ifaces}");
    assert!(ifaces.contains("10.0.0.5"), "{ifaces}");

    // Provenance tags from the provider and the STS account.
    let web = run_ok(orbyn(&dir).args(["asset", "web-01"]));
    assert!(web.contains("cloud:aws"), "{web}");
    assert!(web.contains("cloud-account:123456789012"), "{web}");
    assert!(web.contains("cloud-region:eu-west-1"), "{web}");
    assert!(web.contains("Name=web-01"), "{web}");
    assert!(web.contains("aws-type:t3.micro"), "{web}");

    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("aws,succeeded"), "{jobs}");

    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("aws.import"), "{audit}");
}

#[cfg(unix)]
#[test]
fn aws_secret_key_from_stdin_reaches_curl_signed() {
    let dir = TempDir::new("aws-stdin");
    let curl = fake_bin(&dir, "curl", FAKE_AWS_CURL_SCRIPT);
    let stdin_log = dir.path().join("curl-stdin.log");

    let output = run_with_stdin(
        orbyn(&dir)
            .args(["aws", "import", "--region", "eu-west-1"])
            .args(["--access-key", "AKIDEXAMPLE"])
            .args(["--secret-key", "-"])
            .args(["--session-token", "sessiontoken123"])
            .args(["--endpoint-url", "https://ec2.test.local"])
            .env("ORBYN_CURL_BIN", &curl)
            .env("ORBYN_CURL_STDIN_LOG", &stdin_log),
        "supersecretkey123\n",
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
        !combined.contains("supersecretkey123"),
        "the secret key must never be printed: {combined}"
    );

    let payload = std::fs::read_to_string(&stdin_log).expect("curl stdin log");
    assert!(
        payload.contains("Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "a SigV4 Authorization header must reach curl's stdin: {payload}"
    );
    assert!(
        payload.contains("x-amz-security-token: sessiontoken123"),
        "the session token must reach curl's stdin: {payload}"
    );
}

#[cfg(unix)]
#[test]
fn aws_import_requires_credentials() {
    let dir = TempDir::new("aws-no-creds");
    let curl = fake_bin(&dir, "curl", FAKE_AWS_CURL_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args(["aws", "import", "--region", "eu-west-1"])
            .args(["--endpoint-url", "https://ec2.test.local"])
            .env("ORBYN_CURL_BIN", &curl)
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY"),
    );
    assert!(out.contains("AWS access key id is required"), "{out}");
}

#[cfg(unix)]
#[test]
fn proxmox_import_requires_a_token() {
    let dir = TempDir::new("proxmox-no-token");
    let curl = fake_bin(&dir, "curl", FAKE_PROXMOX_CURL_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args(["proxmox", "import", "--url", "https://pve.example.com:8006"])
            .env("ORBYN_CURL_BIN", &curl)
            .env_remove("ORBYN_PROXMOX_TOKEN"),
    );
    assert!(out.contains("Proxmox API token is required"), "{out}");
}
