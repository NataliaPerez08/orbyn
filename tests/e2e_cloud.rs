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
  */nodes/pve1/qemu/100/config)
    cat <<'JSON'
{"data":{"ostype":"l26","cores":2,"sockets":1,"memory":"2048","net0":"virtio=BC:24:11:B6:97:E4,bridge=vmbr1","ipconfig0":"gw=10.0.0.1,ip=10.0.0.5/24"}}
JSON
    ;;
  */nodes/pve1/qemu/100/agent/get-osinfo)
    cat <<'JSON'
{"data":{"result":{"name":"Ubuntu","pretty-name":"Ubuntu 24.04.5 LTS","version-id":"24.04"}}}
JSON
    ;;
  */nodes/pve1/qemu/100/agent/get-fsinfo)
    cat <<'JSON'
{"data":{"result":[
  {"name":"sda1","mountpoint":"/","type":"ext4","total-bytes":23826268160,"used-bytes":4626456576,"disk":[{"dev":"/dev/sda1"}]}
]}}
JSON
    ;;
  */nodes/pve1/lxc/200/config)
    cat <<'JSON'
{"data":{"ostype":"debian","cores":1,"memory":512,"rootfs":"local-lvm:vm-200-disk-0,size=8G","net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=10.0.0.6/24"}}
JSON
    ;;
  */nodes/pve1/qemu/300/config)
    cat <<'JSON'
{"data":{"ostype":"l26","cores":1,"sockets":1,"memory":"1024","net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0"}}
JSON
    ;;
  */nodes/pve1/storage)
    cat <<'JSON'
{"data":[
  {"storage":"local","type":"dir","active":1,"total":100861726720,"used":63545442304,"avail":32145547264},
  {"storage":"local-lvm","type":"lvmthin","active":1,"total":373553102848,"used":133171681165,"avail":240381421683}
]}
JSON
    ;;
  */nodes/pve2/storage)
    printf '{"data":[]}'
    ;;
  */nodes/pve1/qemu/300/agent/*)
    printf '{"data":null}'
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
        out.contains(
            "Imported 4 assets, 2 interfaces, 4 capacity rows, 4 filesystems from Proxmox"
        ),
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

    // Disk usage from the guest agent, the container rootfs and node datastores.
    let web_disks = run_ok(orbyn(&dir).args(["disks", "web-01", "--format", "csv"]));
    assert!(web_disks.contains("/dev/sda1"), "{web_disks}");

    let ct_disks = run_ok(orbyn(&dir).args(["disks", "ct-01", "--format", "csv"]));
    assert!(ct_disks.contains("local-lvm:vm-200-disk-0"), "{ct_disks}");

    let node_disks = run_ok(orbyn(&dir).args(["disks", "pve1", "--format", "csv"]));
    assert!(node_disks.contains("local-lvm"), "{node_disks}");

    // Provenance tags land on the imported rows, with OS identity from the agent.
    let web = run_ok(orbyn(&dir).args(["asset", "web-01"]));
    assert!(web.contains("cloud:proxmox"), "{web}");
    assert!(web.contains("proxmox-vmid:100"), "{web}");
    assert!(web.contains("Ubuntu 24.04.5 LTS"), "{web}");

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

#[cfg(unix)]
#[test]
fn openstack_import_uses_normalized_cloud_pipeline() {
    let dir = TempDir::new("openstack");
    let curl = fake_bin(
        &dir,
        "curl",
        r##"#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  */flavors/detail*) printf '{"flavors":[{"id":"small","vcpus":2,"ram":2048}]}' ;;
  */servers/detail*) printf '{"servers":[{"id":"srv-1","name":"web","status":"ACTIVE","addresses":{"net":[{"addr":"10.20.0.5","OS-EXT-IPS:type":"fixed","OS-EXT-IPS-MAC:mac_addr":"aa:bb:cc:dd:ee:ff"}]},"flavor":{"id":"small"}}]}' ;;
  */volumes/detail*) printf '{"volumes":[{"id":"vol-1","size":10,"attachments":[{"server_id":"srv-1","device":"/dev/vdb"}]}]}' ;;
  *) printf '{"value":[]}' ;;
esac
printf '200'
"##,
    );
    let out = run_ok_combined(
        orbyn(&dir)
            .args([
                "openstack",
                "import",
                "--url",
                "http://cloud.test/v2.1/project",
            ])
            .args(["--token", "test-token", "--project", "project-1"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 1 assets, 1 interfaces, 1 capacity rows, 1 filesystems"),
        "{out}"
    );
    assert!(!out.contains("test-token"), "token must be redacted: {out}");
}

#[cfg(unix)]
#[test]
fn gcp_import_uses_compute_inventory() {
    let dir = TempDir::new("gcp");
    let curl = fake_bin(
        &dir,
        "curl",
        r##"#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  */aggregated/instances*) printf '{"items":{"zones/eu":{"instances":[{"name":"web","selfLink":"instance/web","zone":"zones/eu","machineType":"machineTypes/e2","networkInterfaces":[{"name":"nic0","networkIP":"10.30.0.5","macAddress":"aa:bb:cc:dd:ee:01"}],"labels":{"env":"test"}}]}}}' ;;
  */aggregated/disks*) printf '{"items":{"zones/eu":{"disks":[{"name":"boot","selfLink":"disk/boot","sizeGb":10,"users":["instance/web"]}]}}}' ;;
  */machineTypes/*) printf '{"guestCpus":2,"memoryMb":4096}' ;;
  *) printf '{}' ;;
esac
printf '200'
"##,
    );
    let out = run_ok_combined(
        orbyn(&dir)
            .args([
                "gcp",
                "import",
                "--project",
                "project-1",
                "--endpoint-url",
                "http://gcp.test/compute/v1",
            ])
            .args(["--token", "test-token"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 1 assets, 1 interfaces, 1 capacity rows, 1 filesystems"),
        "{out}"
    );
    assert!(!out.contains("test-token"), "token must be redacted: {out}");
}

#[cfg(unix)]
#[test]
fn azure_import_uses_arm_inventory() {
    let dir = TempDir::new("azure");
    let curl = fake_bin(
        &dir,
        "curl",
        r##"#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  */virtualMachines?*) printf '{"value":[{"id":"/vm/web","name":"web","location":"east","tags":{"env":"test"},"properties":{"hardwareProfile":{"vmSize":"small"},"storageProfile":{"osDisk":{"osType":"Linux"}},"networkProfile":{"networkInterfaces":[{"id":"/nic/web"}]}}}]}' ;;
  */networkInterfaces?*) printf '{"value":[{"id":"/nic/web","name":"eth0","properties":{"macAddress":"AA-BB-CC-DD-EE-02","ipConfigurations":[{"name":"ipconfig1","privateIPAddress":"10.40.0.5"}]}}]}' ;;
  */disks?*) printf '{"value":[{"id":"/disk/web","managedBy":"/vm/web","properties":{"diskSizeGB":20,"osType":"Linux"},"sku":{"name":"Premium_LRS"}}]}' ;;
  */virtualNetworks?*) printf '{"value":[{"id":"/vnet/main","name":"main","properties":{"addressSpace":{"addressPrefixes":["10.40.0.0/24"]},"subnets":[{"name":"app","properties":{"addressPrefix":"10.40.0.0/25"}}]}}]}' ;;
  */vmSizes?*) printf '{"value":[{"name":"small","numberOfCores":2,"memoryInMB":4096}]}' ;;
  *) printf '{"value":[]}' ;;
esac
printf '200'
"##,
    );
    let out = run_ok_combined(
        orbyn(&dir)
            .args([
                "azure",
                "import",
                "--subscription-id",
                "sub-1",
                "--endpoint-url",
                "http://arm.test",
            ])
            .args(["--token", "test-token"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains("Imported 3 assets, 1 interfaces, 1 capacity rows, 1 filesystems"),
        "{out}"
    );
    assert!(!out.contains("test-token"), "token must be redacted: {out}");
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
  *Action=DescribeVolumes*)
    cat <<'XML'
<DescribeVolumesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <volumeSet>
    <item>
      <volumeId>vol-111</volumeId>
      <size>100</size>
      <volumeType>gp3</volumeType>
      <attachmentSet>
        <item><volumeId>vol-111</volumeId><instanceId>i-111</instanceId><device>/dev/xvdf</device><state>attached</state></item>
      </attachmentSet>
    </item>
    <item>
      <volumeId>vol-orphan</volumeId>
      <size>8</size>
      <volumeType>gp2</volumeType>
      <attachmentSet/>
    </item>
  </volumeSet>
</DescribeVolumesResponse>
XML
    ;;
  *Action=DescribeVpcs*)
    cat <<'XML'
<DescribeVpcsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <vpcSet>
    <item>
      <vpcId>vpc-111</vpcId>
      <cidrBlock>10.0.0.0/16</cidrBlock>
      <isDefault>true</isDefault>
      <tagSet><item><key>Name</key><value>main-vpc</value></item></tagSet>
    </item>
  </vpcSet>
</DescribeVpcsResponse>
XML
    ;;
  *Action=DescribeSubnets*)
    cat <<'XML'
<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <subnetSet>
    <item>
      <subnetId>subnet-111</subnetId>
      <vpcId>vpc-111</vpcId>
      <cidrBlock>10.0.1.0/24</cidrBlock>
      <availabilityZone>eu-west-1a</availabilityZone>
      <availableIpAddressCount>251</availableIpAddressCount>
      <tagSet><item><key>Name</key><value>app-subnet</value></item></tagSet>
    </item>
  </subnetSet>
</DescribeSubnetsResponse>
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
        out.contains("Imported 4 assets, 2 interfaces, 1 filesystems from AWS"),
        "{out}"
    );
    assert!(out.contains("aws:123456789012:eu-west-1"), "{out}");
    assert!(
        out.contains("Skipped 1 resource(s)"),
        "the detached volume is reported: {out}"
    );
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
    assert!(
        assets.contains("main-vpc") && assets.contains("app-subnet"),
        "VPCs and subnets become assets: {assets}"
    );

    // EBS volumes become filesystems on their attached instance.
    let vols = run_ok(orbyn(&dir).args(["disks", "web-01", "--format", "csv"]));
    assert!(vols.contains("vol-111"), "{vols}");
    assert!(vols.contains("/dev/xvdf"), "{vols}");

    let vpc = run_ok(orbyn(&dir).args(["asset", "main-vpc"]));
    assert!(vpc.contains("aws-vpc:vpc-111"), "{vpc}");
    assert!(vpc.contains("aws-cidr:10.0.0.0/16"), "{vpc}");

    let subnet = run_ok(orbyn(&dir).args(["asset", "app-subnet"]));
    assert!(subnet.contains("aws-subnet:subnet-111"), "{subnet}");
    assert!(subnet.contains("aws-cidr:10.0.1.0/24"), "{subnet}");
    assert!(subnet.contains("aws-az:eu-west-1a"), "{subnet}");

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

/// A fake `curl` serving the Huawei Cloud ECS and IAM APIs the adapter calls.
/// The requests are signed by the adapter; this fake ignores the signature but
/// logs stdin so a test can assert the AK/SK reached curl on stdin.
#[cfg(unix)]
const FAKE_HUAWEI_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_CURL_STDIN_LOG" ]]; then
  cat >> "$ORBYN_CURL_STDIN_LOG"
fi
url="${@: -1}"
if [[ "$url" == *"/v2.1/proj-1/flavors/detail"* ]]; then
    cat <<'JSON'
{"flavors":[
  {"id":"s3.small.1","name":"s3.small.1","vcpus":1,"ram":2048},
  {"id":"s3.medium.2","name":"s3.medium.2","vcpus":2,"ram":4096}
]}
JSON
elif [[ "$url" == *"/v2/proj-1/cloudvolumes/detail"* ]]; then
    cat <<'JSON'
{"volumes":[
  {"id":"vol-a","size":40,"volume_type":"SSD","attachments":[
    {"server_id":"srv-a","device":"/dev/vdb","id":"vol-a"}]},
  {"id":"vol-orphan","size":8,"volume_type":"SATA","attachments":[]}
],
"volumes_links":[]}
JSON
elif [[ "$url" == *"/v1/proj-1/vpcs"* ]]; then
    cat <<'JSON'
{"vpcs":[
  {"id":"vpc-a","name":"vpc-main","cidr":"192.168.0.0/16","status":"ACTIVE"}
]}
JSON
elif [[ "$url" == *"/v1/proj-1/subnets"* ]]; then
    cat <<'JSON'
{"subnets":[
  {"id":"subnet-a","name":"sub-main","cidr":"192.168.1.0/24",
   "vpc_id":"vpc-a","availability_zone":"cn-north-4a","status":"ACTIVE"},
  {"id":"subnet-b","name":"sub-overlap","cidr":"192.168.0.0/24",
   "vpc_id":"vpc-a","availability_zone":"cn-north-4a","status":"ACTIVE"}
]}
JSON
elif [[ "$url" == *"offset=100"* ]]; then
    cat <<'JSON'
{"servers":[
  {"id":"srv-c","name":"cache-01","status":"SHUTOFF","flavor":{"id":"s3.small.1","name":"s3.small.1"},"addresses":{}}
]}
JSON
elif [[ "$url" == *"/v2.1/proj-1/servers/detail"* ]]; then
    cat <<'JSON'
{"servers":[
  {"id":"srv-a","name":"web-01","status":"ACTIVE","flavor":{"id":"s3.small.1","name":"s3.small.1"},
   "metadata":{"os_type":"Linux"},"OS-EXT-AZ:availability_zone":"cn-north-4a",
   "addresses":{"vpc-a":[
     {"addr":"192.168.0.5","OS-EXT-IPS:type":"fixed","OS-EXT-IPS-MAC:mac_addr":"fa:16:3e:aa:bb:01","OS-EXT-IPS:port_id":"port-aaa"},
     {"addr":"203.0.113.5","OS-EXT-IPS:type":"floating"}
   ]}},
  {"id":"srv-b","name":"db-01","status":"ACTIVE","flavor":{"id":"s3.medium.2","name":"s3.medium.2"},
   "addresses":{"vpc-a":[
     {"addr":"192.168.0.6","OS-EXT-IPS:type":"fixed","OS-EXT-IPS-MAC:mac_addr":"fa:16:3e:aa:bb:02","OS-EXT-IPS:port_id":"port-bbb"}
   ]}}
],
"servers_links":[{"rel":"next","href":"https://ecs.test.local/v2.1/proj-1/servers/detail?limit=100&offset=100"}]}
JSON
else
    printf 'unexpected request: %s' "$url" >&2
    exit 22
fi
printf '200'
"#;

#[cfg(unix)]
#[test]
fn huawei_import_pulls_instances_and_paginates() {
    let dir = TempDir::new("huawei");
    let curl = fake_bin(&dir, "curl", FAKE_HUAWEI_CURL_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["huawei", "import", "--region", "cn-north-4"])
            .args(["--access-key", "AKTEST"])
            .args(["--secret-key", "supersecretkey123"])
            .args(["--project-id", "proj-1"])
            .args(["--endpoint-url", "https://ecs.test.local"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    assert!(
        out.contains(
            "Imported 5 assets, 3 interfaces, 2 capacity rows, 1 filesystems from Huawei Cloud \
             (huawei:proj-1:cn-north-4)"
        ),
        "{out}"
    );
    assert!(
        out.contains("Skipped 2 resource(s)"),
        "a detached volume is reported: {out}"
    );
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
    assert!(
        !assets.contains("cache-01"),
        "a server without an IP is skipped: {assets}"
    );
    assert!(
        assets.contains("vpc-main") && assets.contains("sub-main"),
        "VPCs and subnets become assets: {assets}"
    );
    // A subnet that shares the VPC's network address coexists on the next
    // free address instead of being dropped.
    let overlap = run_ok(orbyn(&dir).args(["asset", "sub-overlap"]));
    assert!(overlap.contains("192.168.0.1"), "{overlap}");
    assert!(overlap.contains("huawei-netaddr:192.168.0.0"), "{overlap}");

    // EVS volumes become filesystems on their attached server.
    let vols = run_ok(orbyn(&dir).args(["disks", "web-01", "--format", "csv"]));
    assert!(vols.contains("vol-a"), "{vols}");
    assert!(vols.contains("/dev/vdb"), "{vols}");

    let vpc = run_ok(orbyn(&dir).args(["asset", "vpc-main"]));
    assert!(vpc.contains("huawei-vpc:vpc-a"), "{vpc}");
    assert!(vpc.contains("huawei-cidr:192.168.0.0/16"), "{vpc}");

    let subnet = run_ok(orbyn(&dir).args(["asset", "sub-main"]));
    assert!(subnet.contains("huawei-subnet:subnet-a"), "{subnet}");
    assert!(subnet.contains("huawei-cidr:192.168.1.0/24"), "{subnet}");
    assert!(subnet.contains("huawei-az:cn-north-4a"), "{subnet}");

    // Interface detail from the address list.
    let ifaces = run_ok(orbyn(&dir).args(["interfaces", "web-01", "--format", "csv"]));
    assert!(ifaces.contains("port-aaa"), "{ifaces}");
    assert!(ifaces.contains("fa:16:3e:aa:bb:01"), "{ifaces}");
    assert!(ifaces.contains("192.168.0.5"), "{ifaces}");

    // CPU/RAM capacity from the flavor catalogue.
    let capacity = run_ok(orbyn(&dir).args(["capacity", "web-01", "--format", "csv"]));
    assert!(capacity.contains("2048"), "{capacity}");

    // Provenance tags from the provider, project and region.
    let web = run_ok(orbyn(&dir).args(["asset", "web-01"]));
    assert!(web.contains("cloud:huawei"), "{web}");
    assert!(web.contains("cloud-account:proj-1"), "{web}");
    assert!(web.contains("cloud-region:cn-north-4"), "{web}");
    assert!(web.contains("huawei-server:srv-a"), "{web}");
    assert!(web.contains("Linux"), "{web}");

    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("huawei,succeeded"), "{jobs}");

    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("huawei.import"), "{audit}");
}

#[cfg(unix)]
#[test]
fn huawei_secret_key_from_stdin_reaches_curl_signed() {
    let dir = TempDir::new("huawei-stdin");
    let curl = fake_bin(&dir, "curl", FAKE_HUAWEI_CURL_SCRIPT);
    let stdin_log = dir.path().join("curl-stdin.log");

    let output = run_with_stdin(
        orbyn(&dir)
            .args(["huawei", "import", "--region", "cn-north-4"])
            .args(["--access-key", "AKTEST"])
            .args(["--secret-key", "-"])
            .args(["--project-id", "proj-1"])
            .args(["--endpoint-url", "https://ecs.test.local"])
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
        payload.contains(
            "Authorization: SDK-HMAC-SHA256 Access=AKTEST, SignedHeaders=host;x-sdk-date"
        ),
        "an SDK-HMAC-SHA256 Authorization header must reach curl's stdin: {payload}"
    );
}

#[cfg(unix)]
#[test]
fn huawei_import_requires_credentials() {
    let dir = TempDir::new("huawei-no-creds");
    let curl = fake_bin(&dir, "curl", FAKE_HUAWEI_CURL_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args(["huawei", "import", "--region", "cn-north-4"])
            .args(["--endpoint-url", "https://ecs.test.local"])
            .env("ORBYN_CURL_BIN", &curl)
            .env_remove("HUAWEICLOUD_SDK_AK")
            .env_remove("HUAWEICLOUD_SDK_SK"),
    );
    assert!(out.contains("Huawei Cloud access key is required"), "{out}");
}
