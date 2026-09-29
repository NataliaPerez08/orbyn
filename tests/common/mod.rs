//! Shared helpers for end-to-end tests.
//!
//! E2E tests run the real `orbyn` binary (`CARGO_BIN_EXE_orbyn`) against a
//! throwaway SQLite database, with fake `nmap`/`snmpwalk`/`ssh` executables
//! generated on the fly so no network or real tools are required.
//!
//! The fakes are shell scripts, so the whole module is Unix-only and
//! compiles empty on other platforms; `cargo test` (unit + store smoke
//! tests) still runs on Windows CI.
#![cfg(unix)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// A self-cleaning temporary directory.
pub struct TempDir {
    path: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("orbyn-e2e-{name}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn db(&self) -> PathBuf {
        self.path.join("orbyn.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A command pre-pointed at the `orbyn` binary and this test's database.
pub fn orbyn(dir: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_orbyn"));
    cmd.arg("--db").arg(dir.db());
    cmd
}

/// Run a command and panic with full output if it fails. Returns stdout.
pub fn run_ok(cmd: &mut Command) -> String {
    let output = cmd.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Run a command and return combined stdout+stderr on success.
///
/// Use for commands whose useful diagnostics go to stderr (discovery
/// summaries, `deps add/confirm/remove` acknowledgements).
pub fn run_ok_combined(cmd: &mut Command) -> String {
    let output = cmd.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

/// Run a command and assert it fails. Returns combined output for inspection.
pub fn run_fail(cmd: &mut Command) -> String {
    let output = cmd.output().expect("run command");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

/// Run a command with `stdin_data` piped to its stdin and return the raw
/// `Output` (stdout/stderr piped like `Command::output`). The stdin pipe
/// closes after the write so the child sees EOF.
pub fn run_with_stdin(cmd: &mut Command, stdin_data: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn command");
    {
        let pipe = child.stdin.as_mut().expect("stdin pipe");
        pipe.write_all(stdin_data.as_bytes()).expect("write stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait with output")
}

/// Write an executable fake tool (a bash script) and return its path.
#[cfg(unix)]
pub fn fake_bin(dir: &TempDir, name: &str, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.path().join(name);
    std::fs::write(&path, script).expect("write fake bin");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod fake");
    path
}

/// A fake `nmap` that always emits the same XML for any target.
pub const FAKE_NMAP_SCRIPT: &str = r#"#!/usr/bin/env bash
cat <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sV" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="syn-ack"/>
<address addr="10.0.0.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel"/>
<hostnames><hostname name="server-a.example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="3306"><state state="filtered"/></port>
</ports>
<os><osmatch name="Linux 5.15.0-94-generic" accuracy="98"/></os>
<times srtt="1000" rttvar="100" to="100000"/>
</host>
</nmaprun>
XML
"#;

/// A fake `snmpwalk` dispatching on the walked OID (system vs ifTable).
pub const FAKE_SNMPWALK_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_SNMP_ARGS_LOG" ]]; then
  printf '%s\n' "$@" >> "$ORBYN_SNMP_ARGS_LOG"
fi
if [[ -n "$ORBYN_SNMP_ENV_LOG" ]]; then
  env > "$ORBYN_SNMP_ENV_LOG"
fi
if [[ -n "$ORBYN_SNMP_CONF_LOG" && -n "$SNMPCONFPATH" ]]; then
  cat "$SNMPCONFPATH/snmp.conf" >> "$ORBYN_SNMP_CONF_LOG"
fi
oid="${@: -1}"
if [[ "$oid" == "1.3.6.1.2.1.1" ]]; then
cat <<'OUT'
.1.3.6.1.2.1.1.1.0 = STRING: Cisco IOS Software, IOSv
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.1230
.1.3.6.1.2.1.1.5.0 = STRING: switch-core-1
OUT
else
cat <<'OUT'
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.2.1 = STRING: GigabitEthernet0/0
.1.3.6.1.2.1.2.2.1.4.1 = INTEGER: 1500
.1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 00 1C 58 9A BC 34
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.2.2 = STRING: GigabitEthernet0/1
.1.3.6.1.2.1.2.2.1.6.2 = STRING:
.1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2
OUT
fi
"#;

/// A fake `ssh` emitting a Linux host probe with active connections.
pub const FAKE_SSH_LINUX_SCRIPT: &str = r#"#!/usr/bin/env bash
cat <<'OUT'
###os
NAME="Ubuntu"
PRETTY_NAME="Ubuntu 22.04.4 LTS"
###kernel
5.15.0-94-generic
###hostname
web-01
###cpu
Architecture:        x86_64
CPU(s):              8
Thread(s) per core:  2
Core(s) per socket:  4
Socket(s):           1
Model name:          Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz
###mem
MemTotal:       16384532 kB
###disk
Filesystem     Type   1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4       52425716  12345678  37380844      25% /
/dev/sdb1      xfs       209612800  98765432 104947368      49% /data
###svc
nginx.service                 loaded active running A high performance web server and reverse proxy
sshd.service                  loaded active running OpenBSD Secure Shell server
###conn
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB  0      0      10.0.0.5:54322        10.0.0.2:5432            users:(("postgres",pid=977,fd=6))
ESTAB  0      0      10.0.0.5:49200        10.0.0.9:6379            users:(("redis-cli",pid=980,fd=4))
ESTAB  0      0      10.0.0.5:49201        203.0.113.9:443          users:(("curl",pid=981,fd=5))
ESTAB  0      0      127.0.0.1:49202       127.0.0.1:8080
###virt
vmware
VMware, Inc.
VMware Virtual Platform
###metric
62.50|16384532|2655988|8388604|4194304|2.10,2.00,1.90
80.00|16384532|2097152|8388604|3145728|2.50,2.20,2.00
35.00|16384532|7340032|8388604|6291456|1.10,1.40,1.60
OUT
"#;

/// A fake `ssh` emitting a Windows (PowerShell CSV) host probe.
pub const FAKE_SSH_WINDOWS_SCRIPT: &str = r#"#!/usr/bin/env bash
cat <<'OUT'
###os
"Caption","Version","BuildNumber","CSName"
"Microsoft Windows Server 2022 Standard","10.0","20348","WIN-APP01"
###cpu
"Name","NumberOfCores","NumberOfLogicalProcessors"
"Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz","12","24"
###ram
17179869184
###disk
"DeviceID","FileSystem","VolumeName","Size","FreeSpace"
"C:","NTFS","System","107374182400","53687091200"
"D:","NTFS","Data","214748364800","107374182400"
###svc
"Name","DisplayName"
"W3SVC","World Wide Web Publishing Service"
"MSSQLSERVER","SQL Server (MSSQLSERVER)"
###conn
"LocalAddress","LocalPort","RemoteAddress","RemotePort"
"10.0.0.20","49222","10.0.0.5","443"
"10.0.0.20","49223","10.0.0.9","5432"
###virt
"Manufacturer","Model"
"Microsoft Corporation","Virtual Machine"
###metric
45.5|16777216|8388608|512
12.0|16777216|12582912|512
75.0|16777216|4194304|512
OUT
"#;

/// A small JSON inventory (used to pre-seed the DB before host collection).
pub const INVENTORY_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod","criticality":"critical"},
  {"ip":"10.0.0.9","hostname":"cache-01","device_class":"server","environment":"prod"}
]}"#;

/// Write a string to a file inside the test directory and return its path.
pub fn write_file(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write file");
    path
}

/// Import a JSON inventory through the CLI.
pub fn import_json(dir: &TempDir, json: &str) -> String {
    let file = dir.path().join("inventory.json");
    std::fs::write(&file, json).expect("write inventory");
    run_ok(
        orbyn(dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    )
}
