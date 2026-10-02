# Framework internals

The modules below have no CLI entry point of their own. They define the
contract every collector obeys, the heuristics that normalize raw output, and
how authentication is described without ever carrying a secret.

## The `Collector` trait

```rust
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>>;
}
```

Implementors must:

* **never modify target systems** (read-only by default);
* **pass targets as process arguments, never shell strings**;
* **return normalized `Observation`s** instead of writing to the database —
  persistence belongs to the store.

`Send + Sync` lets a discovery run fan targets out over a bounded worker pool.
`ScanTarget` is either `Ip(IpAddr)` or `Cidr(String)`, produced only by
target validation.

## Target validation

`validate_target(raw)` is the default-policy entry point;
`validate_target_with_policy(raw, allow_large_cidr)` takes the explicit
operator opt-in. Every `--target` passes through it before any collector
starts.

| Error | Message |
| --- | --- |
| `TooLarge` | `target '<x>' exceeds the maximum allowed scope` |
| `Invalid` | `target '<x>' is unresolvable or malformed` |
| `NotIpCidr` | `target '<x>' is not an IP address or CIDR expression` |

Rules:

* `MIN_IPV4_PREFIX = 16` (a `/16` covers a classic enterprise scope while
  stopping accidental internet-wide ranges); `MIN_IPV6_PREFIX = 48`.
* `0.0.0.0/0`, a `::` base, and any `/0` prefix are rejected **under any
  policy**.
* CIDR form requires a numeric, in-range prefix — `10.0.0.0/abc` is `Invalid`.
* Hostnames such as `example.com` are `NotIpCidr`: discovery targets are
  addresses, not names.
* Rejections append
  `pass --allow-large-cidr to override the default minimum prefix (IPv4 /16, IPv6 /48)`.

## `CpuFacts`

`{ model, sockets, cores, threads }` — the normalized shape produced from
`lscpu` / `/proc/cpuinfo` (Linux) or `Win32_Processor` (Windows) before it
becomes a capacity record.

## Credential profiles

```rust
pub struct CredentialProfile {
    pub username: String,          // empty = transport default (current user)
    pub port: u16,                 // 22 for ssh unless configured otherwise
    pub identity_file: Option<PathBuf>,  // a path, never a secret value
}
```

Orbyn **does not store credentials**. A profile describes *how* to
authenticate — an ssh-agent, or a reference to an identity file on disk — and
never carries secret material. The key itself is never read, copied or
logged.

* **SSH / Windows-over-SSH:** agent or key file only. Password
  authentication is intentionally unsupported — see
  [Security](../security.md#credentials).
* **WinRM:** the one exception. A password is accepted at the CLI level
  (`ORBYN_WINRM_PASSWORD` or `--winrm-password -`) and held in process memory
  for the run only.

## Device classification

`classify_device(os_name, mac_vendor, service_names, sysdescr) -> Option<String>`
— a **conservative** heuristic: unknown input yields `None`. Used by the
[Nmap](nmap.md) and [SNMP](snmp.md) collectors; the host probes set
`server` directly.

| Class | Evidence consulted, in order |
| --- | --- |
| `printer` | `sysDescr` keywords (`printer`, `laserjet`, `xerox`), or a `jetdirect`/`printer` service |
| `storage` | `sysDescr` keywords (`storage`, `netapp`, `emc`) |
| `security-appliance` | `sysDescr` keywords (`firewall`, `fortigate`), security vendors (Fortinet, Palo Alto, Check Point, SonicWall) |
| `network-device` | network vendors (Cisco, Juniper, Huawei, Arista, Extreme Networks, MikroTik, Alcatel, F5, Ruckus), word-boundary `ios` / `nx-os` / `iosv`, router/switch keywords |
| `server` | server OS names (linux, windows, freebsd, unix, ubuntu, debian, centos, rhel) **only if** services were also observed |

Word-boundary matching (`contains_word`) requires non-alphanumeric edges, so
`ios` never matches inside `bios` or `radios`.

## Hypervisor detection

`virt` normalizes virtualization evidence into a canonical vocabulary stored
on capacity rows and rendered by `orbyn capacity` / `orbyn asset`. `None`
means bare metal.

| Tier (Linux) | Source |
| --- | --- |
| 1 | `systemd-detect-virt` id |
| 2 | DMI: `/sys/class/dmi/id/{sys_vendor,product_name}` |
| 3 | The `hypervisor` CPU flag in `/proc/cpuinfo` → `unknown` |

Windows uses the joined `Win32_ComputerSystem` manufacturer and model text.

Vocabulary: `kvm`, `vmware`, `virtualbox`, `hyperv`, `xen`, `lxc`, `docker`,
`podman`, `systemd-nspawn`, `wsl`, `bhyve`, `bochs`, `uml`, `unknown`.

Notable mappings: QEMU, Amazon EC2, Google Compute Engine, DigitalOcean,
OpenStack and `qemu` DMI strings → `kvm`; Microsoft + "virtual machine" →
`hyperv` (Microsoft alone, e.g. a Surface, is **not** Hyper-V).

## Environment scrubbing

Before spawning `nmap`, `snmpwalk`, `ssh` or `curl`, Orbyn removes
`ORBYN_SNMP_COMMUNITY`, `ORBYN_NETBOX_TOKEN`, `ORBYN_WINRM_PASSWORD`,
`ORBYN_PROMETHEUS_TOKEN` and `ORBYN_DB` from the child's environment: a
hijacked binary must not be able to read the community string, an API token,
the WinRM password or the database URL password.
