//! Virtualization metadata detection (Phase 2 inventory enrichment).
//!
//! Both host collectors probe for hypervisor evidence and normalize it into a
//! small canonical vocabulary stored on [`crate::domain::Capacity`]:
//!
//! - `kvm` — QEMU/KVM guests (QEMU, Amazon EC2, Google Compute Engine,
//!   OpenStack, DigitalOcean and other KVM-based clouds report KVM/QEMU DMI
//!   vendors)
//! - `vmware` — VMware guests (ESXi, Workstation, Fusion)
//! - `virtualbox` — VirtualBox guests (innotek GmbH DMI vendor)
//! - `hyperv` — Hyper-V or Azure guests (Microsoft Corporation DMI vendor,
//!   "Virtual Machine" model)
//! - `xen` — Xen guests
//! - container runtimes: `lxc`, `docker`, `podman`, `systemd-nspawn`
//! - `wsl` — Windows Subsystem for Linux
//! - `bhyve`, `bochs`, `uml` — niche hypervisors reported by
//!   `systemd-detect-virt`
//! - `unknown` — the CPU reports a hypervisor flag but the platform could
//!   not be identified
//!
//! `None` means no virtualization evidence was found: the host is bare metal
//! (or the probe could not assess it).

/// Marker the Linux probe emits when `/proc/cpuinfo` carries the `hypervisor`
/// flag but no DMI/`systemd-detect-virt` evidence identified the platform.
pub const HYPERVISOR_FLAG_MARKER: &str = "hypervisor-flag";

/// Detect the hypervisor from the Linux `###virt` probe section.
///
/// The section carries, in order: the `systemd-detect-virt` output (absent
/// when the tool is not installed, `none` on bare metal), the DMI
/// `/sys/class/dmi/id/sys_vendor` and `product_name` values, and the optional
/// [`HYPERVISOR_FLAG_MARKER`]. The first tier wins when present; otherwise
/// the DMI strings are matched; the bare flag yields `unknown`.
pub fn detect_linux(lines: &[String]) -> Option<String> {
    let non_empty: Vec<String> = lines
        .iter()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect();
    let flag = lines.iter().any(|l| l.trim() == HYPERVISOR_FLAG_MARKER);

    // Tier 1: a systemd-detect-virt identifier (first non-empty line).
    if let Some(first) = non_empty.first() {
        if let Some(id) = from_detect_virt(first) {
            return Some(id.into());
        }
    }

    // Tier 2: DMI vendor/product keywords across the whole section, so
    // evidence split over lines (e.g. "Microsoft Corporation" vendor +
    // "Virtual Machine" product) still matches as one platform.
    let dmi = non_empty
        .iter()
        .filter(|l| l.as_str() != HYPERVISOR_FLAG_MARKER)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(id) = from_dmi(&dmi) {
        return Some(id.into());
    }

    // Tier 3: the CPU hypervisor flag alone proves a VM, not the platform.
    if flag {
        return Some("unknown".into());
    }
    None
}

/// Detect the hypervisor from Windows `Win32_ComputerSystem` fields.
///
/// `manufacturer`/`model` come from the `###virt` CSV section of the Windows
/// probe (e.g. `"VMware, Inc."` / `"VMware7,1"`, `"Microsoft Corporation"` /
/// `"Virtual Machine"`).
pub fn detect_windows(manufacturer: Option<&str>, model: Option<&str>) -> Option<String> {
    // Manufacturer and model are matched as one platform description:
    // Hyper-V/Azure guests only identify themselves through the combination
    // ("Microsoft Corporation" + "Virtual Machine").
    let joined = [manufacturer.unwrap_or_default(), model.unwrap_or_default()]
        .join(" ")
        .trim()
        .to_lowercase();
    if joined.is_empty() {
        return None;
    }
    from_dmi(&joined).map(Into::into)
}

/// Map a `systemd-detect-virt` identifier to the canonical vocabulary.
/// Returns `None` for `none` (bare metal) and unknown identifiers.
fn from_detect_virt(raw: &str) -> Option<&'static str> {
    Some(match raw.trim() {
        "kvm" | "qemu" => "kvm",
        "vmware" => "vmware",
        "oracle" => "virtualbox",
        "microsoft" => "hyperv",
        "xen" => "xen",
        "bochs" => "bochs",
        "uml" => "uml",
        "bhyve" => "bhyve",
        "lxc" | "lxc-libvirt" => "lxc",
        "docker" => "docker",
        "podman" => "podman",
        "systemd-nspawn" => "systemd-nspawn",
        "wsl" => "wsl",
        "vm_other" => "unknown",
        _ => return None,
    })
}

/// Match DMI vendor/product text (or Windows manufacturer/model) against the
/// canonical vocabulary.
fn from_dmi(raw: &str) -> Option<&'static str> {
    // Order matters: specific platform markers before generic vendor names.
    if raw.contains("virtualbox") || raw.contains("innotek") {
        return Some("virtualbox");
    }
    if raw.contains("vmware") {
        return Some("vmware");
    }
    // Microsoft only counts inside a VM: Hyper-V and Azure report the
    // "Virtual Machine" model (or a versioned "Virtual Machine" product),
    // while physical hosts carry real vendor names.
    if raw.contains("microsoft") && raw.contains("virtual machine") {
        return Some("hyperv");
    }
    if raw.contains("hyperv") {
        return Some("hyperv");
    }
    if raw.contains("xen") {
        return Some("xen");
    }
    if raw.contains("qemu") || raw.contains("kvm") {
        return Some("kvm");
    }
    // KVM-based public clouds surface their own DMI vendor strings.
    if raw.contains("amazon") || raw.contains("openstack") || raw.contains("digitalocean") {
        return Some("kvm");
    }
    if raw.contains("google compute") || raw.contains("google, inc") {
        return Some("kvm");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn systemd_detect_virt_identifiers_win() {
        assert_eq!(detect_linux(&lines(&["kvm"])).as_deref(), Some("kvm"));
        assert_eq!(detect_linux(&lines(&["qemu"])).as_deref(), Some("kvm"));
        assert_eq!(detect_linux(&lines(&["vmware"])).as_deref(), Some("vmware"));
        assert_eq!(
            detect_linux(&lines(&["oracle"])).as_deref(),
            Some("virtualbox")
        );
        assert_eq!(
            detect_linux(&lines(&["microsoft"])).as_deref(),
            Some("hyperv")
        );
        assert_eq!(detect_linux(&lines(&["xen"])).as_deref(), Some("xen"));
        assert_eq!(detect_linux(&lines(&["docker"])).as_deref(), Some("docker"));
        assert_eq!(detect_linux(&lines(&["wsl"])).as_deref(), Some("wsl"));
        assert_eq!(
            detect_linux(&lines(&["vm_other"])).as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn dmi_vendor_falls_through_when_detect_virt_is_missing() {
        // No systemd-detect-virt installed: the first line is the DMI vendor.
        assert_eq!(
            detect_linux(&lines(&["VMware, Inc.", "VMware Virtual Platform"])).as_deref(),
            Some("vmware")
        );
        assert_eq!(
            detect_linux(&lines(&["QEMU", "Standard PC (Q35 + ICH9, 2009)"])).as_deref(),
            Some("kvm")
        );
        assert_eq!(
            detect_linux(&lines(&["innotek GmbH", "VirtualBox"])).as_deref(),
            Some("virtualbox")
        );
        assert_eq!(
            detect_linux(&lines(&["Microsoft Corporation", "Virtual Machine"])).as_deref(),
            Some("hyperv")
        );
        assert_eq!(
            detect_linux(&lines(&["Xen", "HVM domU"])).as_deref(),
            Some("xen")
        );
        assert_eq!(
            detect_linux(&lines(&["Amazon EC2", "t3.micro"])).as_deref(),
            Some("kvm")
        );
        assert_eq!(
            detect_linux(&lines(&["Google", "Google Compute Engine"])).as_deref(),
            Some("kvm")
        );
    }

    #[test]
    fn bare_metal_yields_none() {
        // systemd-detect-virt prints "none" on physical hosts.
        assert_eq!(detect_linux(&lines(&["none"])), None);
        assert_eq!(
            detect_linux(&lines(&["none", "Dell Inc.", "PowerEdge R740"])),
            None
        );
        // Empty section: probe could not assess anything.
        assert_eq!(detect_linux(&lines(&[])), None);
        assert_eq!(detect_linux(&lines(&[""])), None);
    }

    #[test]
    fn hypervisor_flag_alone_means_unknown_vm() {
        assert_eq!(
            detect_linux(&lines(&["none", HYPERVISOR_FLAG_MARKER])).as_deref(),
            Some("unknown")
        );
        assert_eq!(
            detect_linux(&lines(&[HYPERVISOR_FLAG_MARKER])).as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn detect_virt_wins_over_conflicting_dmi() {
        assert_eq!(
            detect_linux(&lines(&["kvm", "VMware, Inc.", "VMware Virtual Platform"])).as_deref(),
            Some("kvm")
        );
    }

    #[test]
    fn windows_manufacturer_model_pairs() {
        assert_eq!(
            detect_windows(Some("VMware, Inc."), Some("VMware7,1")).as_deref(),
            Some("vmware")
        );
        assert_eq!(
            detect_windows(Some("Microsoft Corporation"), Some("Virtual Machine")).as_deref(),
            Some("hyperv")
        );
        assert_eq!(
            detect_windows(Some("innotek GmbH"), Some("VirtualBox")).as_deref(),
            Some("virtualbox")
        );
        assert_eq!(
            detect_windows(Some("QEMU"), Some("Standard PC Q35")).as_deref(),
            Some("kvm")
        );
        assert_eq!(
            detect_windows(Some("Xen"), Some("HVM domU")).as_deref(),
            Some("xen")
        );
    }

    #[test]
    fn physical_windows_hosts_are_not_virtual() {
        assert_eq!(
            detect_windows(Some("Dell Inc."), Some("PowerEdge R740")),
            None
        );
        assert_eq!(
            detect_windows(Some("Microsoft Corporation"), Some("Surface Pro")),
            None,
            "Microsoft alone must not imply Hyper-V"
        );
        assert_eq!(detect_windows(None, None), None);
    }
}
