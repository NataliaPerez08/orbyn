//! Device classification heuristics.
//!
//! Collectors report raw facts (OS match, MAC vendor, service fingerprints,
//! SNMP `sysDescr`). Classification maps those facts onto a small set of
//! human-meaningful device classes so the inventory is useful beyond raw port
//! discovery. It is intentionally conservative: unknown inputs yield `None`.

/// Classify a device from whatever evidence is available.
///
/// All inputs are optional; the classifier returns a class only when confident.
pub fn classify_device(
    os_name: Option<&str>,
    mac_vendor: Option<&str>,
    service_names: &[&str],
    sysdescr: Option<&str>,
) -> Option<String> {
    let os = os_name.unwrap_or_default().to_lowercase();
    let vendor = mac_vendor.unwrap_or_default().to_lowercase();
    let descr = sysdescr.unwrap_or_default().to_lowercase();

    // SNMP `sysDescr` / `sysObjectID` text is terse and explicit.
    if descr.contains("printer") || descr.contains("laserjet") || descr.contains("xerox") {
        return Some("printer".into());
    }
    if descr.contains("storage") || descr.contains("netapp") || descr.contains("emc ") {
        return Some("storage".into());
    }
    if descr.contains("firewall") || descr.contains("fortigate") {
        return Some("security-appliance".into());
    }
    if descr.contains("router") || descr.contains("switch") {
        return Some("network-device".into());
    }
    if descr.contains("eso") || descr.contains("example") {
        // NET-SNMP demo/example boxes default to Linux; fall through.
    }

    // Network vendors identify switching/routing gear. Matched against both the
    // MAC OUI vendor and the SNMP `sysDescr`/`sysObjectID` text.
    const NETWORK_VENDORS: &[&str] = &[
        "cisco",
        "juniper",
        "huawei",
        "arista",
        "extreme networks",
        "mikrotik",
        "alcatel",
        "f5",
        "ruckus",
    ];
    if NETWORK_VENDORS
        .iter()
        .any(|v| vendor.contains(v) || descr.contains(v))
    {
        return Some("network-device".into());
    }

    // IOS/NX-OS/catalyst operating system banners also pin network gear even
    // when the vendor word does not appear verbatim.
    if os.contains("ios") || os.contains("nx-os") || descr.contains("iosv") {
        return Some("network-device".into());
    }

    // Security appliance vendors.
    const SECURITY_VENDORS: &[&str] = &["fortinet", "palo alto", "check point", "sonicwall"];
    if SECURITY_VENDORS
        .iter()
        .any(|v| vendor.contains(v) || descr.contains(v))
    {
        return Some("security-appliance".into());
    }

    // Service fingerprints that pin the device type.
    if service_names
        .iter()
        .any(|s| *s == "jetdirect" || *s == "printer")
    {
        return Some("printer".into());
    }

    // Otherwise a recognizable OS with a conventional footprint is a server.
    let has_services = !service_names.is_empty();
    if has_services
        && (os.contains("linux")
            || os.contains("windows")
            || os.contains("freebsd")
            || os.contains("unix")
            || os.contains("ubuntu")
            || os.contains("debian")
            || os.contains("centos")
            || os.contains("rhel"))
    {
        return Some("server".into());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_vendor_is_classified() {
        assert_eq!(
            classify_device(Some("IOS 15.4"), Some("Cisco"), &[], None),
            Some("network-device".into())
        );
    }

    #[test]
    fn printer_descr_wins() {
        assert_eq!(
            classify_device(
                None,
                Some("Hewlett Packard"),
                &["jetdirect"],
                Some("HP LaserJet 4000")
            ),
            Some("printer".into())
        );
    }

    #[test]
    fn firewall_descr_is_appliance() {
        assert_eq!(
            classify_device(None, None, &[], Some("FortiGate-60F v7.0")),
            Some("security-appliance".into())
        );
    }

    #[test]
    fn cisco_ios_descr_is_network_device() {
        assert_eq!(
            classify_device(None, None, &[], Some("Cisco IOS Software, IOSv")),
            Some("network-device".into())
        );
    }

    #[test]
    fn linux_with_services_is_server() {
        assert_eq!(
            classify_device(Some("Linux 5.15.0"), None, &["ssh", "https"], None),
            Some("server".into())
        );
    }

    #[test]
    fn unknown_is_none() {
        assert_eq!(classify_device(None, None, &[], None), None);
    }
}
